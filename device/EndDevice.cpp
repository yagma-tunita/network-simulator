#include "EndDevice.hpp"
#include "Port.hpp"
#include "../link/Link.hpp"
#include "../core/IpPacket.hpp"
#include "../core/Ipv6Packet.hpp"
#include "../core/Ipv6Subnet.hpp"
#include "../core/IcmpMessage.hpp"
#include "../core/Icmpv6Message.hpp"
#include "../core/UdpDatagram.hpp"
#include "../core/TcpSegment.hpp"
#include "../engine/Clock.hpp"
#include "../engine/Scheduler.hpp"
#include "../engine/Event.hpp"
#include <memory>
#include <iostream>
#include <string>
#include <cstddef>
#include <cctype>
#include <algorithm>
#include <iterator>

namespace
{
    struct PingTimeoutEvent : Event
    {
        EndDevice *dev;
        uint16_t seq;

        PingTimeoutEvent(EndDevice *d, uint16_t s) : dev(d), seq(s) {}

        void Execute(Engine &) override { dev->OnPingTimeout(seq); }
        const char *Name() const override { return "ping-timeout"; }
    };

    struct Ping6TimeoutEvent : Event
    {
        EndDevice *dev;
        uint16_t seq;

        Ping6TimeoutEvent(EndDevice *d, uint16_t s) : dev(d), seq(s) {}

        void Execute(Engine &) override { dev->OnPing6Timeout(seq); }
        const char *Name() const override { return "ping6-timeout"; }
    };

    struct TraceNextEvent : Event
    {
        EndDevice *dev;
        explicit TraceNextEvent(EndDevice *d) : dev(d) {}

        void Execute(Engine &) override { dev->AdvanceTrace(); }
        const char *Name() const override { return "trace-next"; }
    };

    struct Trace6NextEvent : Event
    {
        EndDevice *dev;
        explicit Trace6NextEvent(EndDevice *d) : dev(d) {}

        void Execute(Engine &) override { dev->AdvanceTrace6(); }
        const char *Name() const override { return "trace6-next"; }
    };

    struct DhcpTimerEvent : Event
    {
        EndDevice *dev;
        uint64_t gen;

        DhcpTimerEvent(EndDevice *d, uint64_t g) : dev(d), gen(g) {}

        void Execute(Engine &) override { dev->OnDhcpTimer(gen); }
        const char *Name() const override { return "dhcp-timer"; }
    };

}

void EndDevice::OnFrame(Port *port, FramePtr frame)
{
    if (!port)
        return;

    if (frame->type == EthernetFrame::kLLDP)
    {
        HandleLldp(port, frame);
        return;
    }

    if ((port->mac != frame->dst) && !frame->IsBroadcast() &&
        !(frame->type == EthernetFrame::kIPv6 && frame->dst.IsGroup()))
        return;

    if (frame->type == EthernetFrame::kARP)
    {
        arp.HandleArp(port, *frame);
        FlushPending();
    }
    else if (frame->type == EthernetFrame::kIPv4)
    {
        HandleIp(port, frame);
    }
    else if (frame->type == EthernetFrame::kIPv6)
    {
        HandleIpv6(port, frame);
    }
}

void EndDevice::SetIpv6(Port *port, const Ipv6 &addr)
{
    if(!port)
        return;
    port->hasIp6 = true;
    port->ip6 = addr;
}

void EndDevice::SendIpv6(Port *egress, const Ipv6 &dstIp, const Mac &dstMac,
                         const Icmpv6Message &msg, uint8_t hopLimit)
{
    if(!egress || !egress->hasIp6)
        return;

    Ipv6Packet pkt(egress->ip6, dstIp, Icmpv6Message::kNextHeader,
                   msg.ToBytes(egress->ip6, dstIp));
    pkt.hopLimit = hopLimit;
    if(msg.type == Icmpv6Message::kNeighborSolicit ||
       msg.type == Icmpv6Message::kNeighborAdvert)
        pkt.hopLimit = 255;

    egress->Send(std::make_shared<const EthernetFrame>(
        dstMac, egress->mac, EthernetFrame::kIPv6, pkt.ToBytes()));
}

bool EndDevice::ResolveNextHop6(const Ipv6 &target, Port *&egress,
                                Ipv6 &nextHop)
{
    for(Port *p : portList)
        if(p->hasIp6 && Ipv6Subnet(p->ip6, p->prefix6).Contains(target))
        {
            egress = p;
            nextHop = target;
            return true;
        }

    if(hasGateway6)
        for(Port *p : portList)
            if(p->hasIp6 &&
               Ipv6Subnet(p->ip6, p->prefix6).Contains(gateway6))
            {
                egress = p;
                nextHop = gateway6;
                return true;
            }

    for(Port *p : portList)
        if(p->hasIp6)
        {
            egress = p;
            nextHop = target;
            return true;
        }
    return false;
}

void EndDevice::SendEcho6(Port *egress, const Ipv6 &targetIp,
                          const Ipv6 &nextHop, uint16_t seq, uint8_t hopLimit)
{
    auto it = ndCache.find(nextHop);
    if(it == ndCache.end() || !egress)
        return;

    auto oit = outstanding6.find(seq);
    if(oit != outstanding6.end())
    {
        oit->second.sentAt = clock ? clock->Now() : 0;
        oit->second.sent = true;
    }

    Icmpv6Message req;
    req.type = Icmpv6Message::kEchoRequest;
    req.id = 0x1234;
    req.seq = seq;
    SendIpv6(egress, targetIp, it->second, req, hopLimit);
}

void EndDevice::Ping6(const Ipv6 &targetIp)
{
    Port *egress = nullptr;
    Ipv6 nextHop;
    if(!ResolveNextHop6(targetIp, egress, nextHop))
    {
        std::cout << "ping6: no IPv6 address\n";
        return;
    }

    uint16_t seq = ++nextPingSeq;
    outstanding6[seq] = Ping6Outstanding{ targetIp, 0, false };
    if(scheduler)
        scheduler->ScheduleAfter(kPingTimeout,
            std::make_unique<Ping6TimeoutEvent>(this, seq));

    auto it = ndCache.find(nextHop);
    if(it != ndCache.end())
    {
        SendEcho6(egress, targetIp, nextHop, seq);
        return;
    }

    pendingPing6[nextHop].push_back(
        PendingPing6{ targetIp, nextHop, egress, seq, 64 });
    Icmpv6Message ns;
    ns.type = Icmpv6Message::kNeighborSolicit;
    ns.target = nextHop;
    ns.options = NdpLinkLayerOption(1, egress->mac);
    SendIpv6(egress, NdpSolicitedNode(nextHop), NdpSolicitedMac(nextHop), ns);
}

void EndDevice::Traceroute6(const Ipv6 &targetIp, uint8_t maxHops)
{
    traceHops6.clear();
    traceTarget6 = targetIp;
    traceMaxHops6 = maxHops;
    traceTtl6 = 1;
    traceActive6 = true;

    std::cout << "traceroute6 to " << targetIp.ToString()
              << " (" << int(maxHops) << " hops max)\n";
    SendTrace6Probe();
}

void EndDevice::SendTrace6Probe()
{
    if(!traceActive6)
        return;
    if(traceTtl6 > traceMaxHops6)
    {
        traceActive6 = false;
        return;
    }

    Port *egress = nullptr;
    Ipv6 nextHop;
    if(!ResolveNextHop6(traceTarget6, egress, nextHop))
    {
        std::cout << "traceroute6: no IPv6 address\n";
        traceActive6 = false;
        return;
    }

    uint16_t seq = ++nextPingSeq;
    traceHops6[seq] = traceTtl6;
    outstanding6[seq] = Ping6Outstanding{ traceTarget6, 0, false };
    if(scheduler)
        scheduler->ScheduleAfter(kPingTimeout,
            std::make_unique<Ping6TimeoutEvent>(this, seq));

    auto it = ndCache.find(nextHop);
    if(it != ndCache.end())
    {
        SendEcho6(egress, traceTarget6, nextHop, seq, traceTtl6);
        return;
    }

    pendingPing6[nextHop].push_back(
        PendingPing6{ traceTarget6, nextHop, egress, seq, traceTtl6 });
    Icmpv6Message ns;
    ns.type = Icmpv6Message::kNeighborSolicit;
    ns.target = nextHop;
    ns.options = NdpLinkLayerOption(1, egress->mac);
    SendIpv6(egress, NdpSolicitedNode(nextHop), NdpSolicitedMac(nextHop), ns);
}

void EndDevice::ScheduleNextTrace6()
{
    if(!traceActive6)
        return;
    if(traceTtl6 >= traceMaxHops6)
    {
        traceActive6 = false;
        return;
    }

    if(scheduler)
        scheduler->ScheduleAfter(1, std::make_unique<Trace6NextEvent>(this));
    else
        AdvanceTrace6();
}

void EndDevice::AdvanceTrace6()
{
    if(!traceActive6)
        return;
    ++traceTtl6;
    SendTrace6Probe();
}

void EndDevice::HandleIpv6(Port *port, FramePtr frame)
{
    if(!port || !port->hasIp6)
        return;

    Ipv6Packet pkt;
    if(!Ipv6Packet::TryFromBytes(frame->payload, pkt))
        return;
    if(!(pkt.dstIp == port->ip6) && pkt.dstIp.bytes[0] != 0xFF)
        return;
    if(pkt.nextHeader != Icmpv6Message::kNextHeader)
        return;

    Icmpv6Message msg;
    if(!Icmpv6Message::TryFromBytes(pkt.payload, pkt.srcIp, pkt.dstIp, msg))
        return;

    if(msg.type == Icmpv6Message::kNeighborSolicit)
    {
        if(!(msg.target == port->ip6))
            return;
        Icmpv6Message na;
        na.type = Icmpv6Message::kNeighborAdvert;
        na.ndFlags = 0x60000000u;
        na.target = port->ip6;
        na.options = NdpLinkLayerOption(2, port->mac);
        SendIpv6(port, pkt.srcIp, frame->src, na);
        return;
    }

    if(msg.type == Icmpv6Message::kNeighborAdvert)
    {
        ndCache[msg.target] = frame->src;
        auto it = pendingPing6.find(msg.target);
        if(it != pendingPing6.end())
        {
            std::vector<PendingPing6> pending = std::move(it->second);
            pendingPing6.erase(it);
            for(const PendingPing6 &p : pending)
                SendEcho6(p.egress, p.target, p.nextHop, p.seq, p.hopLimit);
        }
        return;
    }

    if(msg.type == Icmpv6Message::kEchoRequest)
    {
        Icmpv6Message rep = msg;
        rep.type = Icmpv6Message::kEchoReply;
        SendIpv6(port, pkt.srcIp, frame->src, rep);
        return;
    }

    if(msg.type == Icmpv6Message::kEchoReply)
    {
        auto th = traceHops6.find(msg.seq);
        if(th != traceHops6.end())
        {
            std::cout << "hop " << int(th->second) << ": "
                      << pkt.srcIp.ToString() << " (target)\n";
            traceHops6.erase(th);
            outstanding6.erase(msg.seq);
            traceActive6 = false;
            return;
        }

        auto oit = outstanding6.find(msg.seq);
        if(oit != outstanding6.end())
        {
            std::cout << "ping6 reply from " << pkt.srcIp.ToString()
                      << " seq=" << msg.seq << "\n";
            outstanding6.erase(oit);
        }
        return;
    }

    if(msg.type == Icmpv6Message::kDestUnreachable ||
       msg.type == Icmpv6Message::kTimeExceeded)
    {
        Ipv6Packet orig;
        Icmpv6Message oc;
        uint16_t oseq = 0;
        bool haveSeq = false;
        if(Ipv6Packet::TryFromBytes(msg.payload, orig) &&
           orig.nextHeader == Icmpv6Message::kNextHeader &&
           Icmpv6Message::TryFromBytes(orig.payload, orig.srcIp, orig.dstIp, oc) &&
           oc.type == Icmpv6Message::kEchoRequest)
        {
            oseq = oc.seq;
            haveSeq = true;
            outstanding6.erase(oseq);
            for(auto pit = pendingPing6.begin(); pit != pendingPing6.end();)
            {
                std::vector<PendingPing6> &v = pit->second;
                v.erase(std::remove_if(v.begin(), v.end(),
                        [&](const PendingPing6 &p) { return p.seq == oseq; }),
                        v.end());
                if(v.empty()) pit = pendingPing6.erase(pit);
                else ++pit;
            }
        }

        auto th = haveSeq ? traceHops6.find(oseq) : traceHops6.end();
        if(th != traceHops6.end())
        {
            uint8_t ttl = th->second;
            traceHops6.erase(th);
            if(msg.type == Icmpv6Message::kTimeExceeded)
            {
                std::cout << "hop " << int(ttl) << ": "
                          << pkt.srcIp.ToString() << "\n";
                ScheduleNextTrace6();
            }
            else
            {
                std::cout << "hop " << int(ttl) << ": unreachable ("
                          << pkt.srcIp.ToString() << ")\n";
                traceActive6 = false;
            }
            return;
        }

        std::cout << (msg.type == Icmpv6Message::kTimeExceeded
                          ? "icmp6 time exceeded from "
                          : "icmp6 unreachable from ")
                  << pkt.srcIp.ToString() << "\n";
    }
}

void EndDevice::HandleIp(Port *port, FramePtr frame)
{
    IpPacket pkt;
    if (!IpPacket::TryFromBytes(frame->payload, pkt))
        return;

    if (pkt.protocol == IpPacket::kUdp)
    {
        UdpDatagram d;
        if (!UdpDatagram::TryFromBytes(pkt.payload, d))
            return;
        if (d.dstPort == 67 || d.dstPort == 68)
        {
            HandleDhcp(port, pkt, d);
            return;
        }
    }

    if (!port->hasIp || !(pkt.dstIp == port->ip))
        return;

    if (pkt.protocol == IpPacket::kUdp)
    {
        UdpDatagram d;
        if (!UdpDatagram::TryFromBytes(pkt.payload, d))
            return;

        if (udpEchoEnabled && d.dstPort == udpEchoPort)
        {
            UdpDatagram rep;
            rep.srcPort = d.dstPort;
            rep.dstPort = d.srcPort;
            rep.payload = d.payload;
            IpPacket out(port->ip, pkt.srcIp, IpPacket::kUdp, rep.ToBytes());
            port->Send(std::make_shared<const EthernetFrame>(
                frame->src, port->mac, EthernetFrame::kIPv4, out.ToBytes()));
            return;
        }

        if ((d.dstPort == 53 && dnsServerEnabled) ||
            (dnsClientPort != 0 && d.dstPort == dnsClientPort) ||
            (dnsUpdateActive && d.dstPort == dnsUpdatePort))
        {
            HandleDns(port, pkt, d);
            return;
        }

        std::string text(d.payload.begin(), d.payload.end());
        std::cout << "udp from " << pkt.srcIp.ToString() << ":" << d.srcPort
                  << " \"" << text << "\"\n";
        return;
    }

    if (pkt.protocol == IpPacket::kTcp)
    {
        if(!HandleTcpStack(port, pkt, frame->src))
            HandleTcp(port, pkt, clock ? clock->Now() : 0);
        return;
    }

    if (pkt.protocol != IpPacket::kIcmp)
        return;

    IcmpMessage icmp;
    if (!IcmpMessage::TryFromBytes(pkt.payload, icmp))
        return;

    uint64_t now = clock ? clock->Now() : 0;

    if (icmp.type == IcmpMessage::kEchoRequest)
    {
        IcmpMessage reply = icmp;
        reply.type = IcmpMessage::kEchoReply;
        IpPacket out(port->ip, pkt.srcIp, IpPacket::kIcmp, reply.ToBytes());
        port->Send(std::make_shared<const EthernetFrame>(
            frame->src, port->mac, EthernetFrame::kIPv4, out.ToBytes()));
        return;
    }

    if (icmp.type == IcmpMessage::kEchoReply)
    {
        auto th = traceHops.find(icmp.seq);
        if (th != traceHops.end())
        {
            std::cout << "hop " << int(th->second) << ": "
                      << pkt.srcIp.ToString() << " (target)\n";
            traceHops.erase(th);
            outstanding.erase(icmp.seq);
            traceActive = false;
            return;
        }

        auto it = outstanding.find(icmp.seq);
        if (it != outstanding.end() && it->second.sent)
        {
            uint64_t rtt = now - it->second.sentAt;
            std::cout << "ping reply from " << pkt.srcIp.ToString()
                      << " seq=" << icmp.seq << " time=" << rtt << "\n";
            outstanding.erase(it);
        }
        else
        {
            std::cout << "ping reply from " << pkt.srcIp.ToString()
                      << " seq=" << icmp.seq << "\n";
            if (it != outstanding.end())
                outstanding.erase(it);
        }
        return;
    }

    if (icmp.type == IcmpMessage::kTimeExceeded ||
        icmp.type == IcmpMessage::kDestUnreachable)
    {
        IpPacket orig;
        IcmpMessage oc;
        uint16_t oseq = 0;
        bool haveSeq = false;
        if (IpPacket::TryFromBytes(icmp.payload, orig) &&
            orig.protocol == IpPacket::kIcmp &&
            IcmpMessage::TryFromBytes(orig.payload, oc))
        {
            oseq = oc.seq;
            haveSeq = true;
        }

        auto th = haveSeq ? traceHops.find(oseq) : traceHops.end();
        if (th != traceHops.end())
        {
            uint8_t ttl = th->second;
            traceHops.erase(th);
            if (haveSeq) outstanding.erase(oseq);

            if (icmp.type == IcmpMessage::kTimeExceeded)
            {
                std::cout << "hop " << int(ttl) << ": " << pkt.srcIp.ToString() << "\n";
                ScheduleNextTrace();
            }
            else
            {
                std::cout << "hop " << int(ttl) << ": unreachable ("
                          << pkt.srcIp.ToString() << ")\n";
                traceActive = false;
            }
            return;
        }

        if (icmp.type == IcmpMessage::kDestUnreachable &&
            icmp.code == IcmpMessage::kFragNeeded)
        {
            if(icmp.payload.size() >= 24 && icmp.payload[9] == IpPacket::kTcp)
            {
                uint16_t localPort =
                    uint16_t((icmp.payload[20] << 8) | icmp.payload[21]);
                uint16_t remotePort =
                    uint16_t((icmp.payload[22] << 8) | icmp.payload[23]);
                Ipv4 remote(
                    (uint32_t(icmp.payload[16]) << 24) |
                    (uint32_t(icmp.payload[17]) << 16) |
                    (uint32_t(icmp.payload[18]) << 8) |
                    uint32_t(icmp.payload[19]));
                TcpConnection *conn =
                    FindTcpConn(localPort, remote, remotePort);
                if(conn)
                    conn->OnPathMtu(icmp.nextHopMtu);
            }
            std::cout << "icmp frag needed from " << pkt.srcIp.ToString()
                      << " mtu=" << icmp.nextHopMtu << "\n";
            if (haveSeq)
                outstanding.erase(oseq);
            return;
        }

        std::cout << (icmp.type == IcmpMessage::kTimeExceeded
                          ? "icmp time exceeded from "
                          : "icmp unreachable from ")
                  << pkt.srcIp.ToString() << "\n";
        if (haveSeq)
            outstanding.erase(oseq);
    }
}

void EndDevice::SendArpRequest(Ipv4 targetIp)
{
    Port *chosen = nullptr;
    for (Port *p : portList)
    {
        if (p->hasIp && p->subnet.Contains(targetIp))
        {
            chosen = p;
            break;
        }
    }

    arp.SendArpRequest(targetIp, chosen);
}

bool EndDevice::Lookup(Ipv4 ip, Mac &outMac)
{
    return arp.Lookup(ip, outMac);
}

void EndDevice::SetClock(Clock *c)
{
    Device::SetClock(c);
    arp.SetClock(c);
}

void EndDevice::SendPing(Ipv4 targetIp, uint16_t seq, uint8_t ttl)
{
    SendEcho(targetIp, seq, ttl);
}

void EndDevice::SendEcho(Ipv4 targetIp, uint16_t seq, uint8_t ttl)
{
    Port *egress = nullptr;
    Ipv4 nextHop;

    for (Port *p : portList)
    {
        if (p->hasIp && p->subnet.Contains(targetIp))
        {
            egress = p;
            nextHop = targetIp;
            break;
        }
    }

    if (!egress)
    {
        if (!hasGateway)
            return;
        nextHop = gateway;
        for (Port *p : portList)
        {
            if (p->hasIp && p->subnet.Contains(gateway))
            {
                egress = p;
                break;
            }
        }
    }

    if (!egress)
        return;

    if (seq == 0)
        seq = ++nextPingSeq;

    IcmpMessage req;
    req.type = IcmpMessage::kEchoRequest;
    req.id = 0x1234;
    req.seq = seq;

    IpPacket pkt(egress->ip, targetIp, IpPacket::kIcmp, req.ToBytes());
    pkt.ttl = ttl;

    outstanding[seq] = PingOutstanding{ targetIp, 0, false };

    if (scheduler)
        scheduler->ScheduleAfter(kPingTimeout, std::make_unique<PingTimeoutEvent>(this, seq));

    Mac dstMac;
    if (arp.Lookup(nextHop, dstMac))
    {
        uint64_t now = clock ? clock->Now() : 0;
        outstanding[seq].sentAt = now;
        outstanding[seq].sent = true;
        egress->Send(std::make_shared<const EthernetFrame>(
            dstMac, egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
    }
    else
    {
        bool alreadyPending =
            pendingArpCounts.find(nextHop.value) != pendingArpCounts.end();
        if (pendingPings.size() < kMaxPending)
        {
            pendingPings.push_back(PendingPing{ egress, nextHop, pkt, seq });
            NotePendingArp(nextHop);
        }
        else
            ++droppedPending;

        if (!alreadyPending)
            arp.SendArpRequest(nextHop, egress);
    }
}

void EndDevice::SetUdpEcho(bool on, uint16_t port)
{
    udpEchoEnabled = on;
    udpEchoPort = port;
}

void EndDevice::SetTcpEcho(bool on, uint16_t port)
{
    tcpEchoEnabled = on;
    tcpEchoPort = port;
}

void EndDevice::SetTcpListen(bool on, uint16_t port)
{
    tcpListenEnabled = on;
    tcpListenPort = port;
}

void EndDevice::SetTcpKeepalive(bool on, uint64_t idle, uint64_t interval,
                                uint8_t count)
{
    tcpKeepalive = on;
    tcpKeepIdle = idle;
    tcpKeepInterval = interval;
    tcpKeepCount = count;
    for(TcpConnection &c : tcpConns)
        c.SetKeepalive(on, idle, interval, count);
}

TcpConnection &EndDevice::NewTcpConnection()
{
    tcpConns.emplace_back();
    TcpConnection &c = tcpConns.back();
    TcpConnection *cp = &c;
    c.SetScheduler(scheduler);
    c.congestion = tcpCongestion;
    c.tlpEnabled = tcpTlp;
    c.prrEnabled = tcpPrr;
    c.rackEnabled = tcpRack;
    c.pacingEnabled = tcpPacing;
    c.out = [this, cp](const TcpSegment &s) { SendTcpSegment(*cp, s); };
    c.queryPathMtu = [this, cp]() -> uint16_t {
        Port *egress = nullptr;
        Ipv4 nextHop;
        if(!ResolveNextHop(cp->remoteIp, egress, nextHop) ||
           !egress || !egress->link)
            return 0;
        return egress->link->mtu;
    };
    c.onKeepaliveTimeout = []() { std::cout << "tcp: keepalive timeout\n"; };
    c.SetKeepalive(tcpKeepalive, tcpKeepIdle, tcpKeepInterval, tcpKeepCount);
    return c;
}

uint16_t EndDevice::AllocateTcpLocalPort()
{
    if(tcpPortMin == 0 || tcpPortMax < tcpPortMin)
        return 0;
    uint32_t span = uint32_t(tcpPortMax - tcpPortMin) + 1;
    uint32_t start = uint32_t(tcpPortCursor - tcpPortMin);
    if(start >= span)
        start = 0;

    for(uint32_t i = 0; i < span; ++i)
    {
        uint32_t offset = (start + i) % span;
        uint16_t port = uint16_t(tcpPortMin + offset);
        bool used = false;
        for(const TcpConnection &c : tcpConns)
            if(c.localPort == port)
            {
                used = true;
                break;
            }
        if(!used)
        {
            tcpPortCursor = uint16_t(tcpPortMin +
                ((offset + 1) % span));
            return port;
        }
    }
    return 0;
}

uint16_t EndDevice::TcpMssLimit(Port *port) const
{
    uint32_t limit = 1460;
    if(port && port->link && port->link->mtu > 40)
    {
        limit = uint32_t(port->link->mtu) - 40;
        if(limit < 536)
            limit = 536;
        if(limit > 1460)
            limit = 1460;
    }
    return uint16_t(limit);
}

void EndDevice::IndexTcpConn(TcpConnection &c)
{
    tcpConnIndex[std::make_tuple(c.localPort, c.remoteIp.value,
                                 c.remotePort)] = &c;
}

TcpConnection *EndDevice::FindTcpConn(uint16_t localPort, Ipv4 remote, uint16_t remotePort)
{
    if(tcpLastConn && tcpLastConn->state != TcpConnection::Closed &&
       tcpLastConn->localPort == localPort &&
       tcpLastConn->remoteIp == remote &&
       tcpLastConn->remotePort == remotePort)
        return tcpLastConn;

    TcpConnKey key = std::make_tuple(localPort, remote.value, remotePort);
    auto indexed = tcpConnIndex.find(key);
    if(indexed != tcpConnIndex.end())
    {
        TcpConnection *c = indexed->second;
        if(c && c->state != TcpConnection::Closed)
        {
            tcpLastConn = c;
            return c;
        }
        tcpConnIndex.erase(indexed);
    }

    for(TcpConnection &c : tcpConns)
    {
        if(c.state != TcpConnection::Closed &&
           c.localPort == localPort && c.remoteIp == remote && c.remotePort == remotePort)
        {
            tcpConnIndex[key] = &c;
            tcpLastConn = &c;
            return &c;
        }
    }
    return nullptr;
}

void EndDevice::CleanupTcpConns()
{
    for(auto it = tcpConns.begin(); it != tcpConns.end(); )
    {
        if(it->state == TcpConnection::Closed)
        {
            TcpConnKey key = std::make_tuple(it->localPort, it->remoteIp.value,
                                             it->remotePort);
            auto indexed = tcpConnIndex.find(key);
            if(indexed != tcpConnIndex.end() && indexed->second == &*it)
                tcpConnIndex.erase(indexed);
            tcpLastConn = nullptr;
            it = tcpConns.erase(it);
        }
        else
            ++it;
    }
}

void EndDevice::SendTcpReset(Port *ingress, const IpPacket &pkt,
                             const TcpSegment &seg, const Mac &srcMac)
{
    if(!ingress || (seg.flags & TcpSegment::kRst))
        return;

    TcpSegment rst;
    rst.srcPort = seg.dstPort;
    rst.dstPort = seg.srcPort;

    uint32_t ack = seg.seq + uint32_t(seg.payload.size());
    if(seg.flags & TcpSegment::kSyn) ++ack;
    if(seg.flags & TcpSegment::kFin) ++ack;

    if(seg.flags & TcpSegment::kAck)
    {
        rst.flags = TcpSegment::kRst;
        rst.seq = seg.ack;
    }
    else
    {
        rst.flags = TcpSegment::kRst | TcpSegment::kAck;
        rst.ack = ack;
    }

    IpPacket out(ingress->ip, pkt.srcIp, IpPacket::kTcp,
                 rst.ToBytes(ingress->ip, pkt.srcIp));

    ++tcpResetsSent;
    ingress->Send(std::make_shared<const EthernetFrame>(
        srcMac, ingress->mac, EthernetFrame::kIPv4, out.ToBytes()));
}

uint32_t EndDevice::TcpCookieSecret(Port *port) const
{
    uint32_t h = 0x9e3779b9u;
    if(port)
    {
        for(std::size_t i = 0; i < 6; ++i)
            h = (h ^ port->mac.bytes[i]) * 16777619u;
        h = (h ^ port->ip.value) * 16777619u;
    }
    return h;
}

uint32_t EndDevice::TcpCookie(Port *port, Ipv4 remote, uint16_t rport,
                              uint32_t clientIsn, uint64_t bucket) const
{
    uint32_t h = TcpCookieSecret(port);
    h = (h ^ remote.value) * 16777619u;
    h = (h ^ uint32_t(rport)) * 16777619u;
    h = (h ^ uint32_t(tcpListenPort)) * 16777619u;
    h = (h ^ clientIsn) * 16777619u;
    h = (h ^ uint32_t(bucket)) * 16777619u;
    h ^= h >> 16;
    return h ? h : 1;
}

void EndDevice::SendTcpCookieSynAck(Port *ingress, const IpPacket &pkt,
                                    const TcpSegment &seg, const Mac &srcMac,
                                    uint32_t clientIsn)
{
    if(!ingress)
        return;

    uint64_t bucket = (clock ? clock->Now() : 0) / 30;
    uint32_t iss = TcpCookie(ingress, pkt.srcIp, seg.srcPort, clientIsn, bucket);

    TcpSegment syn;
    syn.srcPort = tcpListenPort;
    syn.dstPort = seg.srcPort;
    syn.seq = iss;
    syn.ack = clientIsn + 1;
    syn.flags = TcpSegment::kSyn | TcpSegment::kAck;
    syn.window = 65535;
    syn.options = { 2, 4, 0x03, 0xE8 };

    IpPacket out(ingress->ip, pkt.srcIp, IpPacket::kTcp,
                 syn.ToBytes(ingress->ip, pkt.srcIp));

    ++tcpCookiesSent;
    ingress->Send(std::make_shared<const EthernetFrame>(
        srcMac, ingress->mac, EthernetFrame::kIPv4, out.ToBytes()));
}

bool EndDevice::AcceptTcpCookie(Port *ingress, const IpPacket &pkt,
                                const TcpSegment &seg, const Mac &)
{
    if(!ingress || !tcpListenEnabled)
        return false;
    if(!(seg.flags & TcpSegment::kAck) || (seg.flags & TcpSegment::kSyn))
        return false;
    if(seg.ack == 0 || seg.seq == 0)
        return false;

    uint32_t iss = seg.ack - 1;
    uint32_t clientIsn = seg.seq - 1;
    uint64_t bucket = (clock ? clock->Now() : 0) / 30;
    uint32_t expected = TcpCookie(ingress, pkt.srcIp, seg.srcPort, clientIsn, bucket);
    if(iss != expected)
    {
        expected = TcpCookie(ingress, pkt.srcIp, seg.srcPort, clientIsn,
                             bucket > 0 ? bucket - 1 : 0);
        if(iss != expected)
            return false;
    }

    if(tcpConns.size() >= kMaxTcpConns)
        return false;

    TcpConnection &c = NewTcpConnection();
    TcpConnection *cp = &c;
    c.mssLimit = TcpMssLimit(ingress);
    c.mss = c.mssLimit;
    c.onData = [cp](const std::vector<uint8_t> &data) { cp->SendData(data); };
    c.OpenPassiveCookie(ingress->ip, tcpListenPort, pkt.srcIp,
                        seg.srcPort, clientIsn, iss);
    c.OnSegment(seg, pkt.srcIp, pkt.ecn);
    IndexTcpConn(c);

    ++tcpAccepted;
    ++tcpCookiesAccepted;
    return true;
}

void EndDevice::SendTcpSegment(TcpConnection &conn, const TcpSegment &seg)
{
    Port *egress = nullptr;
    Ipv4 nextHop;
    if(!ResolveNextHop(conn.remoteIp, egress, nextHop))
        return;

    std::vector<uint8_t> bytes = seg.ToBytes(conn.localIp, conn.remoteIp);
    IpPacket pkt(conn.localIp, conn.remoteIp, IpPacket::kTcp, bytes);
    pkt.ecn = seg.ecn;
    pkt.dontFragment = true;

    Mac dstMac;
    if(arp.Lookup(nextHop, dstMac))
    {
        egress->Send(std::make_shared<const EthernetFrame>(
            dstMac, egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
        return;
    }

    bool alreadyPending =
        pendingArpCounts.find(nextHop.value) != pendingArpCounts.end();
    if(pendingPings.size() < kMaxPending)
    {
        pendingPings.push_back(PendingPing{ egress, nextHop, pkt, 0 });
        NotePendingArp(nextHop);
    }
    else
        ++droppedPending;

    if(!alreadyPending)
        arp.SendArpRequest(nextHop, egress);
}

bool EndDevice::HandleTcpStack(Port *port, const IpPacket &pkt, const Mac &srcMac)
{
    if(!port) return false;

    TcpSegment raw;
    if(!TcpSegment::TryFromBytes(pkt.payload, raw))
        return false;

    TcpConnection *conn = FindTcpConn(raw.dstPort, pkt.srcIp, raw.srcPort);
    bool tcpEchoListen = tcpListenEnabled && raw.dstPort == tcpListenPort;
    bool dnsListen = dnsServerEnabled && raw.dstPort == 53;
    bool synOnly = (raw.flags & TcpSegment::kSyn) && !(raw.flags & TcpSegment::kAck);
    bool listening = !conn && (tcpEchoListen || dnsListen) && synOnly;

    bool cookieAck = !conn && tcpEchoListen &&
                     (raw.flags & TcpSegment::kAck) && !(raw.flags & TcpSegment::kSyn);
    if(cookieAck)
    {
        CleanupTcpConns();
        if(AcceptTcpCookie(port, pkt, raw, srcMac))
            return true;
    }

    if(!conn && (tcpEchoListen || dnsListen) && synOnly)
    {
        CleanupTcpConns();
        if(tcpConns.size() >= kMaxTcpConns)
        {
            ++tcpDropped;
            SendTcpReset(port, pkt, raw, srcMac);
            return true;
        }

        std::size_t halfOpen = 0;
        for(const TcpConnection &c : tcpConns)
            if(c.state == TcpConnection::SynRcvd)
                ++halfOpen;

        if(halfOpen >= tcpBacklog)
        {
            if(dnsListen)
                SendTcpReset(port, pkt, raw, srcMac);
            else
                SendTcpCookieSynAck(port, pkt, raw, srcMac, raw.seq);
            return true;
        }
    }

    if(!conn && !listening)
    {
        if(tcpEchoEnabled && raw.dstPort == tcpEchoPort)
            return false;
        if(tcpClient.active && raw.dstPort == tcpClient.sport)
            return false;
        SendTcpReset(port, pkt, raw, srcMac);
        return true;
    }
    TcpSegment seg;
    if(!TcpSegment::TryFromBytes(pkt.payload, seg, pkt.srcIp, pkt.dstIp))
        return true;

    if(conn)
    {
        conn->OnSegment(seg, pkt.srcIp, pkt.ecn);
        return true;
    }

    if(tcpConns.size() >= kMaxTcpConns)
    {
        ++tcpDropped;
        SendTcpReset(port, pkt, raw, srcMac);
        return true;
    }

    TcpConnection &c = NewTcpConnection();
    TcpConnection *cp = &c;
    c.mssLimit = TcpMssLimit(port);
    c.mss = c.mssLimit;
    if(dnsListen)
    {
        c.onData = [this, cp](const std::vector<uint8_t> &data) {
            OnDnsTcpData(*cp, data);
        };
    }
    else
    {
        c.onData = [cp](const std::vector<uint8_t> &data) { cp->SendData(data); };
    }
    c.Listen(port->ip, dnsListen ? 53 : tcpListenPort);
    c.OnSegment(seg, pkt.srcIp, pkt.ecn);
    IndexTcpConn(c);
    ++tcpAccepted;
    return true;
}

void EndDevice::TcpConnect(Ipv4 targetIp, uint16_t dstPort, const std::string &text)
{
    Port *egress = nullptr;
    Ipv4 nextHop;
    if(!ResolveNextHop(targetIp, egress, nextHop))
    {
        std::cout << "tcp: no route to " << targetIp.ToString() << "\n";
        return;
    }

    CleanupTcpConns();
    if(tcpConns.size() >= kMaxTcpConns)
    {
        ++tcpDropped;
        std::cout << "tcp: connection limit\n";
        return;
    }

    uint16_t localPort = AllocateTcpLocalPort();
    if(localPort == 0)
    {
        ++tcpDropped;
        std::cout << "tcp: no local port\n";
        return;
    }

    TcpConnection &c = NewTcpConnection();
    TcpConnection *cp = &c;
    c.mssLimit = TcpMssLimit(egress);
    c.mss = c.mssLimit;
    c.onReset = []() { std::cout << "tcp: connection reset\n"; };
    c.onData = [targetIp, dstPort](const std::vector<uint8_t> &data) {
        std::string txt(data.begin(), data.end());
        std::cout << "tcp reply from " << targetIp.ToString() << ":" << dstPort
                  << " \"" << txt << "\"\n";
    };
    c.onConnected = [cp, text]() {
        std::vector<uint8_t> d(text.begin(), text.end());
        cp->SendData(d);
    };

    c.OpenActive(egress->ip, localPort, targetIp, dstPort, 0);
    IndexTcpConn(c);
    ++tcpAccepted;
    std::cout << "tcp: connecting to " << targetIp.ToString()
              << ":" << dstPort << "\n";
}

void EndDevice::TcpSend(const std::string &text)
{
    for(TcpConnection &c : tcpConns)
    {
        if(c.state == TcpConnection::Established)
        {
            c.SendData(std::vector<uint8_t>(text.begin(), text.end()));
            std::cout << "tcp: sent " << text.size() << " bytes\n";
            return;
        }
    }
    std::cout << "tcp: no established connection\n";
}

void EndDevice::SetDhcpServer(bool on, const Ipv4 &start, const Ipv4 &end,
                              uint8_t prefix, const Ipv4 &gw, const Ipv4 &dns)
{
    dhcpServerEnabled = on;
    if(!on)
        return;

    dhcpPoolStart = start;
    dhcpPoolEnd = end;
    dhcpPrefix = prefix;
    dhcpSubnetMask = Ipv4Subnet(start, prefix).Mask();
    dhcpRouter = gw;
    dhcpDns = dns;
    dhcpLeases.clear();
}

void EndDevice::PurgeDhcpLeases(uint64_t now)
{
    for(auto it = dhcpLeases.begin(); it != dhcpLeases.end();)
    {
        if(it->second.expires <= now)
            it = dhcpLeases.erase(it);
        else
            ++it;
    }
}

void EndDevice::SendDhcpPacket(Port *egress, const DhcpMessage &msg)
{
    if(!egress)
        return;

    UdpDatagram d;
    if(msg.op == DhcpMessage::BootRequest)
    {
        d.srcPort = 68;
        d.dstPort = 67;
    }
    else
    {
        d.srcPort = 67;
        d.dstPort = 68;
    }
    d.payload = msg.ToBytes();

    if(msg.op == DhcpMessage::BootReply && !(msg.giaddr == Ipv4::Any()))
    {
        std::string payload(d.payload.begin(), d.payload.end());
        SendUdp(msg.giaddr, 67, payload, 67);
        return;
    }

    if(msg.op == DhcpMessage::BootReply && !(msg.ciaddr == Ipv4::Any()))
    {
        std::string payload(d.payload.begin(), d.payload.end());
        SendUdp(msg.ciaddr, 68, payload, 67);
        return;
    }

    Ipv4 src = Ipv4::Any();
    if(msg.op == DhcpMessage::BootReply)
        src = egress->ip;
    else if(!(msg.ciaddr == Ipv4::Any()))
        src = msg.ciaddr;

    IpPacket pkt(src, Ipv4::Broadcast(), IpPacket::kUdp, d.ToBytes());
    egress->Send(std::make_shared<const EthernetFrame>(
        Mac::Broadcast(), egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
}

void EndDevice::StartDhcpClient(Port *p)
{
    if(!p)
        return;

    ++dhcpTimerGen;
    dhcpClientActive = true;
    dhcpState = 1;
    dhcpClientPort = p;
    dhcpXid = nextDhcpXid++;
    dhcpLeaseSec = 0;
    dhcpLeaseEnd = 0;
    dhcpRenewAt = 0;
    dhcpRebindAt = 0;
    dhcpServerAddr = Ipv4::Any();

    DhcpMessage m;
    m.op = DhcpMessage::BootRequest;
    m.xid = dhcpXid;
    m.flags = 0x8000;
    m.chaddr = p->mac;
    m.type = DhcpMessage::Discover;
    SendDhcpPacket(p, m);
}

void EndDevice::ScheduleDhcpTimer(uint64_t at)
{
    if(!scheduler)
        return;
    uint64_t now = clock ? clock->Now() : 0;
    if(at <= now)
        at = now + 1;
    uint64_t gen = ++dhcpTimerGen;
    scheduler->ScheduleAfter(at - now,
        std::make_unique<DhcpTimerEvent>(this, gen));
}

void EndDevice::OnDhcpTimer(uint64_t gen)
{
    if(gen != dhcpTimerGen || !dhcpClientActive)
        return;

    uint64_t now = clock ? clock->Now() : 0;
    if(dhcpLeaseEnd != 0 && now >= dhcpLeaseEnd)
    {
        if(dhcpClientPort)
            dhcpClientPort->hasIp = false;
        dhcpClientActive = false;
        dhcpState = 0;
        std::cout << "dhcp: lease expired\n";
        return;
    }

    if(dhcpState == 3 && now >= dhcpRenewAt)
    {
        dhcpState = 4;
        SendDhcpRenew(false);
        ScheduleDhcpTimer(dhcpRebindAt);
        return;
    }

    if(dhcpState == 4 && now >= dhcpRebindAt)
    {
        dhcpState = 5;
        SendDhcpRenew(true);
        ScheduleDhcpTimer(dhcpLeaseEnd);
        return;
    }

    ScheduleDhcpTimer(dhcpRenewAt);
}

void EndDevice::SendDhcpRenew(bool rebind)
{
    if(!dhcpClientPort || !dhcpClientActive ||
       dhcpServerAddr == Ipv4::Any())
        return;

    dhcpXid = nextDhcpXid++;
    DhcpMessage m;
    m.op = DhcpMessage::BootRequest;
    m.xid = dhcpXid;
    m.flags = rebind ? 0x8000 : 0;
    m.chaddr = dhcpClientPort->mac;
    m.ciaddr = dhcpClientPort->ip;
    m.type = DhcpMessage::Request;
    m.hasServerId = true;
    m.serverId = dhcpServerAddr;

    if(rebind)
    {
        SendDhcpPacket(dhcpClientPort, m);
    }
    else
    {
        UdpDatagram d;
        d.srcPort = 68;
        d.dstPort = 67;
        d.payload = m.ToBytes();
        SendUdp(dhcpServerAddr, 67,
                std::string(d.payload.begin(), d.payload.end()), 68);
    }
}

void EndDevice::SendDhcpRelease()
{
    if(!dhcpClientActive || !dhcpClientPort || !dhcpClientPort->hasIp)
    {
        std::cout << "dhcp: no active lease\n";
        return;
    }

    Ipv4 server = dhcpServerAddr;
    if(server == Ipv4::Any())
        server = dhcpServerId;
    if(!(server == Ipv4::Any()))
    {
        DhcpMessage m;
        m.op = DhcpMessage::BootRequest;
        m.xid = nextDhcpXid++;
        m.chaddr = dhcpClientPort->mac;
        m.ciaddr = dhcpClientPort->ip;
        m.type = DhcpMessage::Release;
        m.hasServerId = true;
        m.serverId = server;
        SendDhcpPacket(dhcpClientPort, m);
    }

    Ipv4 released = dhcpClientPort->ip;
    ++dhcpTimerGen;
    dhcpClientPort->hasIp = false;
    dhcpState = 0;
    dhcpClientActive = false;
    dhcpLeaseEnd = 0;
    std::cout << "dhcp: released " << released.ToString() << "\n";
}

void EndDevice::HandleDhcp(Port *port, const IpPacket &, const UdpDatagram &dgram)
{
    DhcpMessage m;
    if(!DhcpMessage::TryFromBytes(dgram.payload, m))
        return;

    if(dgram.dstPort == 67 && dhcpServerEnabled && m.op == DhcpMessage::BootRequest)
    {
        if(!port || !port->hasIp)
            return;

        Mac client = m.chaddr;
        uint64_t now = clock ? clock->Now() : 0;
        PurgeDhcpLeases(now);
        if(m.type == DhcpMessage::Discover)
        {
            Ipv4 ip;
            auto it = dhcpLeases.find(client);
            if(it != dhcpLeases.end())
            {
                ip = it->second.ip;
                it->second.expires = std::max(it->second.expires, now + 60);
            }
            else
            {
                bool found = false;
                uint64_t first = dhcpPoolStart.value;
                uint64_t last = dhcpPoolEnd.value;
                for(uint64_t v = first; v <= last; ++v)
                {
                    Ipv4 cand{ uint32_t(v) };
                    bool used = false;
                    for(const auto &kv : dhcpLeases)
                        if(kv.second.ip == cand) { used = true; break; }
                    if(!used)
                        for(Port *p : portList)
                            if(p->hasIp && p->ip == cand) { used = true; break; }
                    if(used)
                        continue;
                    dhcpLeases[client] = DhcpLease{ cand, now + 60 };
                    ip = cand;
                    found = true;
                    break;
                }
                if(!found)
                    return;
            }

            DhcpMessage r;
            r.op = DhcpMessage::BootReply;
            r.xid = m.xid;
            r.flags = m.flags;
            r.chaddr = client;
            r.giaddr = m.giaddr;
            r.hops = m.hops;
            r.ciaddr = m.ciaddr;
            r.yiaddr = ip;
            r.siaddr = port->ip;
            r.type = DhcpMessage::Offer;
            r.hasServerId = true;
            r.serverId = port->ip;
            r.hasSubnetMask = true;
            r.subnetMask = dhcpSubnetMask;
            r.hasRouter = true;
            r.router = dhcpRouter;
            if(!(dhcpDns == Ipv4::Any()))
            {
                r.hasDns = true;
                r.dns = dhcpDns;
            }
            r.hasLease = true;
            r.leaseTime = dhcpLeaseTime;
            SendDhcpPacket(port, r);
        }
        else if(m.type == DhcpMessage::Release)
        {
            dhcpLeases.erase(client);
        }
        else if(m.type == DhcpMessage::Request)
        {
            auto it = dhcpLeases.find(client);
            bool ok = it != dhcpLeases.end() &&
                      (!m.hasRequested || m.requestedIp == it->second.ip);

            DhcpMessage r;
            r.op = DhcpMessage::BootReply;
            r.xid = m.xid;
            r.flags = m.flags;
            r.chaddr = client;
            r.giaddr = m.giaddr;
            r.hops = m.hops;
            r.ciaddr = m.ciaddr;
            r.type = ok ? DhcpMessage::Ack : DhcpMessage::Nak;
            r.hasServerId = true;
            r.serverId = port->ip;
            if(ok)
            {
                it->second.expires = now + dhcpLeaseTime;
                r.yiaddr = it->second.ip;
                r.hasSubnetMask = true;
                r.subnetMask = dhcpSubnetMask;
                r.hasRouter = true;
                r.router = dhcpRouter;
                if(!(dhcpDns == Ipv4::Any()))
                {
                    r.hasDns = true;
                    r.dns = dhcpDns;
                }
                r.hasLease = true;
                r.leaseTime = dhcpLeaseTime;
            }
            SendDhcpPacket(port, r);
        }
        return;
    }

    if(dgram.dstPort == 68 && dhcpClientActive && m.op == DhcpMessage::BootReply)
    {
        if(m.xid != dhcpXid)
            return;

        if(m.type == DhcpMessage::Offer && dhcpState == 1)
        {
            dhcpOfferedIp = m.yiaddr;
            dhcpServerId = m.hasServerId ? m.serverId : Ipv4::Any();
            dhcpState = 2;

            DhcpMessage r;
            r.op = DhcpMessage::BootRequest;
            r.xid = dhcpXid;
            r.flags = 0x8000;
            r.chaddr = dhcpClientPort ? dhcpClientPort->mac : m.chaddr;
            r.type = DhcpMessage::Request;
            r.hasRequested = true;
            r.requestedIp = dhcpOfferedIp;
            if(m.hasServerId)
            {
                r.hasServerId = true;
                r.serverId = dhcpServerId;
            }
            SendDhcpPacket(dhcpClientPort, r);
            return;
        }

        if(m.type == DhcpMessage::Ack &&
           (dhcpState == 2 || dhcpState == 4 || dhcpState == 5))
        {
            bool renewal = (dhcpState == 4 || dhcpState == 5);
            uint8_t prefix = dhcpPrefix;
            if(m.hasSubnetMask)
            {
                uint32_t v = m.subnetMask.value;
                uint8_t n = 0;
                while(n < 32 && (v & 0x80000000u))
                {
                    ++n;
                    v <<= 1;
                }
                prefix = n;
            }

            if(dhcpClientPort)
                dhcpClientPort->SetIp(m.yiaddr, prefix);
            if(m.hasRouter)
                SetGateway(m.router);
            if(m.hasDns)
                dnsServers.assign(1, m.dns);
            if(m.hasServerId)
                dhcpServerAddr = m.serverId;
            else if(!(dhcpServerId == Ipv4::Any()))
                dhcpServerAddr = dhcpServerId;

            dhcpLeaseSec = (m.hasLease && m.leaseTime > 0)
                               ? m.leaseTime : 3600;
            uint64_t now = clock ? clock->Now() : 0;
            dhcpLeaseEnd = now + dhcpLeaseSec;
            dhcpRenewAt = now + dhcpLeaseSec / 2;
            dhcpRebindAt = now + dhcpLeaseSec * 7 / 8;

            dhcpState = 3;
            ScheduleDhcpTimer(dhcpRenewAt);

            std::cout << (renewal ? "dhcp: renewed " : "dhcp: leased ")
                      << m.yiaddr.ToString() << "/" << int(prefix);
            if(m.hasRouter)
                std::cout << " gw " << m.router.ToString();
            if(m.hasDns)
                std::cout << " dns " << m.dns.ToString();
            std::cout << "\n";
            return;
        }

        if(m.type == DhcpMessage::Nak)
        {
            ++dhcpTimerGen;
            if(dhcpClientPort)
                dhcpClientPort->hasIp = false;
            dhcpState = 0;
            dhcpClientActive = false;
            dhcpLeaseEnd = 0;
            std::cout << "dhcp: request denied\n";
        }
    }
}


bool EndDevice::ResolveNextHop(Ipv4 target, Port *&egress, Ipv4 &nextHop)
{
    egress = nullptr;

    for (Port *p : portList)
    {
        if (p->hasIp && p->subnet.Contains(target))
        {
            egress = p;
            nextHop = target;
            return true;
        }
    }

    if (!hasGateway)
        return false;

    nextHop = gateway;
    for (Port *p : portList)
    {
        if (p->hasIp && p->subnet.Contains(gateway))
        {
            egress = p;
            return true;
        }
    }
    return false;
}

void EndDevice::SendTcpTo(Ipv4 peer, uint16_t sport, uint16_t dport,
                          uint32_t seq, uint32_t ack, uint8_t flags,
                          const std::vector<uint8_t> &payload)
{
    Port *egress = nullptr;
    Ipv4 nextHop;
    if (!ResolveNextHop(peer, egress, nextHop))
        return;

    TcpSegment seg;
    seg.srcPort = sport;
    seg.dstPort = dport;
    seg.seq = seq;
    seg.ack = ack;
    seg.flags = flags;
    seg.payload = payload;

    IpPacket pkt(egress->ip, peer, IpPacket::kTcp, seg.ToBytes());

    Mac dstMac;
    if (arp.Lookup(nextHop, dstMac))
    {
        egress->Send(std::make_shared<const EthernetFrame>(
            dstMac, egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
        return;
    }

    bool alreadyPending =
        pendingArpCounts.find(nextHop.value) != pendingArpCounts.end();
    if (pendingPings.size() < kMaxPending)
    {
        pendingPings.push_back(PendingPing{ egress, nextHop, pkt, 0 });
        NotePendingArp(nextHop);
    }
    else
        ++droppedPending;

    if (!alreadyPending)
        arp.SendArpRequest(nextHop, egress);
}

void EndDevice::TcpEchoClient(Ipv4 targetIp, uint16_t dstPort, const std::string &text)
{
    Port *egress = nullptr;
    Ipv4 nextHop;
    if (!ResolveNextHop(targetIp, egress, nextHop))
    {
        std::cout << "tcp-lite: no route to " << targetIp.ToString() << "\n";
        return;
    }

    tcpClient.active = true;
    tcpClient.peer = targetIp;
    tcpClient.dport = dstPort;
    tcpClient.sport = 40001;
    tcpClient.seq = 1000;
    tcpClient.ack = 0;
    tcpClient.state = 1;
    tcpClient.text = text;

    SendTcpTo(targetIp, tcpClient.sport, dstPort, tcpClient.seq, 0,
              TcpSegment::kSyn, std::vector<uint8_t>());
    std::cout << "tcp-lite: connecting to " << targetIp.ToString()
              << ":" << dstPort << "\n";
}

void EndDevice::HandleTcp(Port *, const IpPacket &pkt, uint64_t)
{
    TcpSegment seg;
    if (!TcpSegment::TryFromBytes(pkt.payload, seg))
        return;

    uint8_t flags = seg.flags;
    bool syn = (flags & TcpSegment::kSyn) != 0;
    bool ack = (flags & TcpSegment::kAck) != 0;
    bool fin = (flags & TcpSegment::kFin) != 0;
    bool psh = (flags & TcpSegment::kPsh) != 0;

    if (tcpEchoEnabled && seg.dstPort == tcpEchoPort)
    {
        if (syn && !ack)
        {
            tcpSrvActive = true;
            tcpSrvPeer = pkt.srcIp;
            tcpSrvPeerPort = seg.srcPort;
            tcpSrvAck = seg.seq + 1;
            tcpSrvSeq = 2000;
            SendTcpTo(tcpSrvPeer, tcpEchoPort, tcpSrvPeerPort, tcpSrvSeq,
                      tcpSrvAck, TcpSegment::kSyn | TcpSegment::kAck,
                      std::vector<uint8_t>());
            tcpSrvSeq += 1;
            return;
        }

        if (psh && !seg.payload.empty())
        {
            tcpSrvAck = seg.seq + uint32_t(seg.payload.size());
            SendTcpTo(pkt.srcIp, tcpEchoPort, seg.srcPort, tcpSrvSeq,
                      tcpSrvAck, TcpSegment::kAck | TcpSegment::kPsh,
                      seg.payload);
            tcpSrvSeq += uint32_t(seg.payload.size());
            return;
        }

        if (fin)
        {
            tcpSrvAck = seg.seq + 1;
            SendTcpTo(pkt.srcIp, tcpEchoPort, seg.srcPort, tcpSrvSeq,
                      tcpSrvAck, TcpSegment::kAck, std::vector<uint8_t>());
            SendTcpTo(pkt.srcIp, tcpEchoPort, seg.srcPort, tcpSrvSeq,
                      tcpSrvAck, TcpSegment::kFin | TcpSegment::kAck,
                      std::vector<uint8_t>());
            tcpSrvSeq += 1;
            tcpSrvActive = false;
            return;
        }
        return;
    }

    if (tcpClient.active && seg.dstPort == tcpClient.sport)
    {
        if (syn && ack)
        {
            tcpClient.ack = seg.seq + 1;
            tcpClient.seq += 1;
            SendTcpTo(tcpClient.peer, tcpClient.sport, tcpClient.dport,
                      tcpClient.seq, tcpClient.ack, TcpSegment::kAck,
                      std::vector<uint8_t>());
            std::vector<uint8_t> data(tcpClient.text.begin(), tcpClient.text.end());
            SendTcpTo(tcpClient.peer, tcpClient.sport, tcpClient.dport,
                      tcpClient.seq, tcpClient.ack,
                      TcpSegment::kAck | TcpSegment::kPsh, data);
            tcpClient.seq += uint32_t(data.size());
            tcpClient.state = 2;
            return;
        }

        if (psh && !seg.payload.empty())
        {
            std::string text(seg.payload.begin(), seg.payload.end());
            std::cout << "tcp-lite echo from " << pkt.srcIp.ToString() << ":"
                      << seg.srcPort << " \"" << text << "\"\n";
            tcpClient.ack = seg.seq + uint32_t(seg.payload.size());
            SendTcpTo(tcpClient.peer, tcpClient.sport, tcpClient.dport,
                      tcpClient.seq, tcpClient.ack, TcpSegment::kAck,
                      std::vector<uint8_t>());
            SendTcpTo(tcpClient.peer, tcpClient.sport, tcpClient.dport,
                      tcpClient.seq, tcpClient.ack,
                      TcpSegment::kFin | TcpSegment::kAck,
                      std::vector<uint8_t>());
            tcpClient.seq += 1;
            tcpClient.state = 3;
            return;
        }

        if (fin)
        {
            tcpClient.ack = seg.seq + 1;
            SendTcpTo(tcpClient.peer, tcpClient.sport, tcpClient.dport,
                      tcpClient.seq, tcpClient.ack, TcpSegment::kAck,
                      std::vector<uint8_t>());
            tcpClient.active = false;
            tcpClient.state = 0;
            std::cout << "tcp-lite: connection closed\n";
            return;
        }
    }
}

void EndDevice::SendUdp(Ipv4 targetIp, uint16_t dstPort, const std::string &payload,
                        uint16_t srcPort, bool dontFragment)
{
    Port *egress = nullptr;
    Ipv4 nextHop;

    for (Port *p : portList)
    {
        if (p->hasIp && p->subnet.Contains(targetIp))
        {
            egress = p;
            nextHop = targetIp;
            break;
        }
    }

    if (!egress)
    {
        if (!hasGateway)
            return;
        nextHop = gateway;
        for (Port *p : portList)
        {
            if (p->hasIp && p->subnet.Contains(gateway))
            {
                egress = p;
                break;
            }
        }
    }

    if (!egress)
        return;

    UdpDatagram d;
    d.srcPort = srcPort ? srcPort : uint16_t(40000);
    d.dstPort = dstPort;
    d.payload.assign(payload.begin(), payload.end());

    IpPacket pkt(egress->ip, targetIp, IpPacket::kUdp, d.ToBytes());
    pkt.dontFragment = dontFragment;

    Mac dstMac;
    if (arp.Lookup(nextHop, dstMac))
    {
        egress->Send(std::make_shared<const EthernetFrame>(
            dstMac, egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
    }
    else
    {
        bool alreadyPending =
            pendingArpCounts.find(nextHop.value) != pendingArpCounts.end();
        if (pendingPings.size() < kMaxPending)
        {
            pendingPings.push_back(PendingPing{ egress, nextHop, pkt, 0 });
            NotePendingArp(nextHop);
        }
        else
            ++droppedPending;

        if (!alreadyPending)
            arp.SendArpRequest(nextHop, egress);
    }
}

void EndDevice::Traceroute(Ipv4 targetIp, uint8_t maxHops)
{
    traceHops.clear();
    traceTarget = targetIp;
    traceMaxHops = maxHops;
    traceTtl = 1;
    traceActive = true;

    std::cout << "traceroute to " << targetIp.ToString()
              << " (" << int(maxHops) << " hops max)\n";
    SendTraceProbe();
}

void EndDevice::SendTraceProbe()
{
    if (!traceActive)
        return;
    if (traceTtl > traceMaxHops)
    {
        traceActive = false;
        return;
    }

    uint16_t seq = ++nextPingSeq;
    traceHops[seq] = traceTtl;
    SendEcho(traceTarget, seq, traceTtl);
}

void EndDevice::ScheduleNextTrace()
{
    if (!traceActive)
        return;
    if (traceTtl >= traceMaxHops)
    {
        traceActive = false;
        return;
    }

    if (scheduler)
        scheduler->ScheduleAfter(1, std::make_unique<TraceNextEvent>(this));
    else
        AdvanceTrace();
}

void EndDevice::AdvanceTrace()
{
    if (!traceActive)
        return;
    ++traceTtl;
    SendTraceProbe();
}

void EndDevice::FlushPending()
{
    uint64_t now = clock ? clock->Now() : 0;

    for (auto it = pendingPings.begin(); it != pendingPings.end(); )
    {
        Mac mac;
        if (arp.Lookup(it->nextHop, mac))
        {
            auto o = outstanding.find(it->seq);
            if (o != outstanding.end())
            {
                o->second.sentAt = now;
                o->second.sent = true;
            }
            it->egress->Send(std::make_shared<const EthernetFrame>(
                mac, it->egress->mac, EthernetFrame::kIPv4, it->pkt.ToBytes()));
            DropPendingArp(it->nextHop);
            it = pendingPings.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void EndDevice::OnPing6Timeout(uint16_t seq)
{
    auto it = outstanding6.find(seq);
    if(it == outstanding6.end())
        return;

    auto th = traceHops6.find(seq);
    if(th != traceHops6.end())
    {
        std::cout << "hop " << int(th->second) << ": *\n";
        traceHops6.erase(th);
        outstanding6.erase(it);
        for(auto pit = pendingPing6.begin(); pit != pendingPing6.end();)
        {
            std::vector<PendingPing6> &v = pit->second;
            v.erase(std::remove_if(v.begin(), v.end(),
                    [seq](const PendingPing6 &p) { return p.seq == seq; }),
                    v.end());
            if(v.empty()) pit = pendingPing6.erase(pit);
            else ++pit;
        }
        ScheduleNextTrace6();
        return;
    }

    std::cout << "ping6 timeout from " << it->second.target.ToString()
              << " seq=" << seq << "\n";
    outstanding6.erase(it);

    for(auto pit = pendingPing6.begin(); pit != pendingPing6.end();)
    {
        std::vector<PendingPing6> &v = pit->second;
        v.erase(std::remove_if(v.begin(), v.end(),
                [seq](const PendingPing6 &p) { return p.seq == seq; }),
                v.end());
        if(v.empty()) pit = pendingPing6.erase(pit);
        else ++pit;
    }
}

void EndDevice::OnPingTimeout(uint16_t seq)
{
    auto it = outstanding.find(seq);
    if (it == outstanding.end())
        return;

    auto th = traceHops.find(seq);
    if (th != traceHops.end())
    {
        std::cout << "hop " << int(th->second) << ": *\n";
        traceHops.erase(th);
        outstanding.erase(it);
        for (auto p = pendingPings.begin(); p != pendingPings.end(); )
        {
            if (p->seq == seq)
            {
                DropPendingArp(p->nextHop);
                p = pendingPings.erase(p);
            }
            else ++p;
        }
        ScheduleNextTrace();
        return;
    }

    std::cout << "ping timeout from " << it->second.dst.ToString()
              << " seq=" << seq << "\n";
    outstanding.erase(it);

    for (auto p = pendingPings.begin(); p != pendingPings.end(); )
    {
        if (p->seq == seq)
        {
            DropPendingArp(p->nextHop);
            p = pendingPings.erase(p);
        }
        else
            ++p;
    }
}
