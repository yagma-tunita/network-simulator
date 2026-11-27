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
    Ipv6 SolicitedNode(const Ipv6 &target)
    {
        Ipv6 out;
        out.bytes[0] = 0xFF;
        out.bytes[1] = 0x02;
        out.bytes[11] = 0x01;
        out.bytes[12] = 0xFF;
        out.bytes[13] = target.bytes[13];
        out.bytes[14] = target.bytes[14];
        out.bytes[15] = target.bytes[15];
        return out;
    }

    Mac SolicitedMac(const Ipv6 &target)
    {
        return Mac(0x33, 0x33, 0xFF, target.bytes[13],
                   target.bytes[14], target.bytes[15]);
    }

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

    struct DnsRetryEvent : Event
    {
        EndDevice *dev;
        uint64_t gen;

        DnsRetryEvent(EndDevice *d, uint64_t g) : dev(d), gen(g) {}

        void Execute(Engine &) override { dev->OnDnsTimeout(gen); }
        const char *Name() const override { return "dns-retry"; }
    };

    struct DnsSecondaryEvent : Event
    {
        EndDevice *dev;
        std::string zone;
        uint64_t gen;

        DnsSecondaryEvent(EndDevice *d, std::string z, uint64_t g)
            : dev(d), zone(std::move(z)), gen(g) {}

        void Execute(Engine &) override { dev->OnDnsSecondaryTimer(zone, gen); }
        const char *Name() const override { return "dns-secondary"; }
    };

    std::string LowerName(const std::string &name)
    {
        std::string key;
        key.reserve(name.size());
        for(char c : name)
            key.push_back(char(std::tolower(static_cast<unsigned char>(c))));
        return key;
    }

    bool IsSubdomain(const std::string &name, const std::string &zone)
    {
        if(name == zone)
            return true;
        if(name.size() <= zone.size())
            return false;
        std::size_t off = name.size() - zone.size();
        return name[off - 1] == '.' &&
               name.compare(off, zone.size(), zone) == 0;
    }

    bool SameDnsAnswer(const DnsAnswer &a, const DnsAnswer &b)
    {
        return a.name == b.name && a.type == b.type && a.ttl == b.ttl &&
               a.ip == b.ip && a.ip6 == b.ip6 &&
               a.target == b.target &&
               a.preference == b.preference;
    }

    bool ParseInAddrArpa(const std::string &name, uint32_t &out)
    {
        static const std::string suffix = ".in-addr.arpa";
        if(name.size() <= suffix.size() ||
           name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0)
            return false;

        std::size_t end = name.size() - suffix.size();
        uint32_t parts[4] = {0, 0, 0, 0};
        std::size_t pos = 0;
        int count = 0;
        while(pos < end)
        {
            if(count >= 4)
                return false;
            std::size_t dot = name.find('.', pos);
            if(dot == std::string::npos || dot > end)
                dot = end;
            if(dot == pos || dot - pos > 3)
                return false;
            uint32_t v = 0;
            for(std::size_t i = pos; i < dot; ++i)
            {
                if(!std::isdigit(static_cast<unsigned char>(name[i])))
                    return false;
                v = v * 10 + uint32_t(name[i] - '0');
            }
            if(v > 255)
                return false;
            parts[count++] = v;
            pos = dot + 1;
        }
        if(count != 4)
            return false;
        out = (parts[3] << 24) | (parts[2] << 16) |
              (parts[1] << 8) | parts[0];
        return true;
    }
}

void EndDevice::OnFrame(Port *port, FramePtr frame)
{
    if (!port)
        return;

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
    SendIpv6(egress, SolicitedNode(nextHop), SolicitedMac(nextHop), ns);
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
    SendIpv6(egress, SolicitedNode(nextHop), SolicitedMac(nextHop), ns);
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

void EndDevice::SetDnsServer(bool on)
{
    dnsServerEnabled = on;
}

void EndDevice::AddDnsRecord(const std::string &name, const Ipv4 &ip)
{
    std::string key;
    key.reserve(name.size());
    for(char c : name)
        key.push_back(char(std::tolower(static_cast<unsigned char>(c))));
    dnsRecords[key].push_back(ip);
    dnsReverse[ip.value] = key;
}

void EndDevice::AddDnsAaaa(const std::string &name, const Ipv6 &ip)
{
    std::string key = LowerName(name);
    dnsAaaa[key].push_back(ip);
}

void EndDevice::AddDnsCname(const std::string &alias, const std::string &target)
{
    std::string a;
    std::string t;
    for(char c : alias)
        a.push_back(char(std::tolower(static_cast<unsigned char>(c))));
    for(char c : target)
        t.push_back(char(std::tolower(static_cast<unsigned char>(c))));
    dnsCnames[a] = t;
}

void EndDevice::AddDnsMx(const std::string &name, uint16_t preference,
                         const std::string &exchange)
{
    std::string key;
    std::string target;
    for(char c : name)
        key.push_back(char(std::tolower(static_cast<unsigned char>(c))));
    for(char c : exchange)
        target.push_back(char(std::tolower(static_cast<unsigned char>(c))));
    dnsMxRecords[key].push_back(DnsMxRecord{ preference, target });
}

void EndDevice::SetDnsRrTtl(const std::string &name, uint16_t type,
                            uint32_t ttl)
{
    std::string key = LowerName(name);
    dnsRrTtl[std::make_pair(key, type)] = ttl;
}

uint32_t EndDevice::DnsRrTtl(const std::string &name, uint16_t type,
                             uint32_t fallback) const
{
    std::string key = LowerName(name);
    auto it = dnsRrTtl.find(std::make_pair(key, type));
    return it == dnsRrTtl.end() ? fallback : it->second;
}

void EndDevice::AddDnsZone(const std::string &zoneName)
{
    std::string zone = LowerName(zoneName);
    auto it = dnsZones.find(zone);
    if(it != dnsZones.end())
        return;

    DnsZone z;
    z.name = zone;
    z.mname = "ns." + zone;
    z.rname = "hostmaster." + zone;
    z.ttl = dnsTtl;
    z.minimum = dnsNegativeTtl;
    dnsZones[zone] = z;
}

void EndDevice::AddDnsSecondary(const std::string &zoneName,
                                const Ipv4 &primary)
{
    std::string zone = LowerName(zoneName);
    AddDnsZone(zone);
    DnsSecondaryState state;
    state.primary = primary;
    uint64_t now = clock ? clock->Now() : 0;
    state.expireAt = now + dnsZones[zone].expire;
    dnsSecondaryZones[zone] = state;
    StartDnsSecondaryTransfer(zone, primary);
}

void EndDevice::SetDnsNotifyTargets(const std::string &zoneName,
                                    const std::vector<Ipv4> &targets)
{
    dnsNotifyTargets[LowerName(zoneName)] = targets;
}

void EndDevice::NotifyDnsZone(const std::string &zoneName)
{
    std::string zone = LowerName(zoneName);
    auto it = dnsNotifyTargets.find(zone);
    if(it != dnsNotifyTargets.end())
        NotifyDnsZone(zone, it->second);
}

void EndDevice::NotifyDnsZone(const std::string &zoneName,
                              const std::vector<Ipv4> &targets)
{
    DnsMessage m;
    m.id = uint16_t(nextDnsId++);
    m.flags = 0;
    m.SetOpcode(4);
    m.questions.push_back(DnsQuestion{
        LowerName(zoneName), DnsMessage::kTypeSoa, 1 });
    std::vector<uint8_t> bytes = m.ToBytes();
    if(bytes.empty())
        return;

    std::string payload(bytes.begin(), bytes.end());
    for(const Ipv4 &target : targets)
        SendUdp(target, 53, payload, 53);
}

void EndDevice::StartDnsSecondaryTransfer(const std::string &zone,
                                          const Ipv4 &primary)
{
    std::string key = LowerName(zone);
    auto sit = dnsSecondaryZones.find(key);
    bool useIxfr = sit != dnsSecondaryZones.end() && sit->second.initialized;
    uint32_t serial = 0;
    auto zit = dnsZones.find(key);
    if(zit != dnsZones.end())
        serial = zit->second.serial;
    StartDnsAxfr(primary, key, true, useIxfr, serial);
}

void EndDevice::ApplyDnsSecondaryTransfer(
    const std::string &zoneName, const std::vector<DnsAnswer> &records)
{
    std::string zone = LowerName(zoneName);
    AddDnsZone(zone);

    for(auto it = dnsRecords.begin(); it != dnsRecords.end();)
    {
        if(IsSubdomain(it->first, zone))
        {
            for(const Ipv4 &ip : it->second)
            {
                auto rit = dnsReverse.find(ip.value);
                if(rit != dnsReverse.end() && rit->second == it->first)
                    dnsReverse.erase(rit);
            }
            it = dnsRecords.erase(it);
        }
        else
            ++it;
    }
    for(auto it = dnsAaaa.begin(); it != dnsAaaa.end();)
        it = IsSubdomain(it->first, zone) ? dnsAaaa.erase(it) : std::next(it);
    for(auto it = dnsCnames.begin(); it != dnsCnames.end();)
        it = IsSubdomain(it->first, zone) ? dnsCnames.erase(it)
                                          : std::next(it);
    for(auto it = dnsMxRecords.begin(); it != dnsMxRecords.end();)
        it = IsSubdomain(it->first, zone) ? dnsMxRecords.erase(it)
                                          : std::next(it);
    for(auto it = dnsNsRecords.begin(); it != dnsNsRecords.end();)
        it = IsSubdomain(it->first, zone) ? dnsNsRecords.erase(it)
                                          : std::next(it);
    for(auto it = dnsRrTtl.begin(); it != dnsRrTtl.end();)
        it = IsSubdomain(it->first.first, zone) ? dnsRrTtl.erase(it)
                                                : std::next(it);

    bool sawSoa = false;
    for(const DnsAnswer &a : records)
    {
        std::string name = LowerName(a.name);
        if(a.type == DnsMessage::kTypeSoa)
        {
            if(sawSoa)
                continue;
            sawSoa = true;
            DnsZone &z = dnsZones[zone];
            z.name = zone;
            z.mname = LowerName(a.mname);
            z.rname = LowerName(a.rname);
            z.ttl = a.ttl;
            z.serial = a.serial;
            z.refresh = a.refresh;
            z.retry = a.retry;
            z.expire = a.expire;
            z.minimum = a.minimum;
            continue;
        }
        if(!IsSubdomain(name, zone))
            continue;
        if(a.type == DnsMessage::kTypeNs)
        {
            std::vector<std::string> &ns = dnsNsRecords[name];
            std::string target = LowerName(a.target);
            bool seen = false;
            for(const std::string &v : ns)
                if(v == target) { seen = true; break; }
            if(!seen)
                ns.push_back(target);
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeNs)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeA)
        {
            dnsRecords[name].push_back(a.ip);
            dnsReverse[a.ip.value] = name;
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeA)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeAaaa)
        {
            dnsAaaa[name].push_back(a.ip6);
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeAaaa)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeCname)
        {
            dnsCnames[name] = LowerName(a.target);
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeCname)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeMx)
        {
            dnsMxRecords[name].push_back(
                DnsMxRecord{ a.preference, LowerName(a.target) });
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeMx)] = a.ttl;
        }
    }

    if(!sawSoa)
    {
        std::cout << "dns: secondary " << zone << " failed\n";
        return;
    }
    auto sit = dnsSecondaryZones.find(zone);
    if(sit != dnsSecondaryZones.end())
    {
        uint64_t now = clock ? clock->Now() : 0;
        sit->second.expired = false;
        sit->second.initialized = true;
        sit->second.expireAt = now + dnsZones[zone].expire;
        ScheduleDnsSecondary(zone, dnsZones[zone].refresh);
    }
    std::cout << "dns: secondary " << zone << " updated serial "
              << dnsZones[zone].serial << "\n";
}

void EndDevice::ApplyDnsSecondaryIxfr(
    const std::string &zoneName, const std::vector<DnsAnswer> &records,
    uint32_t clientSerial)
{
    std::string zone = LowerName(zoneName);
    if(records.empty())
    {
        std::cout << "dns: secondary " << zone << " failed\n";
        return;
    }

    if(records.size() == 1 && records[0].type == DnsMessage::kTypeSoa)
    {
        DnsZone &z = dnsZones[zone];
        z.name = zone;
        z.mname = LowerName(records[0].mname);
        z.rname = LowerName(records[0].rname);
        z.ttl = records[0].ttl;
        z.serial = records[0].serial;
        z.refresh = records[0].refresh;
        z.retry = records[0].retry;
        z.expire = records[0].expire;
        z.minimum = records[0].minimum;
        auto sit = dnsSecondaryZones.find(zone);
        if(sit != dnsSecondaryZones.end())
        {
            uint64_t now = clock ? clock->Now() : 0;
            sit->second.expired = false;
            sit->second.initialized = true;
            sit->second.expireAt = now + z.expire;
            ScheduleDnsSecondary(zone, z.refresh);
        }
        std::cout << "dns: secondary " << zone << " up-to-date serial "
                  << z.serial << "\n";
        return;
    }

    bool incremental = records.size() >= 2 &&
                       records[1].type == DnsMessage::kTypeSoa &&
                       records[1].serial == clientSerial;
    if(!incremental)
    {
        ApplyDnsSecondaryTransfer(zone, records);
        return;
    }

    DnsZone &z = dnsZones[zone];
    z.name = zone;
    z.mname = LowerName(records[0].mname);
    z.rname = LowerName(records[0].rname);
    z.ttl = records[0].ttl;
    z.serial = records[0].serial;
    z.refresh = records[0].refresh;
    z.retry = records[0].retry;
    z.expire = records[0].expire;
    z.minimum = records[0].minimum;

    auto removeRecord = [&](const DnsAnswer &a)
    {
        std::string name = LowerName(a.name);
        if(a.type == DnsMessage::kTypeA)
        {
            auto it = dnsRecords.find(name);
            if(it != dnsRecords.end())
            {
                auto &v = it->second;
                for(auto i = v.begin(); i != v.end();)
                {
                    if(*i == a.ip)
                    {
                        auto rit = dnsReverse.find(a.ip.value);
                        if(rit != dnsReverse.end() && rit->second == name)
                            dnsReverse.erase(rit);
                        i = v.erase(i);
                    }
                    else
                        ++i;
                }
                if(v.empty())
                {
                    dnsRecords.erase(it);
                    dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeA));
                }
            }
        }
        else if(a.type == DnsMessage::kTypeAaaa)
        {
            auto it = dnsAaaa.find(name);
            if(it != dnsAaaa.end())
            {
                auto &v = it->second;
                for(auto i = v.begin(); i != v.end();)
                    i = (*i == a.ip6) ? v.erase(i) : std::next(i);
                if(v.empty())
                {
                    dnsAaaa.erase(it);
                    dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeAaaa));
                }
            }
        }
        else if(a.type == DnsMessage::kTypeCname)
        {
            auto it = dnsCnames.find(name);
            if(it != dnsCnames.end() &&
               it->second == LowerName(a.target))
            {
                dnsCnames.erase(it);
                dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeCname));
            }
        }
        else if(a.type == DnsMessage::kTypeMx)
        {
            auto it = dnsMxRecords.find(name);
            if(it != dnsMxRecords.end())
            {
                auto &v = it->second;
                for(auto i = v.begin(); i != v.end();)
                {
                    if(i->preference == a.preference &&
                       i->exchange == LowerName(a.target))
                        i = v.erase(i);
                    else
                        ++i;
                }
                if(v.empty())
                {
                    dnsMxRecords.erase(it);
                    dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeMx));
                }
            }
        }
        else if(a.type == DnsMessage::kTypeNs)
        {
            auto it = dnsNsRecords.find(name);
            if(it != dnsNsRecords.end())
            {
                auto &v = it->second;
                for(auto i = v.begin(); i != v.end();)
                    i = (*i == LowerName(a.target)) ? v.erase(i)
                                                    : std::next(i);
                if(v.empty())
                {
                    dnsNsRecords.erase(it);
                    dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeNs));
                }
            }
        }
    };

    auto addRecord = [&](const DnsAnswer &a)
    {
        std::string name = LowerName(a.name);
        if(a.type == DnsMessage::kTypeA)
        {
            std::vector<Ipv4> &v = dnsRecords[name];
            bool seen = false;
            for(const Ipv4 &ip : v)
                if(ip == a.ip) { seen = true; break; }
            if(!seen)
            {
                v.push_back(a.ip);
                dnsReverse[a.ip.value] = name;
            }
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeA)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeAaaa)
        {
            std::vector<Ipv6> &v = dnsAaaa[name];
            bool seen = false;
            for(const Ipv6 &ip : v)
                if(ip == a.ip6) { seen = true; break; }
            if(!seen)
                v.push_back(a.ip6);
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeAaaa)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeCname)
        {
            dnsCnames[name] = LowerName(a.target);
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeCname)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeMx)
        {
            dnsMxRecords[name].push_back(
                DnsMxRecord{ a.preference, LowerName(a.target) });
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeMx)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeNs)
        {
            std::vector<std::string> &v = dnsNsRecords[name];
            bool seen = false;
            for(const std::string &ns : v)
                if(ns == LowerName(a.target)) { seen = true; break; }
            if(!seen)
                v.push_back(LowerName(a.target));
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeNs)] = a.ttl;
        }
    };

    std::size_t i = 1;
    bool deleting = false;
    while(i < records.size())
    {
        const DnsAnswer &a = records[i];
        if(a.type == DnsMessage::kTypeSoa)
        {
            if(i + 1 == records.size())
                break;
            deleting = !deleting;
            ++i;
            continue;
        }
        if(deleting)
            removeRecord(a);
        else
            addRecord(a);
        ++i;
    }

    auto sit = dnsSecondaryZones.find(zone);
    if(sit != dnsSecondaryZones.end())
    {
        uint64_t now = clock ? clock->Now() : 0;
        sit->second.expired = false;
        sit->second.initialized = true;
        sit->second.expireAt = now + z.expire;
        ScheduleDnsSecondary(zone, z.refresh);
    }
    std::cout << "dns: secondary " << zone << " updated serial "
              << z.serial << "\n";
}

std::vector<DnsAnswer> EndDevice::SnapshotDnsZone(
    const std::string &zoneName) const
{
    std::vector<DnsAnswer> out;
    std::string zone = LowerName(zoneName);
    auto ttl = [this](const std::string &name, uint16_t type,
                      uint32_t fallback)
    {
        return DnsRrTtl(name, type, fallback);
    };
    uint32_t zoneTtl = dnsTtl;
    auto zit = dnsZones.find(zone);
    if(zit != dnsZones.end())
        zoneTtl = zit->second.ttl;

    for(const auto &kv : dnsRecords)
    {
        if(!IsSubdomain(kv.first, zone))
            continue;
        for(const Ipv4 &ip : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeA;
            a.cls = 1;
            a.ttl = ttl(kv.first, DnsMessage::kTypeA, zoneTtl);
            a.ip = ip;
            out.push_back(a);
        }
    }
    for(const auto &kv : dnsAaaa)
    {
        if(!IsSubdomain(kv.first, zone))
            continue;
        for(const Ipv6 &ip : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeAaaa;
            a.cls = 1;
            a.ttl = ttl(kv.first, DnsMessage::kTypeAaaa, zoneTtl);
            a.ip6 = ip;
            out.push_back(a);
        }
    }
    for(const auto &kv : dnsCnames)
    {
        if(!IsSubdomain(kv.first, zone))
            continue;
        DnsAnswer a;
        a.name = kv.first;
        a.type = DnsMessage::kTypeCname;
        a.cls = 1;
        a.ttl = ttl(kv.first, DnsMessage::kTypeCname, zoneTtl);
        a.target = kv.second;
        out.push_back(a);
    }
    for(const auto &kv : dnsMxRecords)
    {
        if(!IsSubdomain(kv.first, zone))
            continue;
        for(const DnsMxRecord &mx : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeMx;
            a.cls = 1;
            a.ttl = ttl(kv.first, DnsMessage::kTypeMx, zoneTtl);
            a.preference = mx.preference;
            a.target = mx.exchange;
            out.push_back(a);
        }
    }
    for(const auto &kv : dnsNsRecords)
    {
        if(!IsSubdomain(kv.first, zone))
            continue;
        for(const std::string &ns : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeNs;
            a.cls = 1;
            a.ttl = ttl(kv.first, DnsMessage::kTypeNs, zoneTtl);
            a.target = ns;
            out.push_back(a);
        }
    }
    return out;
}

void EndDevice::RecordDnsJournal(
    const std::string &zoneName, uint32_t fromSerial, uint32_t toSerial,
    const std::vector<DnsAnswer> &before,
    const std::vector<DnsAnswer> &after)
{
    std::string zone = LowerName(zoneName);
    DnsJournalEntry entry;
    entry.fromSerial = fromSerial;
    entry.toSerial = toSerial;

    for(const DnsAnswer &old : before)
    {
        bool found = false;
        for(const DnsAnswer &cur : after)
            if(SameDnsAnswer(old, cur)) { found = true; break; }
        if(!found)
            entry.deleted.push_back(old);
    }
    for(const DnsAnswer &cur : after)
    {
        bool found = false;
        for(const DnsAnswer &old : before)
            if(SameDnsAnswer(cur, old)) { found = true; break; }
        if(!found)
            entry.added.push_back(cur);
    }
    if(entry.deleted.empty() && entry.added.empty())
        return;

    std::deque<DnsJournalEntry> &journal = dnsJournal[zone];
    journal.push_back(entry);
    while(journal.size() > 64)
        journal.pop_front();
}

void EndDevice::ScheduleDnsSecondary(const std::string &zoneName,
                                     uint64_t delay)
{
    if(!scheduler)
        return;
    std::string zone = LowerName(zoneName);
    auto sit = dnsSecondaryZones.find(zone);
    if(sit == dnsSecondaryZones.end())
        return;
    if(delay == 0)
        delay = 3600;
    uint64_t gen = ++sit->second.gen;
    uint64_t now = clock ? clock->Now() : 0;
    sit->second.refreshAt = now + delay;
    scheduler->ScheduleAfter(delay,
        std::make_unique<DnsSecondaryEvent>(this, zone, gen));
}

void EndDevice::OnDnsSecondaryTimer(const std::string &zoneName, uint64_t gen)
{
    std::string zone = LowerName(zoneName);
    auto sit = dnsSecondaryZones.find(zone);
    if(sit == dnsSecondaryZones.end() || sit->second.gen != gen ||
       sit->second.expired)
        return;
    if(axfrActive)
    {
        ScheduleDnsSecondary(zone, 1);
        return;
    }
    StartDnsSecondaryTransfer(zone, sit->second.primary);
}

void EndDevice::DnsSecondaryFailed(const std::string &zoneName)
{
    std::string zone = LowerName(zoneName);
    auto sit = dnsSecondaryZones.find(zone);
    if(sit == dnsSecondaryZones.end())
        return;
    uint64_t now = clock ? clock->Now() : 0;
    if(sit->second.expireAt != 0 && now >= sit->second.expireAt)
    {
        if(!sit->second.expired)
        {
            sit->second.expired = true;
            ++sit->second.gen;
            std::cout << "dns: secondary " << zone << " expired\n";
        }
        return;
    }
    auto zit = dnsZones.find(zone);
    uint64_t retry = zit != dnsZones.end() ? zit->second.retry : 60;
    ScheduleDnsSecondary(zone, retry);
}

void EndDevice::SetDnsSoa(const std::string &zoneName,
                         const std::string &mname, const std::string &rname,
                         uint32_t ttl, uint32_t serial, uint32_t refresh,
                         uint32_t retry, uint32_t expire, uint32_t minimum)
{
    std::string zone = LowerName(zoneName);
    AddDnsZone(zone);
    DnsZone &z = dnsZones[zone];
    z.mname = LowerName(mname);
    z.rname = LowerName(rname);
    z.ttl = ttl;
    z.serial = serial;
    z.refresh = refresh;
    z.retry = retry;
    z.expire = expire;
    z.minimum = minimum;
}

void EndDevice::AddDnsNs(const std::string &ownerName,
                         const std::string &nameserver)
{
    std::string owner = LowerName(ownerName);
    std::string ns = LowerName(nameserver);
    std::vector<std::string> &list = dnsNsRecords[owner];
    for(const std::string &existing : list)
        if(existing == ns)
            return;
    list.push_back(ns);
}

void EndDevice::SetDnsAxfrAllow(const std::vector<Ipv4> &allow, bool any)
{
    dnsAxfrAllow = allow;
    dnsAxfrAllowAny = any;
}

bool EndDevice::DnsAxfrAllowed(const Ipv4 &client) const
{
    if(dnsAxfrAllowAny)
        return true;
    for(const Ipv4 &ip : dnsAxfrAllow)
        if(ip == client)
            return true;
    return false;
}

void EndDevice::SetDnsUpdateAllow(const std::vector<Ipv4> &allow, bool any)
{
    dnsUpdateAllow = allow;
    dnsUpdateAllowAny = any;
}

bool EndDevice::DnsUpdateAllowed(const Ipv4 &client) const
{
    if(dnsUpdateAllowAny)
        return true;
    for(const Ipv4 &ip : dnsUpdateAllow)
        if(ip == client)
            return true;
    return false;
}

const EndDevice::DnsTsigKey *EndDevice::FindDnsTsigKey(
    const std::string &name) const
{
    std::string key = LowerName(name);
    auto it = dnsTsigKeys.find(key);
    return it == dnsTsigKeys.end() ? nullptr : &it->second;
}

void EndDevice::AddDnsTsig(const std::string &keyName,
                           const std::string &secret,
                           const std::string &algorithm)
{
    std::string key = LowerName(keyName);
    std::string alg = LowerName(algorithm);
    if(!alg.empty() && alg.back() == '.')
        alg.pop_back();
    if(alg == "md5" || alg == "hmac-md5" || alg == "hmac-md5.sig-alg.reg.int")
        alg = "hmac-md5.sig-alg.reg.int";
    else if(alg == "sha1" || alg == "hmac-sha1")
        alg = "hmac-sha1";
    else
        alg = "hmac-sha256";

    dnsTsigKeys[key] = DnsTsigKey{ secret, alg };
    dnsTsigClient = true;
    dnsTsigClientName = key;
    dnsTsigClientSecret = secret;
    dnsTsigClientAlgorithm = alg;
}

bool EndDevice::HasDnsName(const std::string &name) const
{
    return dnsRecords.find(name) != dnsRecords.end() ||
           dnsAaaa.find(name) != dnsAaaa.end() ||
           dnsCnames.find(name) != dnsCnames.end() ||
           dnsMxRecords.find(name) != dnsMxRecords.end() ||
           dnsNsRecords.find(name) != dnsNsRecords.end();
}

std::string EndDevice::FindDnsWildcard(const std::string &name) const
{
    std::size_t dot = name.find('.');
    while(dot != std::string::npos && dot + 1 < name.size())
    {
        std::string candidate = "*." + name.substr(dot + 1);
        if(HasDnsName(candidate))
            return candidate;
        dot = name.find('.', dot + 1);
    }
    return {};
}

void EndDevice::SetDnsResolvers(const std::vector<Ipv4> &servers)
{
    dnsServers = servers;
}

void EndDevice::SetDnsCacheLimit(std::size_t entries)
{
    dnsCacheMax = entries ? entries : 1;
    while(dnsCache.size() > dnsCacheMax)
    {
        auto back = dnsLru.back();
        dnsCache.erase(back);
        dnsLru.pop_back();
    }
}

uint32_t EndDevice::ClampDnsTtl(uint32_t ttl) const
{
    if(ttl == 0)
        return 0;
    if(ttl < dnsTtlMin)
        return dnsTtlMin;
    if(ttl > dnsTtlMax)
        return dnsTtlMax;
    return ttl;
}

void EndDevice::TouchDnsCache(
    const std::pair<std::string, uint16_t> &key)
{
    auto it = dnsCache.find(key);
    if(it == dnsCache.end())
        return;
    dnsLru.splice(dnsLru.begin(), dnsLru, it->second.lru);
}

void EndDevice::StoreDnsCache(
    const std::pair<std::string, uint16_t> &key,
    const DnsCacheEntry &entry)
{
    auto it = dnsCache.find(key);
    if(it != dnsCache.end())
    {
        it->second.answers = entry.answers;
        it->second.expires = entry.expires;
        it->second.negative = entry.negative;
        it->second.nxdomain = entry.nxdomain;
        TouchDnsCache(key);
        return;
    }

    DnsCacheEntry stored = entry;
    dnsLru.push_front(key);
    stored.lru = dnsLru.begin();
    dnsCache.emplace(key, stored);

    while(dnsCache.size() > dnsCacheMax)
    {
        auto back = dnsLru.back();
        dnsCache.erase(back);
        dnsLru.pop_back();
    }
}

void EndDevice::RemoveDnsCache(
    const std::pair<std::string, uint16_t> &key)
{
    auto it = dnsCache.find(key);
    if(it == dnsCache.end())
        return;
    dnsLru.erase(it->second.lru);
    dnsCache.erase(it);
}

bool EndDevice::PrintDnsAnswers(const std::string &name,
                                const std::vector<DnsAnswer> &answers,
                                bool cached)
{
    bool printed = false;
    for(const DnsAnswer &a : answers)
    {
        if(a.type == DnsMessage::kTypeA)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> " << a.ip.ToString() << "\n";
            printed = true;
        }
        else if(a.type == DnsMessage::kTypeAaaa)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> AAAA " << a.ip6.ToString() << "\n";
            printed = true;
        }
        else if(a.type == DnsMessage::kTypePtr)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> PTR " << a.target << "\n";
            printed = true;
        }
        else if(a.type == DnsMessage::kTypeMx)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> MX " << a.preference
                      << " " << a.target << "\n";
            printed = true;
        }
        else if(a.type == DnsMessage::kTypeNs)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> NS " << a.target << "\n";
            printed = true;
        }
        else if(a.type == DnsMessage::kTypeSoa)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> SOA " << a.mname
                      << " " << a.rname << "\n";
            printed = true;
        }
    }
    return printed;
}

void EndDevice::DnsQuery(const std::string &name, uint16_t qtype)
{
    dnsReferralDepth = 0;
    dnsInternalQuery = false;
    StartDnsQuery(name, qtype, dnsServers);
}

void EndDevice::DnsQuery(const Ipv4 &server, const std::string &name,
                         uint16_t qtype)
{
    dnsReferralDepth = 0;
    dnsInternalQuery = false;
    StartDnsQuery(name, qtype, std::vector<Ipv4>{ server });
}

void EndDevice::StartDnsQuery(const std::string &name, uint16_t qtype,
                              const std::vector<Ipv4> &servers)
{
    std::string key;
    key.reserve(name.size());
    for(char c : name)
        key.push_back(char(std::tolower(static_cast<unsigned char>(c))));

    if(servers.empty())
    {
        std::cout << "dns: no resolver configured\n";
        return;
    }

    std::pair<std::string, uint16_t> cacheKey{ key, qtype };
    uint64_t now = clock ? clock->Now() : 0;
    if(!dnsInternalQuery)
    {
        auto cached = dnsCache.find(cacheKey);
        if(cached != dnsCache.end())
        {
            if(cached->second.expires > now)
            {
                TouchDnsCache(cacheKey);
                if(cached->second.negative)
                {
                    std::cout << "dns: cached " << key << " -> "
                              << (cached->second.nxdomain ? "NXDOMAIN"
                                                          : "NODATA")
                              << "\n";
                }
                else
                {
                    PrintDnsAnswers(key, cached->second.answers, true);
                }
                return;
            }
            RemoveDnsCache(cacheKey);
        }
    }

    CancelDnsRetry();
    if(dnsTcpActive)
    {
        dnsTcpActive = false;
        if(dnsTcpConn)
        {
            dnsTcpConn->Abort();
            dnsTcpConn = nullptr;
        }
    }
    dnsClientPort = nextDnsClientPort++;
    dnsQueryId = uint16_t(nextDnsId++);
    dnsQueryName = key;
    dnsQueryType = qtype;
    dnsQueryServers = servers;
    dnsQueryServerIndex = 0;
    dnsQueryAttempt = 1;
    dnsQueryServer = dnsQueryServers[0];
    SendDnsQuery();
}

void EndDevice::SendDnsQuery()
{
    if(dnsClientPort == 0 || dnsQueryServers.empty())
        return;

    DnsMessage q;
    q.id = dnsQueryId;
    q.flags = 0x0100;
    q.questions.push_back(DnsQuestion{ dnsQueryName, dnsQueryType, 1 });
    q.hasOpt = true;
    q.optUdpSize = 1232;

    std::vector<uint8_t> bytes = q.ToBytes();
    if(bytes.empty())
    {
        FailDnsQuery();
        return;
    }

    SendUdp(dnsQueryServer, 53,
            std::string(bytes.begin(), bytes.end()), dnsClientPort);
    if(dnsClientPort != 0)
        ScheduleDnsRetry();
}

void EndDevice::ScheduleDnsRetry(uint64_t delay)
{
    if(!scheduler)
        return;
    CancelDnsRetry();
    if(delay == 0)
        delay = dnsTimeout;
    uint64_t gen = ++dnsTimerGen;
    std::unique_ptr<DnsRetryEvent> ev =
        std::make_unique<DnsRetryEvent>(this, gen);
    dnsRetryEvent = ev.get();
    scheduler->ScheduleAfter(delay, std::move(ev));
}

void EndDevice::CancelDnsRetry()
{
    if(dnsRetryEvent)
    {
        dnsRetryEvent->cancelled = true;
        dnsRetryEvent = nullptr;
    }
    ++dnsTimerGen;
}

void EndDevice::OnDnsTimeout(uint64_t gen)
{
    if(gen != dnsTimerGen)
        return;

    dnsRetryEvent = nullptr;

    if(dnsTcpActive)
    {
        if(dnsTcpConn)
        {
            dnsTcpConn->Abort();
            dnsTcpConn = nullptr;
        }
        FailDnsQuery();
        return;
    }

    if(dnsClientPort == 0)
        return;

    if(dnsQueryAttempt < dnsMaxAttempts)
    {
        ++dnsQueryAttempt;
        SendDnsQuery();
        return;
    }

    if(dnsQueryServerIndex + 1 < dnsQueryServers.size())
    {
        ++dnsQueryServerIndex;
        dnsQueryServer = dnsQueryServers[dnsQueryServerIndex];
        dnsQueryAttempt = 1;
        SendDnsQuery();
        return;
    }

    FailDnsQuery();
}

void EndDevice::FailDnsQuery()
{
    CancelDnsRetry();
    dnsTcpActive = false;
    dnsTcpConn = nullptr;
    if(dnsInternalQuery)
    {
        std::string original = dnsOriginalName;
        dnsInternalQuery = false;
        dnsClientPort = 0;
        std::cout << "dns: " << original << " -> SERVFAIL\n";
        return;
    }
    std::cout << "dns: " << dnsQueryName << " -> timeout\n";
    dnsClientPort = 0;
}

void EndDevice::DnsAxfr(const Ipv4 &server, const std::string &zone)
{
    StartDnsAxfr(server, zone, false);
}

void EndDevice::DnsIxfr(const Ipv4 &server, const std::string &zone,
                        uint32_t serial)
{
    StartDnsIxfr(server, zone, serial);
}

void EndDevice::StartDnsIxfr(const Ipv4 &server, const std::string &zone,
                             uint32_t serial)
{
    if(ixfrActive && ixfrConn)
    {
        ixfrActive = false;
        ixfrConn->Abort();
        ixfrConn = nullptr;
    }

    Port *egress = nullptr;
    Ipv4 nextHop;
    if(!ResolveNextHop(server, egress, nextHop))
    {
        std::cout << "dns: ixfr " << LowerName(zone) << " failed\n";
        return;
    }

    CleanupTcpConns();
    if(tcpConns.size() >= kMaxTcpConns)
    {
        ++tcpDropped;
        std::cout << "dns: ixfr " << LowerName(zone) << " failed\n";
        return;
    }

    ixfrZone = LowerName(zone);
    ixfrSerial = serial;
    ixfrId = uint16_t(nextDnsId++);
    ixfrRequestMac.clear();

    TcpConnection &c = NewTcpConnection();
    TcpConnection *cp = &c;
    c.onConnected = [this, cp]() { SendDnsIxfrQuery(*cp); };
    c.onData = [this, cp](const std::vector<uint8_t> &data) {
        OnDnsIxfrData(*cp, data);
    };
    c.onReset = [this, cp]() {
        if(ixfrActive && ixfrConn == cp)
        {
            ixfrActive = false;
            ixfrConn = nullptr;
            std::cout << "dns: ixfr " << ixfrZone << " failed\n";
        }
    };

    ixfrConn = cp;
    ixfrActive = true;
    std::cout << "dns: ixfr " << ixfrZone << " from " << serial << "\n";
    c.OpenActive(egress->ip, nextIxfrLocalPort++, server, 53);
    IndexTcpConn(c);
}

void EndDevice::SendDnsIxfrQuery(TcpConnection &conn)
{
    if(!ixfrActive || ixfrConn != &conn)
        return;

    DnsMessage q;
    q.id = ixfrId;
    q.flags = 0x0100;
    q.questions.push_back(DnsQuestion{
        ixfrZone, DnsMessage::kTypeIxfr, 1 });
    DnsAnswer soa;
    soa.name = ixfrZone;
    soa.type = DnsMessage::kTypeSoa;
    soa.cls = 1;
    soa.ttl = 0;
    soa.mname = "ns." + ixfrZone;
    soa.rname = "hostmaster." + ixfrZone;
    soa.serial = ixfrSerial;
    q.authority.push_back(soa);
    q.hasOpt = true;
    q.optUdpSize = 1232;

    if(dnsTsigClient)
    {
        q.tsig.present = true;
        q.tsig.keyName = dnsTsigClientName;
        q.tsig.algorithm = dnsTsigClientAlgorithm;
        q.tsig.timeSigned = clock ? clock->Now() : 0;
        q.tsig.fudge = 300;
        q.tsig.originalId = q.id;
        q.tsig.error = 0;
        if(!q.SignTsig(dnsTsigClientSecret))
        {
            FailDnsIxfr();
            return;
        }
        ixfrRequestMac = q.tsig.mac;
    }

    std::vector<uint8_t> bytes = q.ToBytes();
    if(bytes.empty() || bytes.size() > 65535)
    {
        FailDnsIxfr();
        return;
    }

    std::vector<uint8_t> framed;
    framed.reserve(bytes.size() + 2);
    framed.push_back(uint8_t(bytes.size() >> 8));
    framed.push_back(uint8_t(bytes.size() & 0xFF));
    framed.insert(framed.end(), bytes.begin(), bytes.end());
    conn.SendData(framed);
}

void EndDevice::OnDnsIxfrData(TcpConnection &conn,
                              const std::vector<uint8_t> &data)
{
    conn.appRx.insert(conn.appRx.end(), data.begin(), data.end());

    while(conn.appRx.size() >= 2)
    {
        std::size_t len = (std::size_t(conn.appRx[0]) << 8) | conn.appRx[1];
        if(len == 0 || len > 65535)
        {
            FailDnsIxfr();
            return;
        }
        if(conn.appRx.size() < len + 2)
            return;

        std::vector<uint8_t> message(conn.appRx.begin() + 2,
                                     conn.appRx.begin() + 2 + len);
        conn.appRx.erase(conn.appRx.begin(),
                         conn.appRx.begin() + 2 + len);

        DnsMessage m;
        if(!DnsMessage::TryFromBytes(message, m) || !m.IsResponse() ||
           m.id != ixfrId || m.Rcode() != 0)
        {
            FailDnsIxfr();
            return;
        }

        if(!ixfrRequestMac.empty())
        {
            bool ok = m.tsig.present &&
                      m.tsig.keyName == dnsTsigClientName &&
                      m.tsig.algorithm == dnsTsigClientAlgorithm &&
                      m.tsig.originalId == ixfrId;
            if(ok)
            {
                uint64_t now = clock ? clock->Now() : 0;
                uint64_t ts = m.tsig.timeSigned;
                uint64_t diff = ts > now ? ts - now : now - ts;
                ok = diff <= m.tsig.fudge;
            }
            if(ok)
                ok = m.VerifyTsig(dnsTsigClientSecret, &ixfrRequestMac);
            if(!ok)
            {
                FailDnsIxfr();
                return;
            }
        }

        for(const DnsAnswer &a : m.answers)
        {
            if(a.type == DnsMessage::kTypeSoa)
                std::cout << "dns: ixfr SOA " << a.serial << "\n";
            else if(a.type == DnsMessage::kTypeA)
                std::cout << "dns: ixfr A " << a.name << " "
                          << a.ip.ToString() << "\n";
            else if(a.type == DnsMessage::kTypeAaaa)
                std::cout << "dns: ixfr AAAA " << a.name << " "
                          << a.ip6.ToString() << "\n";
            else if(a.type == DnsMessage::kTypeCname)
                std::cout << "dns: ixfr CNAME " << a.name << " "
                          << a.target << "\n";
            else if(a.type == DnsMessage::kTypeMx)
                std::cout << "dns: ixfr MX " << a.name << " "
                          << a.preference << " " << a.target << "\n";
            else if(a.type == DnsMessage::kTypeNs)
                std::cout << "dns: ixfr NS " << a.name << " "
                          << a.target << "\n";
        }

        std::cout << "dns: ixfr " << ixfrZone << " complete\n";
        ixfrActive = false;
        ixfrConn = nullptr;
        ixfrRequestMac.clear();
        conn.Close();
        return;
    }
}

void EndDevice::FailDnsIxfr()
{
    if(!ixfrActive)
        return;
    ixfrActive = false;
    if(ixfrConn)
    {
        ixfrConn->Abort();
        ixfrConn = nullptr;
    }
    ixfrRequestMac.clear();
    std::cout << "dns: ixfr " << ixfrZone << " failed\n";
}

void EndDevice::StartDnsAxfr(const Ipv4 &server, const std::string &zone,
                             bool internal, bool useIxfr,
                             uint32_t clientSerial)
{
    if(axfrActive && axfrConn)
    {
        axfrActive = false;
        axfrConn->Abort();
        axfrConn = nullptr;
    }

    Port *egress = nullptr;
    Ipv4 nextHop;
    if(!ResolveNextHop(server, egress, nextHop))
    {
        if(internal)
        {
            std::cout << "dns: secondary " << LowerName(zone) << " failed\n";
            DnsSecondaryFailed(zone);
        }
        else
            std::cout << "dns: axfr " << LowerName(zone) << " failed\n";
        return;
    }

    CleanupTcpConns();
    if(tcpConns.size() >= kMaxTcpConns)
    {
        ++tcpDropped;
        if(internal)
        {
            std::cout << "dns: secondary " << LowerName(zone) << " failed\n";
            DnsSecondaryFailed(zone);
        }
        else
            std::cout << "dns: axfr " << LowerName(zone) << " failed\n";
        return;
    }

    axfrZone = LowerName(zone);
    axfrInternal = internal;
    axfrUseIxfr = useIxfr;
    axfrClientSerial = clientSerial;
    axfrInternalZone = axfrZone;
    axfrId = uint16_t(nextDnsId++);
    axfrSoaCount = 0;
    axfrRecordCount = 0;
    axfrRequestMac.clear();
    axfrRecords.clear();

    TcpConnection &c = NewTcpConnection();
    TcpConnection *cp = &c;
    c.onConnected = [this, cp]() { SendDnsAxfrQuery(*cp); };
    c.onData = [this, cp](const std::vector<uint8_t> &data) {
        OnDnsAxfrData(*cp, data);
    };
    c.onReset = [this, cp]() {
        if(axfrActive && axfrConn == cp)
        {
            axfrActive = false;
            axfrConn = nullptr;
            if(axfrInternal)
            {
                std::cout << "dns: secondary " << axfrInternalZone
                          << " failed\n";
                DnsSecondaryFailed(axfrInternalZone);
            }
            else
                std::cout << "dns: axfr " << axfrZone << " failed\n";
        }
    };

    axfrConn = cp;
    axfrActive = true;
    if(!internal)
        std::cout << "dns: axfr " << axfrZone << " begin\n";
    c.OpenActive(egress->ip, nextAxfrLocalPort++, server, 53);
    IndexTcpConn(c);
}

void EndDevice::SendDnsAxfrQuery(TcpConnection &conn)
{
    if(!axfrActive || axfrConn != &conn)
        return;

    DnsMessage q;
    q.id = axfrId;
    q.flags = 0x0100;
    q.questions.push_back(DnsQuestion{
        axfrZone,
        axfrUseIxfr ? DnsMessage::kTypeIxfr : DnsMessage::kTypeAxfr, 1 });
    if(axfrUseIxfr)
    {
        DnsAnswer soa;
        soa.name = axfrZone;
        soa.type = DnsMessage::kTypeSoa;
        soa.cls = 1;
        soa.ttl = 0;
        soa.mname = "ns." + axfrZone;
        soa.rname = "hostmaster." + axfrZone;
        soa.serial = axfrClientSerial;
        q.authority.push_back(soa);
    }
    if(dnsTsigClient)
    {
        q.tsig.present = true;
        q.tsig.keyName = dnsTsigClientName;
        q.tsig.algorithm = dnsTsigClientAlgorithm;
        q.tsig.timeSigned = clock ? clock->Now() : 0;
        q.tsig.fudge = 300;
        q.tsig.originalId = q.id;
        q.tsig.error = 0;
        if(!q.SignTsig(dnsTsigClientSecret))
        {
            FailDnsAxfr();
            return;
        }
        axfrRequestMac = q.tsig.mac;
    }

    std::vector<uint8_t> bytes = q.ToBytes();
    if(bytes.empty() || bytes.size() > 65535)
    {
        FailDnsAxfr();
        return;
    }

    std::vector<uint8_t> framed;
    framed.reserve(bytes.size() + 2);
    framed.push_back(uint8_t(bytes.size() >> 8));
    framed.push_back(uint8_t(bytes.size() & 0xFF));
    framed.insert(framed.end(), bytes.begin(), bytes.end());
    conn.SendData(framed);
}

void EndDevice::OnDnsAxfrData(TcpConnection &conn,
                              const std::vector<uint8_t> &data)
{
    conn.appRx.insert(conn.appRx.end(), data.begin(), data.end());

    while(conn.appRx.size() >= 2)
    {
        std::size_t len = (std::size_t(conn.appRx[0]) << 8) | conn.appRx[1];
        if(len == 0 || len > 65535)
        {
            FailDnsAxfr();
            return;
        }
        if(conn.appRx.size() < len + 2)
            return;

        std::vector<uint8_t> message(conn.appRx.begin() + 2,
                                     conn.appRx.begin() + 2 + len);
        conn.appRx.erase(conn.appRx.begin(),
                         conn.appRx.begin() + 2 + len);

        DnsMessage m;
        if(!DnsMessage::TryFromBytes(message, m) || !m.IsResponse() ||
           m.id != axfrId || m.Rcode() != 0)
        {
            FailDnsAxfr();
            return;
        }

        if(!axfrRequestMac.empty())
        {
            bool ok = m.tsig.present &&
                      m.tsig.keyName == dnsTsigClientName &&
                      m.tsig.algorithm == dnsTsigClientAlgorithm &&
                      m.tsig.originalId == axfrId;
            if(ok)
            {
                uint64_t now = clock ? clock->Now() : 0;
                uint64_t ts = m.tsig.timeSigned;
                uint64_t diff = ts > now ? ts - now : now - ts;
                ok = diff <= m.tsig.fudge;
            }
            if(ok)
                ok = m.VerifyTsig(dnsTsigClientSecret, &axfrRequestMac);
            if(!ok)
            {
                FailDnsAxfr();
                return;
            }
        }

        if(axfrUseIxfr)
        {
            ApplyDnsSecondaryIxfr(axfrInternalZone, m.answers,
                                  axfrClientSerial);
            axfrActive = false;
            axfrInternal = false;
            axfrUseIxfr = false;
            axfrConn = nullptr;
            axfrRecords.clear();
            conn.Close();
            return;
        }

        for(const DnsAnswer &a : m.answers)
        {
            if(a.type == DnsMessage::kTypeSoa)
                ++axfrSoaCount;
            ++axfrRecordCount;
            if(axfrInternal)
            {
                axfrRecords.push_back(a);
                continue;
            }
            if(a.type == DnsMessage::kTypeSoa)
                std::cout << "dns: axfr SOA " << a.name << " "
                          << a.mname << " " << a.rname << "\n";
            else if(a.type == DnsMessage::kTypeNs)
                std::cout << "dns: axfr NS " << a.name << " "
                          << a.target << "\n";
            else if(a.type == DnsMessage::kTypeA)
                std::cout << "dns: axfr A " << a.name << " "
                          << a.ip.ToString() << "\n";
            else if(a.type == DnsMessage::kTypeAaaa)
                std::cout << "dns: axfr AAAA " << a.name << " "
                          << a.ip6.ToString() << "\n";
            else if(a.type == DnsMessage::kTypeCname)
                std::cout << "dns: axfr CNAME " << a.name << " "
                          << a.target << "\n";
            else if(a.type == DnsMessage::kTypeMx)
                std::cout << "dns: axfr MX " << a.name << " "
                          << a.preference << " " << a.target << "\n";
        }

        if(axfrSoaCount >= 2)
        {
            if(axfrInternal)
                ApplyDnsSecondaryTransfer(axfrInternalZone, axfrRecords);
            else
                std::cout << "dns: axfr " << axfrZone << " complete "
                          << axfrRecordCount << "\n";
            axfrActive = false;
            axfrInternal = false;
            axfrUseIxfr = false;
            axfrConn = nullptr;
            axfrRecords.clear();
            conn.Close();
            return;
        }
    }
}

void EndDevice::FailDnsAxfr()
{
    if(!axfrActive)
        return;
    axfrActive = false;
    if(axfrConn)
    {
        axfrConn->Abort();
        axfrConn = nullptr;
    }
    if(axfrInternal)
    {
        std::cout << "dns: secondary " << axfrInternalZone << " failed\n";
        DnsSecondaryFailed(axfrInternalZone);
    }
    else
        std::cout << "dns: axfr " << axfrZone << " failed\n";
    axfrInternal = false;
    axfrUseIxfr = false;
    axfrRecords.clear();
}

DnsMessage EndDevice::ProcessDnsUpdate(const DnsMessage &m,
                                       const Ipv4 &client)
{
    const DnsTsigKey *tsigKey = nullptr;
    std::vector<uint8_t> requestMac;
    uint64_t now = clock ? clock->Now() : 0;

    auto finish = [&](uint16_t rcode)
    {
        DnsMessage r;
        r.id = m.id;
        r.flags = 0x8000;
        r.SetOpcode(5);
        r.flags = uint16_t((r.flags & ~0x000Fu) | (rcode & 0x000Fu));
        r.questions = m.questions;
        if(tsigKey)
        {
            r.tsig.present = true;
            r.tsig.keyName = m.tsig.keyName;
            r.tsig.algorithm = tsigKey->algorithm;
            r.tsig.timeSigned = now;
            r.tsig.fudge = 300;
            r.tsig.originalId = m.id;
            r.tsig.error = 0;
            r.SignTsig(tsigKey->secret, &requestMac);
        }
        return r;
    };

    if(m.questions.size() != 1 ||
       m.questions[0].qtype != DnsMessage::kTypeSoa ||
       m.questions[0].qclass != 1)
        return finish(1);

    std::string zoneName = LowerName(m.questions[0].name);
    auto zoneIt = dnsZones.find(zoneName);
    if(zoneIt == dnsZones.end())
        return finish(9);

    if(!DnsUpdateAllowed(client))
        return finish(5);

    if(m.tsig.present)
    {
        tsigKey = FindDnsTsigKey(m.tsig.keyName);
        bool ok = tsigKey != nullptr &&
                  tsigKey->algorithm == m.tsig.algorithm &&
                  m.tsig.originalId == m.id;
        if(ok)
        {
            uint64_t ts = m.tsig.timeSigned;
            uint64_t diff = ts > now ? ts - now : now - ts;
            ok = diff <= m.tsig.fudge;
        }
        if(ok)
            ok = m.VerifyTsig(tsigKey->secret);
        if(!ok)
        {
            tsigKey = nullptr;
            return finish(9);
        }
        requestMac = m.tsig.mac;
    }
    else if(dnsTsigRequired)
    {
        return finish(5);
    }

    const uint16_t clAny = 255;
    const uint16_t clNone = 254;
    const uint16_t typeAny = 255;

    auto rrsetExists = [&](const std::string &name, uint16_t type) -> bool
    {
        if(type == DnsMessage::kTypeA)
            return dnsRecords.find(name) != dnsRecords.end();
        if(type == DnsMessage::kTypeCname)
            return dnsCnames.find(name) != dnsCnames.end();
        if(type == DnsMessage::kTypeMx)
            return dnsMxRecords.find(name) != dnsMxRecords.end();
        if(type == DnsMessage::kTypeNs)
            return dnsNsRecords.find(name) != dnsNsRecords.end();
        return false;
    };

    for(const DnsAnswer &p : m.answers)
    {
        std::string name = LowerName(p.name);
        if(p.cls == clAny)
        {
            if(p.type == typeAny)
            {
                if(!HasDnsName(name))
                    return finish(3);
            }
            else if(!rrsetExists(name, p.type))
                return finish(8);
        }
        else if(p.cls == clNone)
        {
            if(p.type == typeAny)
            {
                if(HasDnsName(name))
                    return finish(7);
            }
            else if(rrsetExists(name, p.type))
                return finish(7);
        }
        else if(p.cls == 1)
        {
            if(p.ttl != 0)
                return finish(1);
            if(!HasDnsName(name))
                return finish(3);
            if(!rrsetExists(name, p.type))
                return finish(8);

            bool valueExists = false;
            if(p.type == DnsMessage::kTypeA)
            {
                auto it = dnsRecords.find(name);
                if(it != dnsRecords.end())
                    for(const Ipv4 &ip : it->second)
                        if(ip == p.ip) { valueExists = true; break; }
            }
            else if(p.type == DnsMessage::kTypeCname)
            {
                auto it = dnsCnames.find(name);
                if(it != dnsCnames.end() &&
                   it->second == LowerName(p.target))
                    valueExists = true;
            }
            else if(p.type == DnsMessage::kTypeMx)
            {
                auto it = dnsMxRecords.find(name);
                if(it != dnsMxRecords.end())
                    for(const DnsMxRecord &mx : it->second)
                        if(mx.preference == p.preference &&
                           mx.exchange == LowerName(p.target))
                        {
                            valueExists = true;
                            break;
                        }
            }
            else
                return finish(4);
            if(!valueExists)
                return finish(8);
        }
        else
            return finish(4);
    }

    for(const DnsAnswer &u : m.authority)
    {
        std::string name = LowerName(u.name);
        if(!IsSubdomain(name, zoneName))
            return finish(5);
        if(u.cls == clAny)
        {
            if(u.type != typeAny && u.type != DnsMessage::kTypeA &&
               u.type != DnsMessage::kTypeCname &&
               u.type != DnsMessage::kTypeMx)
                return finish(4);
        }
        else if(u.cls == clNone)
        {
            if(u.type != DnsMessage::kTypeA)
                return finish(4);
        }
        else if(u.cls == 1)
        {
            if(u.type != DnsMessage::kTypeA &&
               u.type != DnsMessage::kTypeCname &&
               u.type != DnsMessage::kTypeMx)
                return finish(4);
        }
        else
            return finish(1);
    }

    std::vector<DnsAnswer> before = SnapshotDnsZone(zoneName);
    uint32_t oldSerial = zoneIt->second.serial;

    auto dropReverse = [&](const std::string &name, const Ipv4 &ip)
    {
        auto rit = dnsReverse.find(ip.value);
        if(rit != dnsReverse.end() && rit->second == name)
            dnsReverse.erase(rit);
    };

    for(const DnsAnswer &u : m.authority)
    {
        std::string name = LowerName(u.name);
        if(u.cls == clAny)
        {
            if(u.type == typeAny || u.type == DnsMessage::kTypeA)
            {
                auto it = dnsRecords.find(name);
                if(it != dnsRecords.end())
                {
                    for(const Ipv4 &ip : it->second)
                        dropReverse(name, ip);
                    dnsRecords.erase(it);
                }
                dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeA));
            }
            if(u.type == typeAny || u.type == DnsMessage::kTypeCname)
            {
                dnsCnames.erase(name);
                dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeCname));
            }
            if(u.type == typeAny || u.type == DnsMessage::kTypeMx)
            {
                dnsMxRecords.erase(name);
                dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeMx));
            }
        }
        else if(u.cls == clNone)
        {
            auto it = dnsRecords.find(name);
            if(it != dnsRecords.end())
            {
                auto &ips = it->second;
                for(auto i = ips.begin(); i != ips.end();)
                {
                    if(*i == u.ip)
                    {
                        dropReverse(name, *i);
                        i = ips.erase(i);
                    }
                    else
                        ++i;
                }
                if(ips.empty())
                {
                    dnsRecords.erase(it);
                    dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeA));
                }
            }
        }
        else if(u.cls == 1)
        {
            if(u.type == DnsMessage::kTypeA)
            {
                std::vector<Ipv4> &ips = dnsRecords[name];
                bool seen = false;
                for(const Ipv4 &ip : ips)
                    if(ip == u.ip) { seen = true; break; }
                if(!seen)
                {
                    ips.push_back(u.ip);
                    dnsReverse[u.ip.value] = name;
                }
                dnsRrTtl[std::make_pair(name, DnsMessage::kTypeA)] = u.ttl;
            }
            else if(u.type == DnsMessage::kTypeCname)
            {
                dnsCnames[name] = LowerName(u.target);
                dnsRrTtl[std::make_pair(name, DnsMessage::kTypeCname)] = u.ttl;
            }
            else if(u.type == DnsMessage::kTypeMx)
            {
                dnsMxRecords[name].push_back(
                    DnsMxRecord{ u.preference, LowerName(u.target) });
                dnsRrTtl[std::make_pair(name, DnsMessage::kTypeMx)] = u.ttl;
            }
        }
    }

    std::vector<DnsAnswer> after = SnapshotDnsZone(zoneName);
    bool changed = before.size() != after.size() ||
                   !std::equal(before.begin(), before.end(), after.begin(),
                               SameDnsAnswer);
    if(changed && !m.authority.empty())
    {
        uint32_t nextSerial = oldSerial + 1;
        if(nextSerial == 0)
            nextSerial = 1;
        RecordDnsJournal(zoneName, oldSerial, nextSerial, before, after);
        zoneIt->second.serial = nextSerial;
        NotifyDnsZone(zoneName);
    }

    return finish(0);
}

void EndDevice::DnsUpdateAdd(const Ipv4 &server, const std::string &zone,
                             const std::string &name, const Ipv4 &ip,
                             uint32_t ttl)
{
    DnsAnswer a;
    a.name = LowerName(name);
    a.type = DnsMessage::kTypeA;
    a.cls = 1;
    a.ttl = ttl;
    a.ip = ip;
    SendDnsUpdate(server, zone, std::vector<DnsAnswer>{ a });
}

void EndDevice::DnsUpdateDelete(const Ipv4 &server, const std::string &zone,
                                const std::string &name, uint16_t qtype)
{
    DnsAnswer a;
    a.name = LowerName(name);
    a.type = qtype;
    a.cls = 255;
    a.ttl = 0;
    a.noRdata = true;
    SendDnsUpdate(server, zone, std::vector<DnsAnswer>{ a });
}

void EndDevice::DnsUpdateCheck(const Ipv4 &server, const std::string &zone,
                               const std::string &name, const Ipv4 &ip)
{
    DnsAnswer p;
    p.name = LowerName(name);
    p.type = DnsMessage::kTypeA;
    p.cls = 1;
    p.ttl = 0;
    p.ip = ip;
    SendDnsUpdate(server, zone, {}, std::vector<DnsAnswer>{ p });
}

void EndDevice::SendDnsUpdate(const Ipv4 &server, const std::string &zone,
                              const std::vector<DnsAnswer> &updates,
                              const std::vector<DnsAnswer> &prereqs)
{
    DnsMessage m;
    m.id = uint16_t(nextDnsId++);
    m.flags = 0;
    m.SetOpcode(5);
    m.questions.push_back(DnsQuestion{
        LowerName(zone), DnsMessage::kTypeSoa, 1 });
    m.answers = prereqs;
    m.authority = updates;

    dnsUpdateRequestMac.clear();
    if(dnsTsigClient)
    {
        m.tsig.present = true;
        m.tsig.keyName = dnsTsigClientName;
        m.tsig.algorithm = dnsTsigClientAlgorithm;
        m.tsig.timeSigned = clock ? clock->Now() : 0;
        m.tsig.fudge = 300;
        m.tsig.originalId = m.id;
        m.tsig.error = 0;
        if(!m.SignTsig(dnsTsigClientSecret))
        {
            std::cout << "dns: update " << LowerName(zone) << " failed\n";
            return;
        }
        dnsUpdateRequestMac = m.tsig.mac;
    }

    std::vector<uint8_t> bytes = m.ToBytes();
    if(bytes.empty())
    {
        std::cout << "dns: update " << LowerName(zone) << " failed\n";
        return;
    }

    dnsUpdateActive = true;
    dnsUpdatePort = nextDnsClientPort++;
    dnsUpdateId = m.id;
    dnsUpdateServer = server;
    dnsUpdateZone = LowerName(zone);
    SendUdp(server, 53,
            std::string(bytes.begin(), bytes.end()), dnsUpdatePort);
}

DnsMessage EndDevice::BuildDnsResponse(const DnsMessage &m)
{
    if(!m.questions.empty() &&
       (m.questions[0].qtype == DnsMessage::kTypeAxfr ||
        m.questions[0].qtype == DnsMessage::kTypeIxfr))
    {
        DnsMessage r;
        r.id = m.id;
        r.flags = 0x8185;
        r.questions = m.questions;
        return r;
    }

    if(!dnsZones.empty())
        return BuildZonedDnsResponse(m);

    DnsMessage r;
    r.id = m.id;
    r.flags = 0x8180;
    r.questions = m.questions;
    r.hasOpt = m.hasOpt;
    r.optUdpSize = m.hasOpt ? 1232 : 512;

    std::string key;
    for(char c : m.questions[0].name)
        key.push_back(char(std::tolower(static_cast<unsigned char>(c))));

    std::string name = key;
    bool found = false;
    std::string wildcard;
    for(int depth = 0; depth < 8; ++depth)
    {
        auto cit = dnsCnames.find(name);
        if(cit == dnsCnames.end())
            break;
        DnsAnswer cname;
        cname.name = name;
        cname.type = DnsMessage::kTypeCname;
        cname.cls = 1;
        cname.ttl = DnsRrTtl(name, DnsMessage::kTypeCname, dnsTtl);
        cname.target = cit->second;
        r.answers.push_back(cname);
        name = cit->second;
    }

    if(!HasDnsName(key))
    {
        wildcard = FindDnsWildcard(key);
        if(!wildcard.empty())
        {
            auto cit = dnsCnames.find(wildcard);
            if(cit != dnsCnames.end())
            {
                DnsAnswer cname;
                cname.name = key;
                cname.type = DnsMessage::kTypeCname;
                cname.cls = 1;
                cname.ttl = DnsRrTtl(wildcard, DnsMessage::kTypeCname, dnsTtl);
                cname.target = cit->second;
                r.answers.push_back(cname);
                name = cit->second;
            }
        }
    }

    std::string dataName = name;
    if(name == key && !wildcard.empty() &&
       dnsCnames.find(wildcard) == dnsCnames.end())
        dataName = wildcard;

    uint16_t qtype = m.questions[0].qtype;
    if(qtype == DnsMessage::kTypeA)
    {
        auto it = dnsRecords.find(dataName);
        if(it != dnsRecords.end())
        {
            for(const Ipv4 &ip : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeA;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeA, dnsTtl);
                a.ip = ip;
                r.answers.push_back(a);
            }
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypeAaaa)
    {
        auto it = dnsAaaa.find(dataName);
        if(it != dnsAaaa.end())
        {
            for(const Ipv6 &ip : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeAaaa;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeAaaa, dnsTtl);
                a.ip6 = ip;
                r.answers.push_back(a);
            }
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypePtr)
    {
        uint32_t ip = 0;
        if(ParseInAddrArpa(name, ip))
        {
            auto it = dnsReverse.find(ip);
            if(it != dnsReverse.end())
            {
                DnsAnswer a;
                a.name = name;
                a.type = DnsMessage::kTypePtr;
                a.cls = 1;
                a.ttl = dnsTtl;
                a.target = it->second;
                r.answers.push_back(a);
                found = true;
            }
        }
    }
    else if(qtype == DnsMessage::kTypeMx)
    {
        auto it = dnsMxRecords.find(dataName);
        if(it != dnsMxRecords.end())
        {
            for(const DnsMxRecord &mx : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeMx;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeMx, dnsTtl);
                a.preference = mx.preference;
                a.target = mx.exchange;
                r.answers.push_back(a);
            }
            found = true;
        }
    }

    if(!found)
    {
        bool nameExists = !wildcard.empty() ||
                          dnsRecords.find(name) != dnsRecords.end() ||
                          dnsAaaa.find(name) != dnsAaaa.end() ||
                          dnsMxRecords.find(name) != dnsMxRecords.end() ||
                          dnsCnames.find(name) != dnsCnames.end();
        r.flags = nameExists ? 0x8180 : 0x8183;

        std::string zone = key;
        std::size_t dot = zone.find('.');
        if(dot != std::string::npos && dot + 1 < zone.size())
            zone = zone.substr(dot + 1);

        DnsAnswer soa;
        soa.name = zone;
        soa.type = DnsMessage::kTypeSoa;
        soa.cls = 1;
        soa.ttl = dnsNegativeTtl;
        soa.mname = "ns." + zone;
        soa.rname = "hostmaster." + zone;
        soa.serial = 1;
        soa.refresh = 3600;
        soa.retry = 600;
        soa.expire = 86400;
        soa.minimum = dnsNegativeTtl;
        r.authority.push_back(soa);
    }

    return r;
}

DnsMessage EndDevice::BuildZonedDnsResponse(const DnsMessage &m)
{
    DnsMessage r;
    r.id = m.id;
    r.flags = 0x8180;
    r.questions = m.questions;
    r.hasOpt = m.hasOpt;
    r.optUdpSize = m.hasOpt ? 1232 : 512;

    std::string key = LowerName(m.questions[0].name);
    const DnsZone *zone = nullptr;
    std::size_t bestZone = 0;
    for(const auto &kv : dnsZones)
    {
        if(IsSubdomain(key, kv.first) && kv.first.size() > bestZone)
        {
            zone = &kv.second;
            bestZone = kv.first.size();
        }
    }
    if(!zone)
    {
        r.flags = 0x8185;
        return r;
    }
    auto secondary = dnsSecondaryZones.find(zone->name);
    if(secondary != dnsSecondaryZones.end() && secondary->second.expired)
    {
        r.flags = 0x8182;
        return r;
    }

    std::string delegation;
    std::size_t bestDelegation = 0;
    for(const auto &kv : dnsNsRecords)
    {
        const std::string &owner = kv.first;
        if(owner == zone->name || !IsSubdomain(key, owner) ||
           !IsSubdomain(owner, zone->name))
            continue;
        if(owner.size() > bestDelegation)
        {
            delegation = owner;
            bestDelegation = owner.size();
        }
    }

    auto addSoa = [&](std::vector<DnsAnswer> &out, const std::string &owner)
    {
        DnsAnswer a;
        a.name = owner;
        a.type = DnsMessage::kTypeSoa;
        a.cls = 1;
        a.ttl = zone->ttl;
        a.mname = zone->mname;
        a.rname = zone->rname;
        a.serial = zone->serial;
        a.refresh = zone->refresh;
        a.retry = zone->retry;
        a.expire = zone->expire;
        a.minimum = zone->minimum;
        out.push_back(a);
    };

    auto addGlue = [&](const std::string &ns)
    {
        auto it = dnsRecords.find(ns);
        if(it == dnsRecords.end())
            return;
        for(const Ipv4 &ip : it->second)
        {
            DnsAnswer a;
            a.name = ns;
            a.type = DnsMessage::kTypeA;
            a.cls = 1;
            a.ttl = DnsRrTtl(ns, DnsMessage::kTypeA, zone->ttl);
            a.ip = ip;
            r.additional.push_back(a);
        }
    };

    if(bestDelegation > 0)
    {
        auto it = dnsNsRecords.find(delegation);
        if(it != dnsNsRecords.end())
        {
            for(const std::string &ns : it->second)
            {
                DnsAnswer a;
                a.name = delegation;
                a.type = DnsMessage::kTypeNs;
                a.cls = 1;
                a.ttl = DnsRrTtl(delegation, DnsMessage::kTypeNs, zone->ttl);
                a.target = ns;
                r.authority.push_back(a);
                if(IsSubdomain(ns, delegation))
                    addGlue(ns);
            }
        }
        return r;
    }

    std::string name = key;
    bool found = false;
    std::string wildcard;
    for(int depth = 0; depth < 8; ++depth)
    {
        auto cit = dnsCnames.find(name);
        if(cit == dnsCnames.end())
            break;
        DnsAnswer cname;
        cname.name = name;
        cname.type = DnsMessage::kTypeCname;
        cname.cls = 1;
        cname.ttl = DnsRrTtl(name, DnsMessage::kTypeCname, zone->ttl);
        cname.target = cit->second;
        r.answers.push_back(cname);
        if(!IsSubdomain(cit->second, zone->name))
            break;
        name = cit->second;
    }

    if(!HasDnsName(key))
    {
        wildcard = FindDnsWildcard(key);
        if(!wildcard.empty() && !IsSubdomain(wildcard, zone->name))
            wildcard.clear();
        if(!wildcard.empty())
        {
            auto cit = dnsCnames.find(wildcard);
            if(cit != dnsCnames.end())
            {
                DnsAnswer cname;
                cname.name = key;
                cname.type = DnsMessage::kTypeCname;
                cname.cls = 1;
                cname.ttl = DnsRrTtl(wildcard, DnsMessage::kTypeCname, zone->ttl);
                cname.target = cit->second;
                r.answers.push_back(cname);
                name = cit->second;
            }
        }
    }

    std::string dataName = name;
    if(name == key && !wildcard.empty() &&
       dnsCnames.find(wildcard) == dnsCnames.end())
        dataName = wildcard;

    uint16_t qtype = m.questions[0].qtype;
    if(qtype == DnsMessage::kTypeSoa)
    {
        if(name == zone->name)
        {
            addSoa(r.answers, zone->name);
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypeNs)
    {
        auto it = dnsNsRecords.find(name);
        if(it != dnsNsRecords.end())
        {
            for(const std::string &ns : it->second)
            {
                DnsAnswer a;
                a.name = name;
                a.type = DnsMessage::kTypeNs;
                a.cls = 1;
                a.ttl = DnsRrTtl(name, DnsMessage::kTypeNs, zone->ttl);
                a.target = ns;
                r.answers.push_back(a);
                addGlue(ns);
            }
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypeA)
    {
        auto it = dnsRecords.find(dataName);
        if(it != dnsRecords.end())
        {
            for(const Ipv4 &ip : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeA;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeA, zone->ttl);
                a.ip = ip;
                r.answers.push_back(a);
            }
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypeAaaa)
    {
        auto it = dnsAaaa.find(dataName);
        if(it != dnsAaaa.end())
        {
            for(const Ipv6 &ip : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeAaaa;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeAaaa, zone->ttl);
                a.ip6 = ip;
                r.answers.push_back(a);
            }
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypePtr)
    {
        uint32_t ip = 0;
        if(ParseInAddrArpa(name, ip))
        {
            auto it = dnsReverse.find(ip);
            if(it != dnsReverse.end())
            {
                DnsAnswer a;
                a.name = name;
                a.type = DnsMessage::kTypePtr;
                a.cls = 1;
                a.ttl = zone->ttl;
                a.target = it->second;
                r.answers.push_back(a);
                found = true;
            }
        }
    }
    else if(qtype == DnsMessage::kTypeMx)
    {
        auto it = dnsMxRecords.find(dataName);
        if(it != dnsMxRecords.end())
        {
            for(const DnsMxRecord &mx : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeMx;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeMx, zone->ttl);
                a.preference = mx.preference;
                a.target = mx.exchange;
                r.answers.push_back(a);
            }
            found = true;
        }
    }

    if(!found)
    {
        bool nameExists = !wildcard.empty() ||
                          name == zone->name ||
                          dnsRecords.find(name) != dnsRecords.end() ||
                          dnsAaaa.find(name) != dnsAaaa.end() ||
                          dnsMxRecords.find(name) != dnsMxRecords.end() ||
                          dnsCnames.find(name) != dnsCnames.end() ||
                          dnsNsRecords.find(name) != dnsNsRecords.end();
        r.flags = nameExists ? 0x8180 : 0x8183;
        addSoa(r.authority, zone->name);
    }

    return r;
}

DnsMessage EndDevice::BuildDnsAxfrResponse(const DnsMessage &m)
{
    DnsMessage r;
    r.id = m.id;
    r.flags = 0x8400;
    r.questions = m.questions;
    r.hasOpt = m.hasOpt;
    r.optUdpSize = m.hasOpt ? 1232 : 512;

    std::string zoneName = LowerName(m.questions[0].name);
    auto zit = dnsZones.find(zoneName);
    if(zit == dnsZones.end())
    {
        r.flags = 0x8185;
        return r;
    }
    const DnsZone &zone = zit->second;

    auto append = [&](const DnsAnswer &a) { r.answers.push_back(a); };
    auto addSoa = [&]()
    {
        DnsAnswer soa;
        soa.name = zone.name;
        soa.type = DnsMessage::kTypeSoa;
        soa.cls = 1;
        soa.ttl = zone.ttl;
        soa.mname = zone.mname;
        soa.rname = zone.rname;
        soa.serial = zone.serial;
        soa.refresh = zone.refresh;
        soa.retry = zone.retry;
        soa.expire = zone.expire;
        soa.minimum = zone.minimum;
        append(soa);
    };

    addSoa();
    auto apex = dnsNsRecords.find(zone.name);
    if(apex != dnsNsRecords.end())
    {
        for(const std::string &ns : apex->second)
        {
            DnsAnswer a;
            a.name = zone.name;
            a.type = DnsMessage::kTypeNs;
            a.cls = 1;
            a.ttl = DnsRrTtl(zone.name, DnsMessage::kTypeNs, zone.ttl);
            a.target = ns;
            append(a);
        }
    }

    for(const auto &kv : dnsRecords)
    {
        if(!IsSubdomain(kv.first, zone.name))
            continue;
        for(const Ipv4 &ip : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeA;
            a.cls = 1;
            a.ttl = DnsRrTtl(kv.first, DnsMessage::kTypeA, zone.ttl);
            a.ip = ip;
            append(a);
        }
    }

    for(const auto &kv : dnsAaaa)
    {
        if(!IsSubdomain(kv.first, zone.name))
            continue;
        for(const Ipv6 &ip : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeAaaa;
            a.cls = 1;
            a.ttl = DnsRrTtl(kv.first, DnsMessage::kTypeAaaa, zone.ttl);
            a.ip6 = ip;
            append(a);
        }
    }

    for(const auto &kv : dnsCnames)
    {
        if(!IsSubdomain(kv.first, zone.name))
            continue;
        DnsAnswer a;
        a.name = kv.first;
        a.type = DnsMessage::kTypeCname;
        a.cls = 1;
        a.ttl = DnsRrTtl(kv.first, DnsMessage::kTypeCname, zone.ttl);
        a.target = kv.second;
        append(a);
    }

    for(const auto &kv : dnsMxRecords)
    {
        if(!IsSubdomain(kv.first, zone.name))
            continue;
        for(const DnsMxRecord &mx : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeMx;
            a.cls = 1;
            a.ttl = DnsRrTtl(kv.first, DnsMessage::kTypeMx, zone.ttl);
            a.preference = mx.preference;
            a.target = mx.exchange;
            append(a);
        }
    }

    for(const auto &kv : dnsNsRecords)
    {
        if(kv.first == zone.name || !IsSubdomain(kv.first, zone.name))
            continue;
        for(const std::string &ns : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeNs;
            a.cls = 1;
            a.ttl = DnsRrTtl(kv.first, DnsMessage::kTypeNs, zone.ttl);
            a.target = ns;
            append(a);
        }
    }

    addSoa();
    return r;
}

DnsMessage EndDevice::BuildDnsIxfrResponse(const DnsMessage &m)
{
    DnsMessage r;
    r.id = m.id;
    r.flags = 0x8400;
    r.questions = m.questions;
    r.hasOpt = m.hasOpt;
    r.optUdpSize = m.hasOpt ? 1232 : 512;

    std::string zoneName = LowerName(m.questions[0].name);
    auto zit = dnsZones.find(zoneName);
    if(zit == dnsZones.end())
    {
        r.flags = 0x8185;
        return r;
    }
    const DnsZone &zone = zit->second;
    uint32_t clientSerial = 0;
    for(const DnsAnswer &a : m.authority)
    {
        if(a.type == DnsMessage::kTypeSoa)
        {
            clientSerial = a.serial;
            break;
        }
    }

    auto addSoa = [&](uint32_t serial)
    {
        DnsAnswer soa;
        soa.name = zone.name;
        soa.type = DnsMessage::kTypeSoa;
        soa.cls = 1;
        soa.ttl = zone.ttl;
        soa.mname = zone.mname;
        soa.rname = zone.rname;
        soa.serial = serial;
        soa.refresh = zone.refresh;
        soa.retry = zone.retry;
        soa.expire = zone.expire;
        soa.minimum = zone.minimum;
        r.answers.push_back(soa);
    };

    if(clientSerial >= zone.serial)
    {
        addSoa(zone.serial);
        return r;
    }

    auto jit = dnsJournal.find(zone.name);
    std::vector<const DnsJournalEntry *> chain;
    uint32_t serial = clientSerial;
    while(serial != zone.serial)
    {
        const DnsJournalEntry *found = nullptr;
        if(jit != dnsJournal.end())
        {
            for(const DnsJournalEntry &entry : jit->second)
                if(entry.fromSerial == serial)
                {
                    found = &entry;
                    break;
                }
        }
        if(!found)
            break;
        chain.push_back(found);
        serial = found->toSerial;
        if(chain.size() > 64)
            break;
    }

    if(serial != zone.serial || chain.empty())
        return BuildDnsAxfrResponse(m);

    addSoa(zone.serial);
    for(const DnsJournalEntry *entry : chain)
    {
        addSoa(entry->fromSerial);
        for(const DnsAnswer &a : entry->deleted)
            r.answers.push_back(a);
        addSoa(entry->toSerial);
        for(const DnsAnswer &a : entry->added)
            r.answers.push_back(a);
    }
    addSoa(zone.serial);
    return r;
}

bool EndDevice::TryFollowDnsReferral(const DnsMessage &m)
{
    if(!m.answers.empty() || m.Rcode() != 0)
        return false;

    std::string owner;
    std::vector<std::string> nameservers;
    for(const DnsAnswer &a : m.authority)
    {
        if(a.type == DnsMessage::kTypeNs)
        {
            owner = LowerName(a.name);
            nameservers.push_back(LowerName(a.target));
        }
    }
    if(nameservers.empty())
        return false;

    Ipv4 glue;
    bool haveGlue = false;
    for(const std::string &ns : nameservers)
    {
        for(const DnsAnswer &a : m.additional)
        {
            if(a.type == DnsMessage::kTypeA && LowerName(a.name) == ns)
            {
                glue = a.ip;
                haveGlue = true;
                break;
            }
        }
        if(haveGlue)
            break;
    }

    if(dnsReferralDepth >= 8 || (dnsInternalQuery && !haveGlue))
    {
        std::string failed = dnsInternalQuery ? dnsOriginalName : dnsQueryName;
        std::cout << "dns: " << failed << " -> SERVFAIL\n";
        dnsClientPort = 0;
        dnsInternalQuery = false;
        return true;
    }

    if(!haveGlue)
    {
        ++dnsReferralDepth;
        dnsInternalQuery = true;
        dnsOriginalName = dnsQueryName;
        dnsOriginalType = dnsQueryType;
        dnsReferralOwner = owner;
        std::vector<Ipv4> resolvers = dnsQueryServers;
        if(resolvers.empty())
            resolvers.push_back(dnsQueryServer);
        std::cout << "dns: referral " << owner << " -> resolve NS "
                  << nameservers[0] << "\n";
        StartDnsQuery(nameservers[0], DnsMessage::kTypeA, resolvers);
        return true;
    }

    ++dnsReferralDepth;
    std::cout << "dns: referral " << owner << " -> "
              << glue.ToString() << "\n";
    StartDnsQuery(dnsQueryName, dnsQueryType,
                  std::vector<Ipv4>{ glue });
    return true;
}

void EndDevice::ProcessDnsResponse(const DnsMessage &m)
{
    if(dnsInternalQuery)
    {
        Ipv4 glue;
        bool haveGlue = false;
        for(const DnsAnswer &a : m.answers)
        {
            if(a.type == DnsMessage::kTypeA)
            {
                glue = a.ip;
                haveGlue = true;
                break;
            }
        }

        std::string original = dnsOriginalName;
        uint16_t originalType = dnsOriginalType;
        std::string owner = dnsReferralOwner;
        dnsInternalQuery = false;
        dnsClientPort = 0;

        if(!haveGlue)
        {
            std::cout << "dns: " << original << " -> SERVFAIL\n";
            return;
        }

        std::cout << "dns: referral " << owner << " -> "
                  << glue.ToString() << "\n";
        StartDnsQuery(original, originalType, std::vector<Ipv4>{ glue });
        return;
    }

    uint32_t ttl = 0xFFFFFFFFu;
    bool ttlSeen = false;
    bool hasData = false;
    for(const DnsAnswer &a : m.answers)
    {
        if(a.type == DnsMessage::kTypeA ||
           a.type == DnsMessage::kTypeAaaa ||
           a.type == DnsMessage::kTypeCname ||
           a.type == DnsMessage::kTypePtr ||
           a.type == DnsMessage::kTypeMx ||
           a.type == DnsMessage::kTypeNs ||
           a.type == DnsMessage::kTypeSoa)
        {
            ttl = std::min(ttl, a.ttl);
            ttlSeen = true;
        }
        if(a.type == DnsMessage::kTypeA ||
           a.type == DnsMessage::kTypeAaaa ||
           a.type == DnsMessage::kTypePtr ||
           a.type == DnsMessage::kTypeMx ||
           a.type == DnsMessage::kTypeNs ||
           a.type == DnsMessage::kTypeSoa)
            hasData = true;
    }

    bool printed = PrintDnsAnswers(dnsQueryName, m.answers);
    if(!printed)
    {
        if(m.Rcode() == 3)
            std::cout << "dns: " << dnsQueryName << " -> NXDOMAIN\n";
        else if(m.Rcode() == 0)
            std::cout << "dns: " << dnsQueryName << " -> NODATA\n";
        else
            std::cout << "dns: " << dnsQueryName << " -> SERVFAIL\n";
    }

    auto cacheKey = std::make_pair(dnsQueryName, dnsQueryType);
    if(hasData && ttlSeen && ttl > 0)
    {
        uint64_t now = clock ? clock->Now() : 0;
        DnsCacheEntry entry;
        entry.answers = m.answers;
        entry.expires = now + ClampDnsTtl(ttl);
        entry.negative = false;
        entry.nxdomain = false;
        StoreDnsCache(cacheKey, entry);
    }
    else if(m.Rcode() == 0 || m.Rcode() == 3)
    {
        uint32_t negTtl = 0xFFFFFFFFu;
        bool negSeen = false;
        for(const DnsAnswer &a : m.authority)
        {
            if(a.type == DnsMessage::kTypeSoa)
            {
                negTtl = std::min(negTtl, std::min(a.ttl, a.minimum));
                negSeen = true;
            }
        }
        if(negSeen && negTtl > 0)
        {
            uint64_t now = clock ? clock->Now() : 0;
            DnsCacheEntry entry;
            entry.expires = now + ClampDnsTtl(negTtl);
            entry.negative = true;
            entry.nxdomain = m.Rcode() == 3;
            StoreDnsCache(cacheKey, entry);
        }
        else
        {
            RemoveDnsCache(cacheKey);
        }
    }
    dnsClientPort = 0;
}

void EndDevice::StartDnsTcpQuery()
{
    Port *egress = nullptr;
    Ipv4 nextHop;
    if(!ResolveNextHop(dnsQueryServer, egress, nextHop))
    {
        FailDnsQuery();
        return;
    }

    CleanupTcpConns();
    if(tcpConns.size() >= kMaxTcpConns)
    {
        ++tcpDropped;
        FailDnsQuery();
        return;
    }

    TcpConnection &c = NewTcpConnection();
    TcpConnection *cp = &c;
    c.onConnected = [this, cp]() { SendDnsTcpQuery(*cp); };
    c.onData = [this, cp](const std::vector<uint8_t> &data) {
        OnDnsTcpData(*cp, data);
    };
    c.onReset = [this, cp]() {
        if(dnsTcpActive && dnsTcpConn == cp)
        {
            dnsTcpActive = false;
            dnsTcpConn = nullptr;
            FailDnsQuery();
        }
    };
    dnsTcpConn = cp;
    dnsTcpActive = true;
    c.OpenActive(egress->ip, nextDnsTcpLocalPort++, dnsQueryServer, 53);
    IndexTcpConn(c);
    if(dnsTcpActive)
        ScheduleDnsRetry(std::max<uint64_t>(dnsTimeout * 5, 500));
}

void EndDevice::SendDnsTcpQuery(TcpConnection &conn)
{
    if(!dnsTcpActive || dnsTcpConn != &conn)
        return;

    DnsMessage q;
    q.id = dnsQueryId;
    q.flags = 0x0100;
    q.questions.push_back(DnsQuestion{ dnsQueryName, dnsQueryType, 1 });
    q.hasOpt = true;
    q.optUdpSize = 1232;

    std::vector<uint8_t> bytes = q.ToBytes();
    if(bytes.empty() || bytes.size() > 65535)
    {
        conn.Abort();
        dnsTcpActive = false;
        dnsTcpConn = nullptr;
        FailDnsQuery();
        return;
    }

    std::vector<uint8_t> framed;
    framed.reserve(bytes.size() + 2);
    framed.push_back(uint8_t(bytes.size() >> 8));
    framed.push_back(uint8_t(bytes.size() & 0xFF));
    framed.insert(framed.end(), bytes.begin(), bytes.end());
    conn.SendData(framed);
}

void EndDevice::OnDnsTcpData(TcpConnection &conn,
                             const std::vector<uint8_t> &data)
{
    conn.appRx.insert(conn.appRx.end(), data.begin(), data.end());

    if(conn.localPort == 53)
    {
        while(conn.appRx.size() >= 2)
        {
            std::size_t len = (std::size_t(conn.appRx[0]) << 8) |
                              conn.appRx[1];
            if(len == 0 || len > 65535)
            {
                conn.Abort();
                return;
            }
            if(conn.appRx.size() < len + 2)
                return;
            std::vector<uint8_t> message(conn.appRx.begin() + 2,
                                         conn.appRx.begin() + 2 + len);
            conn.appRx.erase(conn.appRx.begin(),
                             conn.appRx.begin() + 2 + len);
            HandleDnsTcpQuery(conn, message);
        }
        return;
    }

    if(!dnsTcpActive || dnsTcpConn != &conn)
        return;

    while(conn.appRx.size() >= 2)
    {
        std::size_t len = (std::size_t(conn.appRx[0]) << 8) | conn.appRx[1];
        if(len == 0 || len > 65535)
            break;
        if(conn.appRx.size() < len + 2)
            return;

        std::vector<uint8_t> message(conn.appRx.begin() + 2,
                                     conn.appRx.begin() + 2 + len);
        conn.appRx.erase(conn.appRx.begin(),
                         conn.appRx.begin() + 2 + len);

        DnsMessage m;
        if(!DnsMessage::TryFromBytes(message, m))
            continue;
        if(!m.IsResponse() || m.id != dnsQueryId || m.questions.empty())
            continue;

        std::string qname;
        for(char ch : m.questions[0].name)
            qname.push_back(char(std::tolower(static_cast<unsigned char>(ch))));
        if(qname != dnsQueryName || m.questions[0].qtype != dnsQueryType)
            continue;

        CancelDnsRetry();
        dnsTcpActive = false;
        dnsTcpConn = nullptr;
        ProcessDnsResponse(m);
        conn.Close();
        return;
    }
}

void EndDevice::HandleDnsTcpQuery(TcpConnection &conn,
                                  const std::vector<uint8_t> &message)
{
    DnsMessage m;
    if(!DnsMessage::TryFromBytes(message, m))
        return;
    if(m.Opcode() == 5 && !m.IsResponse())
    {
        DnsMessage r = ProcessDnsUpdate(m, conn.remoteIp);
        std::vector<uint8_t> bytes = r.ToBytes();
        if(bytes.empty() || bytes.size() > 65535)
        {
            conn.Abort();
            return;
        }
        std::vector<uint8_t> framed;
        framed.reserve(bytes.size() + 2);
        framed.push_back(uint8_t(bytes.size() >> 8));
        framed.push_back(uint8_t(bytes.size() & 0xFF));
        framed.insert(framed.end(), bytes.begin(), bytes.end());
        conn.SendData(framed);
        conn.Close();
        return;
    }
    if(m.IsResponse() || m.questions.empty())
        return;

    auto refuse = [&]()
    {
        DnsMessage r;
        r.id = m.id;
        r.flags = 0x8185;
        r.questions = m.questions;
        std::vector<uint8_t> bytes = r.ToBytes();
        if(bytes.empty() || bytes.size() > 65535)
        {
            conn.Abort();
            return;
        }
        std::vector<uint8_t> framed;
        framed.reserve(bytes.size() + 2);
        framed.push_back(uint8_t(bytes.size() >> 8));
        framed.push_back(uint8_t(bytes.size() & 0xFF));
        framed.insert(framed.end(), bytes.begin(), bytes.end());
        conn.SendData(framed);
        conn.Close();
    };

    bool axfr = m.questions[0].qtype == DnsMessage::kTypeAxfr;
    bool ixfr = m.questions[0].qtype == DnsMessage::kTypeIxfr;
    bool transfer = axfr || ixfr;
    if(transfer && !DnsAxfrAllowed(conn.remoteIp))
    {
        refuse();
        return;
    }

    std::vector<uint8_t> requestMac;
    const DnsTsigKey *tsigKey = nullptr;
    uint64_t now = clock ? clock->Now() : 0;
    if(m.tsig.present)
    {
        tsigKey = FindDnsTsigKey(m.tsig.keyName);
        bool ok = tsigKey != nullptr && tsigKey->algorithm == m.tsig.algorithm &&
                  m.tsig.originalId == m.id;
        if(ok)
        {
            uint64_t ts = m.tsig.timeSigned;
            uint64_t diff = ts > now ? ts - now : now - ts;
            ok = diff <= m.tsig.fudge;
        }
        if(ok)
            ok = m.VerifyTsig(tsigKey->secret);
        if(!ok)
        {
            refuse();
            return;
        }
        requestMac = m.tsig.mac;
    }
    else if(transfer && dnsTsigRequired)
    {
        refuse();
        return;
    }

    DnsMessage r =
        axfr ? BuildDnsAxfrResponse(m)
             : (ixfr ? BuildDnsIxfrResponse(m) : BuildDnsResponse(m));

    if(axfr && r.Rcode() == 0)
    {
        std::vector<DnsMessage> chunks;
        DnsMessage cur;
        auto resetChunk = [&]()
        {
            cur = DnsMessage();
            cur.id = r.id;
            cur.flags = r.flags;
            cur.questions = r.questions;
            cur.hasOpt = r.hasOpt;
            cur.optUdpSize = r.optUdpSize;
        };
        resetChunk();
        for(const DnsAnswer &a : r.answers)
        {
            cur.answers.push_back(a);
            if(cur.answers.size() % 32 == 0)
            {
                std::vector<uint8_t> probe = cur.ToBytes();
                if(probe.size() > 60000)
                {
                    cur.answers.pop_back();
                    chunks.push_back(cur);
                    resetChunk();
                    cur.answers.push_back(a);
                }
            }
        }
        if(!cur.answers.empty())
            chunks.push_back(cur);

        std::vector<uint8_t> framed;
        for(DnsMessage &chunk : chunks)
        {
            if(!requestMac.empty() && tsigKey)
            {
                chunk.tsig.present = true;
                chunk.tsig.keyName = m.tsig.keyName;
                chunk.tsig.algorithm = tsigKey->algorithm;
                chunk.tsig.timeSigned = now;
                chunk.tsig.fudge = 300;
                chunk.tsig.originalId = m.id;
                chunk.tsig.error = 0;
                if(!chunk.SignTsig(tsigKey->secret, &requestMac))
                {
                    conn.Abort();
                    return;
                }
            }
            std::vector<uint8_t> bytes = chunk.ToBytes();
            if(bytes.empty() || bytes.size() > 65535)
            {
                conn.Abort();
                return;
            }
            framed.push_back(uint8_t(bytes.size() >> 8));
            framed.push_back(uint8_t(bytes.size() & 0xFF));
            framed.insert(framed.end(), bytes.begin(), bytes.end());
        }
        conn.SendData(framed);
        conn.Close();
        return;
    }

    if(!requestMac.empty() && tsigKey)
    {
        r.tsig.present = true;
        r.tsig.keyName = m.tsig.keyName;
        r.tsig.algorithm = tsigKey->algorithm;
        r.tsig.timeSigned = now;
        r.tsig.fudge = 300;
        r.tsig.originalId = m.id;
        r.tsig.error = 0;
        if(!r.SignTsig(tsigKey->secret, &requestMac))
        {
            conn.Abort();
            return;
        }
    }

    std::vector<uint8_t> bytes = r.ToBytes();
    if(bytes.empty() || bytes.size() > 65535)
    {
        conn.Abort();
        return;
    }

    std::vector<uint8_t> framed;
    framed.reserve(bytes.size() + 2);
    framed.push_back(uint8_t(bytes.size() >> 8));
    framed.push_back(uint8_t(bytes.size() & 0xFF));
    framed.insert(framed.end(), bytes.begin(), bytes.end());
    conn.SendData(framed);
    conn.Close();
}

void EndDevice::HandleDns(Port *, const IpPacket &pkt, const UdpDatagram &dgram)
{
    DnsMessage m;
    if(!DnsMessage::TryFromBytes(dgram.payload, m))
        return;

    if(dgram.dstPort == 53 && dnsServerEnabled && m.Opcode() == 4)
    {
        if(m.IsResponse() || m.questions.empty())
            return;

        std::string zone = LowerName(m.questions[0].name);
        auto sit = dnsSecondaryZones.find(zone);
        DnsMessage r;
        r.id = m.id;
        r.flags = 0x8000;
        r.SetOpcode(4);
        r.flags = uint16_t((r.flags & ~0x000Fu) |
                           (sit == dnsSecondaryZones.end() ? 5 : 0));
        r.questions = m.questions;
        std::vector<uint8_t> bytes = r.ToBytes();
        if(!bytes.empty())
            SendUdp(pkt.srcIp, dgram.srcPort,
                    std::string(bytes.begin(), bytes.end()), 53);

        if(sit != dnsSecondaryZones.end())
            StartDnsSecondaryTransfer(zone, sit->second.primary);
        return;
    }

    if(dgram.dstPort == 53 && dnsServerEnabled && m.Opcode() == 5 &&
       !m.IsResponse())
    {
        DnsMessage r = ProcessDnsUpdate(m, pkt.srcIp);
        std::vector<uint8_t> bytes = r.ToBytes();
        if(!bytes.empty())
            SendUdp(pkt.srcIp, dgram.srcPort,
                    std::string(bytes.begin(), bytes.end()), 53);
        return;
    }

    if(dnsUpdateActive && dgram.dstPort == dnsUpdatePort &&
       m.IsResponse() && m.Opcode() == 5)
    {
        if(m.id != dnsUpdateId || !(pkt.srcIp == dnsUpdateServer))
            return;

        bool sigOk = true;
        if(!dnsUpdateRequestMac.empty())
        {
            sigOk = m.tsig.present &&
                    m.tsig.keyName == dnsTsigClientName &&
                    m.tsig.algorithm == dnsTsigClientAlgorithm &&
                    m.tsig.originalId == dnsUpdateId;
            if(sigOk)
            {
                uint64_t now = clock ? clock->Now() : 0;
                uint64_t ts = m.tsig.timeSigned;
                uint64_t diff = ts > now ? ts - now : now - ts;
                sigOk = diff <= m.tsig.fudge;
            }
            if(sigOk)
                sigOk = m.VerifyTsig(dnsTsigClientSecret,
                                     &dnsUpdateRequestMac);
        }

        std::string result = "failed";
        if(!sigOk)
            result = "failed";
        else if(m.Rcode() == 0)
            result = "ok";
        else if(m.Rcode() == 5)
            result = "refused";
        else if(m.Rcode() == 9)
            result = "notauth";
        else if(m.Rcode() == 1)
            result = "formerr";
        else if(m.Rcode() == 3)
            result = "nxdomain";
        else if(m.Rcode() == 4)
            result = "notimp";
        else if(m.Rcode() == 7 || m.Rcode() == 8)
            result = "prereq";

        std::cout << "dns: update " << dnsUpdateZone << " "
                  << result << "\n";
        dnsUpdateActive = false;
        dnsUpdateRequestMac.clear();
        return;
    }

    if(dgram.dstPort == 53 && dnsServerEnabled)
    {
        if(m.IsResponse() || m.questions.empty())
            return;

        DnsMessage r = BuildDnsResponse(m);
        uint16_t limit = 512;
        if(m.hasOpt)
            limit = std::max<uint16_t>(512, std::min<uint16_t>(m.optUdpSize, 4096));

        std::vector<uint8_t> bytes = r.ToBytes();
        if(bytes.size() > limit)
        {
            DnsMessage t;
            t.id = r.id;
            t.flags = r.flags | 0x0200;
            t.questions = r.questions;
            t.hasOpt = r.hasOpt;
            t.optUdpSize = r.optUdpSize;
            bytes = t.ToBytes();
        }
        if(bytes.empty())
            return;
        SendUdp(pkt.srcIp, dgram.srcPort,
                std::string(bytes.begin(), bytes.end()), 53);
        return;
    }

    if(dgram.srcPort == 53 && dnsClientPort != 0 && dgram.dstPort == dnsClientPort)
    {
        if(!m.IsResponse() || m.id != dnsQueryId)
            return;
        if(!(pkt.srcIp == dnsQueryServer) || m.questions.empty())
            return;

        std::string qname;
        for(char c : m.questions[0].name)
            qname.push_back(char(std::tolower(static_cast<unsigned char>(c))));
        if(qname != dnsQueryName || m.questions[0].qtype != dnsQueryType)
            return;

        CancelDnsRetry();

        if(m.flags & 0x0200)
        {
            dnsClientPort = 0;
            std::cout << "dns: truncated; retrying over TCP\n";
            StartDnsTcpQuery();
            return;
        }

        if(TryFollowDnsReferral(m))
            return;

        ProcessDnsResponse(m);
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
