#include "EndDevice.hpp"
#include "Port.hpp"
#include "../core/IpPacket.hpp"
#include "../core/IcmpMessage.hpp"
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

    struct TraceNextEvent : Event
    {
        EndDevice *dev;
        explicit TraceNextEvent(EndDevice *d) : dev(d) {}

        void Execute(Engine &) override { dev->AdvanceTrace(); }
        const char *Name() const override { return "trace-next"; }
    };
}

void EndDevice::OnFrame(Port *port, FramePtr frame)
{
    if (!port)
        return;

    if ((port->mac != frame->dst) && !frame->IsBroadcast())
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
            (dnsClientPort != 0 && d.dstPort == dnsClientPort))
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
        if(!HandleTcpStack(port, pkt))
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
        bool alreadyPending = false;
        for (const PendingPing &pp : pendingPings)
            if (pp.nextHop == nextHop) { alreadyPending = true; break; }

        if (pendingPings.size() < kMaxPending)
            pendingPings.push_back(PendingPing{ egress, nextHop, pkt, seq });
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

TcpConnection *EndDevice::FindTcpConn(uint16_t localPort, Ipv4 remote, uint16_t remotePort)
{
    for(TcpConnection &c : tcpConns)
    {
        if(c.state != TcpConnection::Closed &&
           c.localPort == localPort && c.remoteIp == remote && c.remotePort == remotePort)
            return &c;
    }
    return nullptr;
}

void EndDevice::SendTcpSegment(TcpConnection &conn, const TcpSegment &seg)
{
    Port *egress = nullptr;
    Ipv4 nextHop;
    if(!ResolveNextHop(conn.remoteIp, egress, nextHop))
        return;

    std::vector<uint8_t> bytes = seg.ToBytes(conn.localIp, conn.remoteIp);
    IpPacket pkt(conn.localIp, conn.remoteIp, IpPacket::kTcp, bytes);

    Mac dstMac;
    if(arp.Lookup(nextHop, dstMac))
    {
        egress->Send(std::make_shared<const EthernetFrame>(
            dstMac, egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
        return;
    }

    bool alreadyPending = false;
    for(const PendingPing &pp : pendingPings)
        if(pp.nextHop == nextHop) { alreadyPending = true; break; }

    if(pendingPings.size() < kMaxPending)
        pendingPings.push_back(PendingPing{ egress, nextHop, pkt, 0 });
    else
        ++droppedPending;

    if(!alreadyPending)
        arp.SendArpRequest(nextHop, egress);
}

bool EndDevice::HandleTcpStack(Port *port, const IpPacket &pkt)
{
    if(!port) return false;

    TcpSegment raw;
    if(!TcpSegment::TryFromBytes(pkt.payload, raw))
        return false;

    TcpConnection *conn = FindTcpConn(raw.dstPort, pkt.srcIp, raw.srcPort);
    bool listening = !conn && tcpListenEnabled && raw.dstPort == tcpListenPort &&
                     (raw.flags & TcpSegment::kSyn) && !(raw.flags & TcpSegment::kAck);

    if(!conn && !listening)
        return false;

    TcpSegment seg;
    if(!TcpSegment::TryFromBytes(pkt.payload, seg, pkt.srcIp, pkt.dstIp))
        return true;

    if(conn)
    {
        conn->OnSegment(seg, pkt.srcIp);
        return true;
    }

    tcpConns.emplace_back();
    TcpConnection &c = tcpConns.back();
    TcpConnection *cp = &c;
    c.SetScheduler(scheduler);
    c.out = [this, cp](const TcpSegment &s) { SendTcpSegment(*cp, s); };
    c.onData = [cp](const std::vector<uint8_t> &data) { cp->SendData(data); };
    c.Listen(port->ip, tcpListenPort);
    c.OnSegment(seg, pkt.srcIp);
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

    tcpConns.emplace_back();
    TcpConnection &c = tcpConns.back();
    TcpConnection *cp = &c;
    c.SetScheduler(scheduler);
    c.out = [this, cp](const TcpSegment &s) { SendTcpSegment(*cp, s); };
    c.onData = [targetIp, dstPort](const std::vector<uint8_t> &data) {
        std::string txt(data.begin(), data.end());
        std::cout << "tcp reply from " << targetIp.ToString() << ":" << dstPort
                  << " \"" << txt << "\"\n";
    };
    c.onConnected = [cp, text]() {
        std::vector<uint8_t> d(text.begin(), text.end());
        cp->SendData(d);
    };

    uint16_t localPort = nextTcpLocalPort++;
    c.OpenActive(egress->ip, localPort, targetIp, dstPort, 1000 + localPort);
    std::cout << "tcp: connecting to " << targetIp.ToString()
              << ":" << dstPort << "\n";
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

    Ipv4 src = (msg.op == DhcpMessage::BootRequest) ? Ipv4::Any() : egress->ip;
    IpPacket pkt(src, Ipv4::Broadcast(), IpPacket::kUdp, d.ToBytes());
    egress->Send(std::make_shared<const EthernetFrame>(
        Mac::Broadcast(), egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
}

void EndDevice::StartDhcpClient(Port *p)
{
    if(!p)
        return;

    dhcpClientActive = true;
    dhcpState = 1;
    dhcpClientPort = p;
    dhcpXid = nextDhcpXid++;

    DhcpMessage m;
    m.op = DhcpMessage::BootRequest;
    m.xid = dhcpXid;
    m.flags = 0x8000;
    m.chaddr = p->mac;
    m.type = DhcpMessage::Discover;
    SendDhcpPacket(p, m);
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
        if(m.type == DhcpMessage::Discover)
        {
            Ipv4 ip;
            auto it = dhcpLeases.find(client);
            if(it != dhcpLeases.end())
            {
                ip = it->second;
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
                        if(kv.second == cand) { used = true; break; }
                    if(!used)
                        for(Port *p : portList)
                            if(p->hasIp && p->ip == cand) { used = true; break; }
                    if(used)
                        continue;
                    dhcpLeases[client] = cand;
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
            r.leaseTime = 3600;
            SendDhcpPacket(port, r);
        }
        else if(m.type == DhcpMessage::Request)
        {
            auto it = dhcpLeases.find(client);
            if(it == dhcpLeases.end())
                return;

            bool ok = !m.hasRequested || m.requestedIp == it->second;

            DhcpMessage r;
            r.op = DhcpMessage::BootReply;
            r.xid = m.xid;
            r.flags = m.flags;
            r.chaddr = client;
            r.type = ok ? DhcpMessage::Ack : DhcpMessage::Nak;
            r.hasServerId = true;
            r.serverId = port->ip;
            if(ok)
            {
                r.yiaddr = it->second;
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
                r.leaseTime = 3600;
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

        if(m.type == DhcpMessage::Ack && dhcpState == 2)
        {
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
            {
                dnsServerIp = m.dns;
                hasDnsServer = true;
            }

            dhcpState = 3;
            std::cout << "dhcp: leased " << m.yiaddr.ToString()
                      << "/" << int(prefix);
            if(m.hasRouter)
                std::cout << " gw " << m.router.ToString();
            if(m.hasDns)
                std::cout << " dns " << m.dns.ToString();
            std::cout << "\n";
            return;
        }

        if(m.type == DhcpMessage::Nak)
        {
            dhcpState = 0;
            dhcpClientActive = false;
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
    dnsRecords[key] = ip;
}

void EndDevice::DnsQuery(const Ipv4 &server, const std::string &name)
{
    DnsMessage q;
    q.id = uint16_t(nextDnsId++);
    q.flags = 0x0100;

    std::string key;
    key.reserve(name.size());
    for(char c : name)
        key.push_back(char(std::tolower(static_cast<unsigned char>(c))));
    q.questions.push_back(DnsQuestion{ key, 1, 1 });

    std::vector<uint8_t> bytes = q.ToBytes();
    if(bytes.empty())
        return;

    dnsClientPort = nextDnsClientPort++;
    dnsQueryId = q.id;
    dnsQueryName = key;

    std::string payload(bytes.begin(), bytes.end());
    SendUdp(server, 53, payload, dnsClientPort);
}

void EndDevice::HandleDns(Port *, const IpPacket &pkt, const UdpDatagram &dgram)
{
    DnsMessage m;
    if(!DnsMessage::TryFromBytes(dgram.payload, m))
        return;

    if(dgram.dstPort == 53 && dnsServerEnabled)
    {
        if(m.IsResponse() || m.questions.empty())
            return;

        DnsMessage r;
        r.id = m.id;
        r.flags = 0x8180;
        r.questions = m.questions;

        std::string key;
        for(char c : m.questions[0].name)
            key.push_back(char(std::tolower(static_cast<unsigned char>(c))));

        auto it = dnsRecords.find(key);
        if(m.questions[0].qtype == 1 && it != dnsRecords.end())
        {
            DnsAnswer a;
            a.name = m.questions[0].name;
            a.type = 1;
            a.cls = 1;
            a.ttl = 60;
            a.ip = it->second;
            r.answers.push_back(a);
        }
        else
        {
            r.flags = 0x8183;
        }

        std::vector<uint8_t> bytes = r.ToBytes();
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

        if(m.Rcode() == 0 && !m.answers.empty())
            std::cout << "dns: " << dnsQueryName << " -> "
                      << m.answers[0].ip.ToString() << "\n";
        else
            std::cout << "dns: " << dnsQueryName << " -> NXDOMAIN\n";
        dnsClientPort = 0;
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

    bool alreadyPending = false;
    for (const PendingPing &pp : pendingPings)
        if (pp.nextHop == nextHop) { alreadyPending = true; break; }

    if (pendingPings.size() < kMaxPending)
        pendingPings.push_back(PendingPing{ egress, nextHop, pkt, 0 });
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
                        uint16_t srcPort)
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

    Mac dstMac;
    if (arp.Lookup(nextHop, dstMac))
    {
        egress->Send(std::make_shared<const EthernetFrame>(
            dstMac, egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
    }
    else
    {
        bool alreadyPending = false;
        for (const PendingPing &pp : pendingPings)
            if (pp.nextHop == nextHop) { alreadyPending = true; break; }

        if (pendingPings.size() < kMaxPending)
            pendingPings.push_back(PendingPing{ egress, nextHop, pkt, 0 });
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
            it = pendingPings.erase(it);
        }
        else
        {
            ++it;
        }
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
            if (p->seq == seq) p = pendingPings.erase(p);
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
            p = pendingPings.erase(p);
        else
            ++p;
    }
}
