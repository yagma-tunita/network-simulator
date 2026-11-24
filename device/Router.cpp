#include "Router.hpp"
#include "Port.hpp"
#include "../core/IcmpMessage.hpp"
#include "../core/UdpDatagram.hpp"
#include "../core/TcpSegment.hpp"
#include "../core/RipMessage.hpp"
#include "../engine/Clock.hpp"
#include "../engine/Scheduler.hpp"
#include "../engine/Event.hpp"
#include <memory>
#include <algorithm>
#include <cstddef>
#include <vector>
#include <set>
#include <tuple>

namespace
{
    struct RipEvent : Event
    {
        Router *router;
        uint64_t gen;

        RipEvent(Router *r, uint64_t g) : router(r), gen(g) {}

        void Execute(Engine &) override { router->RipTick(gen); }
        const char *Name() const override { return "rip-tick"; }
    };


    uint8_t PrefixFromMask(const Ipv4 &mask)
    {
        uint32_t v = mask.value;
        uint8_t n = 0;
        while(n < 32 && (v & 0x80000000u))
        {
            ++n;
            v <<= 1;
        }
        return n;
    }
}

Route::Route(const Ipv4Subnet &dst, const Ipv4 &nextHop, bool direct)
    : dst(dst), nextHop(nextHop), direct(direct)
{}

void Router::AddPort(Port *p)
{
    if(!p) return;

    Device::AddPort(p);
    if(p->hasIp)
        AddRoute(p->subnet, Ipv4::Any(), true);
}

void Router::RebuildConnected()
{
    routeTable.erase(std::remove_if(routeTable.begin(), routeTable.end(),
                     [](const Route &r) { return r.direct || r.dynamic; }),
                     routeTable.end());
    for(Port *p : portList)
        if(p->hasIp) AddRoute(p->subnet, Ipv4::Any(), true);
}

void Router::SetClock(Clock *c)
{
    Device::SetClock(c);
    arp.SetClock(c);
}

bool Router::IsMyIp(Ipv4 ip) const
{
    for (const Port *p : portList)
    {
        if (p->hasIp && p->ip == ip)
            return true;
    }
    return false;
}

void Router::AddRoute(const Ipv4Subnet &dst, const Ipv4 &nextHop, bool direct)
{
    routeTable.push_back(Route(dst, nextHop, direct));
}

void Router::AddRoute(const Route &r)
{
    routeTable.push_back(r);
}

const Route *Router::FindRoute(const Ipv4 &dstip) const
{
    const Route *best = nullptr;

    for (const Route &r : routeTable)
    {
        if (r.dst.Contains(dstip))
        {
            if (!best || r.dst.prefix > best->dst.prefix ||
                (r.dst.prefix == best->dst.prefix && r.metric < best->metric))
                best = &r;
        }
    }

    return best;
}

Port *Router::PortForNextHop(const Ipv4 &ip)
{
    for (Port *p : portList)
    {
        if (p->hasIp && p->subnet.Contains(ip))
            return p;
    }
    return nullptr;
}

void Router::AddAcl(bool inbound, bool permit, const Ipv4Subnet &src,
                    const Ipv4Subnet &dst, uint8_t proto)
{
    AclRule r;
    r.permit = permit;
    r.src = src;
    r.dst = dst;
    r.proto = proto;
    (inbound ? aclIn : aclOut).push_back(r);
}

bool Router::AclAllows(const std::vector<AclRule> &rules, const IpPacket &pkt) const
{
    for(const AclRule &r : rules)
    {
        if(r.src.Contains(pkt.srcIp) && r.dst.Contains(pkt.dstIp) &&
           (r.proto == 0 || r.proto == pkt.protocol))
            return r.permit;
    }
    return true;
}

void Router::SetNat(bool on, Port *inside, Port *outside)
{
    natInside = inside;
    natOutside = outside;
    natEnabled = on && inside && outside && inside != outside;
    natTable.clear();
}

void Router::AddNatForward(uint8_t proto, uint16_t publicPort,
                           const Ipv4 &insideIp, uint16_t insidePort)
{
    for(NatForward &f : natForwards)
    {
        if(f.proto == proto && f.publicPort == publicPort)
        {
            f.insideIp = insideIp;
            f.insidePort = insidePort;
            return;
        }
    }
    if(natForwards.size() < kMaxNat)
        natForwards.push_back(NatForward{ proto, publicPort, insideIp, insidePort });
}

uint16_t Router::AllocNatPort(uint8_t proto, const Ipv4 &outsideIp)
{
    for(std::size_t i = 0; i < 65536; ++i)
    {
        uint16_t p = nextNatPort++;
        if(p == 0)
            continue;
        bool used = false;
        for(const NatTranslation &t : natTable)
            if(t.proto == proto && t.outsideIp == outsideIp && t.outsidePort == p)
            {
                used = true;
                break;
            }
        for(const NatForward &f : natForwards)
            if(f.proto == proto && f.publicPort == p)
            {
                used = true;
                break;
            }
        if(!used)
            return p;
    }
    return nextNatPort++;
}

bool Router::ApplyNatIngress(Port *ingress, IpPacket &pkt)
{
    if(!natEnabled || !natOutside || ingress != natOutside)
        return false;

    uint8_t proto = pkt.protocol;
    uint16_t dport = 0;
    bool hasPort = false;

    UdpDatagram udp;
    TcpSegment tcp;
    IcmpMessage icmp;
    bool haveUdp = false;
    bool haveTcp = false;
    bool haveIcmp = false;

    if(proto == IpPacket::kUdp && UdpDatagram::TryFromBytes(pkt.payload, udp))
    {
        dport = udp.dstPort;
        hasPort = true;
        haveUdp = true;
    }
    else if(proto == IpPacket::kTcp && TcpSegment::TryFromBytes(pkt.payload, tcp))
    {
        dport = tcp.dstPort;
        hasPort = true;
        haveTcp = true;
    }
    else if(proto == IpPacket::kIcmp && IcmpMessage::TryFromBytes(pkt.payload, icmp))
    {
        if(icmp.type == IcmpMessage::kEchoReply)
        {
            dport = icmp.id;
            hasPort = true;
            haveIcmp = true;
        }
    }

    if(!hasPort)
        return false;

    const NatTranslation *tr = nullptr;
    for(const NatTranslation &t : natTable)
    {
        if(t.proto == proto && t.outsideIp == pkt.dstIp && t.outsidePort == dport)
        {
            tr = &t;
            break;
        }
    }

    if(!tr)
    {
        if(!(haveUdp || haveTcp) || !(pkt.dstIp == ingress->ip))
            return false;

        for(const NatForward &f : natForwards)
        {
            if(f.proto != proto || f.publicPort != dport)
                continue;

            for(const NatTranslation &t : natTable)
                if(t.proto == proto && t.insideIp == f.insideIp &&
                   t.insidePort == f.insidePort)
                {
                    tr = &t;
                    break;
                }

            if(!tr)
            {
                if(natTable.size() >= kMaxNat)
                    natTable.erase(natTable.begin());
                natTable.push_back(NatTranslation{
                    proto, f.insideIp, f.insidePort, ingress->ip, f.publicPort });
                tr = &natTable.back();
            }
            break;
        }
    }

    if(!tr)
        return false;

    Ipv4 newDst = tr->insideIp;
    uint16_t newPort = tr->insidePort;

    if(haveUdp)
    {
        udp.dstPort = newPort;
        pkt.payload = udp.ToBytes();
    }
    else if(haveTcp)
    {
        tcp.dstPort = newPort;
        pkt.payload = tcp.ToBytes(pkt.srcIp, newDst);
    }
    else if(haveIcmp)
    {
        icmp.id = newPort;
        pkt.payload = icmp.ToBytes();
    }

    pkt.dstIp = newDst;
    return true;
}

void Router::ApplyNatEgress(Port *ingress, Port *egress, IpPacket &pkt)
{
    if(!natEnabled || !natInside || !natOutside)
        return;
    if(ingress != natInside || egress != natOutside)
        return;

    uint8_t proto = pkt.protocol;
    uint16_t sport = 0;
    bool hasPort = false;

    UdpDatagram udp;
    TcpSegment tcp;
    IcmpMessage icmp;
    bool haveUdp = false;
    bool haveTcp = false;
    bool haveIcmp = false;

    if(proto == IpPacket::kUdp && UdpDatagram::TryFromBytes(pkt.payload, udp))
    {
        sport = udp.srcPort;
        hasPort = true;
        haveUdp = true;
    }
    else if(proto == IpPacket::kTcp && TcpSegment::TryFromBytes(pkt.payload, tcp))
    {
        sport = tcp.srcPort;
        hasPort = true;
        haveTcp = true;
    }
    else if(proto == IpPacket::kIcmp && IcmpMessage::TryFromBytes(pkt.payload, icmp))
    {
        if(icmp.type == IcmpMessage::kEchoRequest)
        {
            sport = icmp.id;
            hasPort = true;
            haveIcmp = true;
        }
    }

    if(!hasPort)
        return;

    Ipv4 outsideIp = egress->ip;
    uint16_t outsidePort = 0;
    bool found = false;

    for(const NatTranslation &t : natTable)
    {
        if(t.proto == proto && t.insideIp == pkt.srcIp &&
           t.insidePort == sport && t.outsideIp == outsideIp)
        {
            outsidePort = t.outsidePort;
            found = true;
            break;
        }
    }

    if(!found)
    {
        outsidePort = AllocNatPort(proto, outsideIp);
        if(natTable.size() >= kMaxNat)
            natTable.erase(natTable.begin());
        natTable.push_back(NatTranslation{
            proto, pkt.srcIp, sport, outsideIp, outsidePort });
    }

    if(haveUdp)
    {
        udp.srcPort = outsidePort;
        pkt.payload = udp.ToBytes();
    }
    else if(haveTcp)
    {
        tcp.srcPort = outsidePort;
        pkt.payload = tcp.ToBytes(outsideIp, pkt.dstIp);
    }
    else if(haveIcmp)
    {
        icmp.id = outsidePort;
        pkt.payload = icmp.ToBytes();
    }

    pkt.srcIp = outsideIp;
}

void Router::SetRip(bool on)
{
    ++ripGen;
    ripEnabled = on;

    if(!on)
    {
        routeTable.erase(std::remove_if(routeTable.begin(), routeTable.end(),
                         [](const Route &r) { return r.dynamic && !r.ospf; }),
                         routeTable.end());
        return;
    }

    uint64_t now = clock ? clock->Now() : 0;
    ripNextUpdate = now + kRipInterval;
    if(scheduler)
        scheduler->ScheduleAfter(kRipInterval,
            std::make_unique<RipEvent>(this, ripGen));
    SendRipUpdates();
}

void Router::RipTick(uint64_t gen)
{
    if(!ripEnabled || gen != ripGen)
        return;

    uint64_t now = clock ? clock->Now() : 0;

    routeTable.erase(std::remove_if(routeTable.begin(), routeTable.end(),
                     [now](const Route &r) {
                         return r.dynamic && !r.ospf && now >= r.expiresAt;
                     }),
                     routeTable.end());

    SendRipUpdates();

    ripNextUpdate = now + kRipInterval;
    if(scheduler)
        scheduler->ScheduleAfter(kRipInterval,
            std::make_unique<RipEvent>(this, ripGen));
}

void Router::SendRipUpdates()
{
    for(Port *p : portList)
        if(p->hasIp)
            SendRipOnPort(p);
}

void Router::SendRipOnPort(Port *p)
{
    if(!p || !p->hasIp)
        return;

    RipMessage m;
    m.command = RipMessage::kResponse;

    for(const Route &r : routeTable)
    {
        if(r.dst.prefix == 0)
            continue;
        if(r.ospf)
            continue;
        if(r.dynamic && r.learnedFromPort == p)
            continue;

        uint16_t metric = 1;
        if(r.dynamic)
            metric = r.metric;
        else if(!r.direct)
            metric = 1;

        if(metric >= kRipInfinity)
            continue;

        m.entries.push_back(RipEntry{ r.dst.network, r.dst.Mask(), metric });
    }

    UdpDatagram d;
    d.srcPort = 520;
    d.dstPort = 520;
    d.payload = m.ToBytes();

    IpPacket pkt(p->ip, Ipv4::Broadcast(), IpPacket::kUdp, d.ToBytes());
    pkt.ttl = 1;

    p->Send(std::make_shared<const EthernetFrame>(
        Mac::Broadcast(), p->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
}

void Router::HandleRip(Port *ingress, const IpPacket &pkt, const UdpDatagram &dgram)
{
    if(!ingress)
        return;

    RipMessage m;
    if(!RipMessage::TryFromBytes(dgram.payload, m))
        return;

    if(m.command == RipMessage::kRequest)
    {
        SendRipOnPort(ingress);
        return;
    }
    if(m.command != RipMessage::kResponse)
        return;

    uint64_t now = clock ? clock->Now() : 0;

    for(const RipEntry &e : m.entries)
    {
        Ipv4Subnet dst(e.dst & e.mask, PrefixFromMask(e.mask));
        if(dst.prefix == 0)
            continue;

        uint32_t metric = uint32_t(e.metric) + 1;

        Route *dyn = nullptr;
        bool blocked = false;

        for(Route &r : routeTable)
        {
            if(!(r.dst == dst))
                continue;
            if(r.direct || r.ospf || !r.dynamic)
            {
                blocked = true;
                break;
            }
            dyn = &r;
        }

        if(blocked)
            continue;

        if(metric >= kRipInfinity)
        {
            if(dyn)
                routeTable.erase(std::remove_if(routeTable.begin(), routeTable.end(),
                                 [&dst](const Route &r) {
                                     return r.dynamic && !r.ospf && r.dst == dst;
                                 }),
                                 routeTable.end());
            continue;
        }

        if(dyn)
        {
            if(dyn->learnedFromPort == ingress || metric < dyn->metric)
            {
                dyn->metric = uint16_t(metric);
                dyn->nextHop = pkt.srcIp;
                dyn->learnedFromPort = ingress;
                dyn->expiresAt = now + kRipTimeout;
            }
        }
        else
        {
            routeTable.push_back(Route(dst, pkt.srcIp, false));
            Route &nr = routeTable.back();
            nr.metric = uint16_t(metric);
            nr.dynamic = true;
            nr.learnedFromPort = ingress;
            nr.expiresAt = now + kRipTimeout;
        }
    }
}

void Router::OnFrame(Port *port, FramePtr frame)
{
    if(!port) return;

    if((port->mac != frame->dst) && !frame->IsBroadcast() && !frame->dst.IsGroup()) return;

    if(frame->type == EthernetFrame::kARP)
    {
        arp.HandleArp(port, *frame);
        FlushPending();
        return;
    }

    if(frame->type != EthernetFrame::kIPv4) return;

    IpPacket pkt;
    if(!IpPacket::TryFromBytes(frame->payload, pkt)) return;

    if(pkt.protocol == IpPacket::kUdp)
    {
        UdpDatagram d;
        if(UdpDatagram::TryFromBytes(pkt.payload, d))
        {
            if(d.dstPort == 520)
            {
                if(ripEnabled)
                    HandleRip(port, pkt, d);
                return;
            }
            if(d.dstPort == 67 || d.dstPort == 68)
            {
                HandleDhcpRelay(port, pkt, d);
                return;
            }
        }
    }

    if(pkt.protocol == IpPacket::kOspf)
    {
        if(ospfEnabled)
            HandleOspf(port, pkt, frame->src);
        return;
    }

    if(!AclAllows(aclIn, pkt))
    {
        ++port->drop;
        return;
    }

    ApplyNatIngress(port, pkt);

    if(IsMyIp(pkt.dstIp))
    {
        Port *me = nullptr;
        for(Port *p : portList)
            if(p->hasIp && p->ip == pkt.dstIp) { me = p; break; }

        if(me && pkt.protocol == IpPacket::kIcmp)
        {
            IcmpMessage req;
            if(IcmpMessage::TryFromBytes(pkt.payload, req) &&
               req.type == IcmpMessage::kEchoRequest)
            {
                IcmpMessage rep = req;
                rep.type = IcmpMessage::kEchoReply;
                IpPacket out(me->ip, pkt.srcIp, IpPacket::kIcmp, rep.ToBytes());
                port->Send(std::make_shared<const EthernetFrame>(
                    frame->src, port->mac, EthernetFrame::kIPv4, out.ToBytes()));
            }
        }
        return;
    }

    if(pkt.ttl <= 1)
    {
        ++port->drop;
        SendIcmpError(port, *frame, pkt, IcmpMessage::kTimeExceeded);
        return;
    }
    pkt.DecTtl();

    const Route* r = FindRoute(pkt.dstIp);
    if(!r)
    {
        ++port->drop;
        SendIcmpError(port, *frame, pkt, IcmpMessage::kDestUnreachable);
        return;
    }

    Ipv4 nextIp = r->direct ? pkt.dstIp : r->nextHop;

    Port* egress = PortForNextHop(nextIp);
    if(!egress)
    {
        ++port->drop;
        SendIcmpError(port, *frame, pkt, IcmpMessage::kDestUnreachable);
        return;
    }

    if(!AclAllows(aclOut, pkt))
    {
        ++port->drop;
        return;
    }

    ApplyNatEgress(port, egress, pkt);

    Mac nextMac;
    if(!arp.Lookup(nextIp, nextMac))
    {
        uint64_t now = clock ? clock->Now() : 0;
        std::vector<Pending> &q = pending[nextIp];
        if(q.size() >= kMaxPendingPerDest)
        {
            ++droppedPending;
            ++port->drop;
            return;
        }
        q.push_back(Pending{egress, pkt, now});
        arp.SendArpRequest(nextIp, egress);
        return;
    }

    egress->Send(std::make_shared<const EthernetFrame>(
        nextMac, egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
}

void Router::SendIcmpError(Port *ingress, const EthernetFrame &origin,
                           const IpPacket &pkt, uint8_t type)
{
    if(!ingress || !ingress->hasIp) return;

    IcmpMessage err;
    err.type = type;
    err.code = 0;

    std::vector<uint8_t> orig = pkt.ToBytes();
    if(orig.size() > 28) orig.resize(28);
    err.payload = orig;

    IpPacket out(ingress->ip, pkt.srcIp, IpPacket::kIcmp, err.ToBytes());
    ingress->Send(std::make_shared<const EthernetFrame>(
        origin.src, ingress->mac, EthernetFrame::kIPv4, out.ToBytes()));
}

void Router::AgeOutPending(uint64_t now)
{
    for(auto it = pending.begin(); it != pending.end(); )
    {
        std::vector<Pending> &q = it->second;
        std::size_t before = q.size();
        q.erase(std::remove_if(q.begin(), q.end(),
                [now](const Pending &p){ return now - p.enqueuedAt > kPendingTimeout; }),
                q.end());
        droppedPending += (before - q.size());
        if(q.empty()) it = pending.erase(it);
        else ++it;
    }
}

void Router::FlushPending()
{
    AgeOutPending(clock ? clock->Now() : 0);

    for(auto it = pending.begin(); it != pending.end(); )
    {
        const Ipv4& ip = it->first;
        std::vector<Pending>& list = it->second;

        Mac mac;
        if(arp.Lookup(ip, mac))
        {
            for(const Pending& pd : list)
                pd.egress->Send(std::make_shared<const EthernetFrame>(
                    mac, pd.egress->mac, EthernetFrame::kIPv4, pd.pkt.ToBytes()));
            it = pending.erase(it);
        }
        else
            ++it;
    }
}
