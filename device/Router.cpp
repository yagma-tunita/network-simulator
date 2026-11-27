#include "Router.hpp"
#include "Port.hpp"
#include "../link/Link.hpp"
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

    Ipv6 SolicitedNode6(const Ipv6 &target)
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

    Mac SolicitedMac6(const Ipv6 &target)
    {
        return Mac(0x33, 0x33, 0xFF, target.bytes[13],
                   target.bytes[14], target.bytes[15]);
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
    if(p->hasIp6)
        AddRoute6(Ipv6Subnet(p->ip6, p->prefix6), Ipv6(), true, p);
}

void Router::RebuildConnected()
{
    routeTable.erase(std::remove_if(routeTable.begin(), routeTable.end(),
                     [](const Route &r) { return r.direct || r.dynamic; }),
                     routeTable.end());
    MarkRoutesDirty();
    for(Port *p : portList)
        if(p->hasIp) AddRoute(p->subnet, Ipv4::Any(), true);
    RebuildConnected6();
}

void Router::RebuildConnected6()
{
    route6.erase(std::remove_if(route6.begin(), route6.end(),
                 [](const Ipv6Route &r) { return r.direct; }),
                 route6.end());
    for(Port *p : portList)
        if(p->hasIp6)
            route6.push_back(Ipv6Route(
                Ipv6Subnet(p->ip6, p->prefix6), Ipv6(), true, p));
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

bool Router::IsMyIp6(const Ipv6 &ip) const
{
    for(const Port *p : portList)
        if(p->hasIp6 && p->ip6 == ip)
            return true;
    return false;
}

void Router::AddRoute6(const Ipv6Subnet &dst, const Ipv6 &nextHop, bool direct,
                       Port *p)
{
    route6.push_back(Ipv6Route(dst, nextHop, direct, p));
}

const Ipv6Route* Router::FindRoute6(const Ipv6 &dstip) const
{
    const Ipv6Route *best = nullptr;
    for(const Ipv6Route &r : route6)
        if(r.dst.Contains(dstip) && (!best || r.dst.prefix > best->dst.prefix))
            best = &r;
    return best;
}

Port* Router::PortForIpv6NextHop(const Ipv6 &ip) const
{
    for(Port *p : portList)
        if(p->hasIp6 && Ipv6Subnet(p->ip6, p->prefix6).Contains(ip))
            return p;
    return nullptr;
}

void Router::AddRoute(const Ipv4Subnet &dst, const Ipv4 &nextHop, bool direct)
{
    routeTable.push_back(Route(dst, nextHop, direct));
    MarkRoutesDirty();
    if(ospfEnabled && (ospfRedistConnected || ospfRedistStatic))
        OspfOriginateExternals();
}

void Router::AddRoute(const Route &r)
{
    routeTable.push_back(r);
    MarkRoutesDirty();
    if(ospfEnabled && (ospfRedistConnected || ospfRedistStatic))
        OspfOriginateExternals();
}

void Router::RebuildRouteTrie() const
{
    routeTrie.clear();
    routeTrie.push_back(RouteTrieNode{});
    for(std::size_t i = 0; i < routeTable.size(); ++i)
    {
        const Route &r = routeTable[i];
        int node = 0;
        uint32_t net = r.dst.network.value;
        for(int bit = 31; bit >= 32 - int(r.dst.prefix); --bit)
        {
            int b = int((net >> bit) & 1u);
            int next = routeTrie[node].child[b];
            if(next < 0)
            {
                next = int(routeTrie.size());
                routeTrie[node].child[b] = next;
                routeTrie.push_back(RouteTrieNode{});
            }
            node = next;
        }
        int &slot = routeTrie[node].route;
        if(slot < 0 || r.metric < routeTable[slot].metric)
            slot = int(i);
    }
    routeTrieDirty = false;
}

const Route *Router::FindRoute(const Ipv4 &dstip) const
{
    if(routeTrieDirty)
        RebuildRouteTrie();

    int node = 0;
    int best = routeTrie[0].route;
    uint32_t v = dstip.value;
    for(int bit = 31; bit >= 0; --bit)
    {
        int b = int((v >> bit) & 1u);
        node = routeTrie[node].child[b];
        if(node < 0)
            break;
        if(routeTrie[node].route >= 0)
            best = routeTrie[node].route;
    }
    if(best < 0 || std::size_t(best) >= routeTable.size())
        return nullptr;
    return &routeTable[std::size_t(best)];
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

void Router::AddAcl6(bool inbound, bool permit, const Ipv6Subnet &src,
                     const Ipv6Subnet &dst, uint8_t proto)
{
    Acl6Rule r;
    r.permit = permit;
    r.src = src;
    r.dst = dst;
    r.proto = proto;
    (inbound ? acl6In : acl6Out).push_back(r);
}

bool Router::Acl6Allows(const std::vector<Acl6Rule> &rules,
                        const Ipv6Packet &pkt) const
{
    for(const Acl6Rule &r : rules)
    {
        if(r.src.Contains(pkt.srcIp) && r.dst.Contains(pkt.dstIp) &&
           (r.proto == 0 || r.proto == pkt.nextHeader))
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
        MarkRoutesDirty();
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
    MarkRoutesDirty();

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
    MarkRoutesDirty();
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

    if(frame->type == EthernetFrame::kIPv6)
    {
        HandleIpv6(port, frame);
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
        port->CountDrop(DropReason::Acl);
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
        port->CountDrop(DropReason::Ttl);
        SendIcmpError(port, *frame, pkt, IcmpMessage::kTimeExceeded);
        return;
    }
    pkt.DecTtl();

    const Route* r = FindRoute(pkt.dstIp);
    if(!r)
    {
        port->CountDrop(DropReason::NoRoute);
        SendIcmpError(port, *frame, pkt, IcmpMessage::kDestUnreachable);
        return;
    }

    Ipv4 nextIp = r->direct ? pkt.dstIp : r->nextHop;

    Port* egress = PortForNextHop(nextIp);
    if(!egress)
    {
        port->CountDrop(DropReason::NoEgress);
        SendIcmpError(port, *frame, pkt, IcmpMessage::kDestUnreachable);
        return;
    }

    if(!AclAllows(aclOut, pkt))
    {
        port->CountDrop(DropReason::Acl);
        return;
    }

    ApplyNatEgress(port, egress, pkt);

    auto eit = ecnMark.find(egress);
    if(eit != ecnMark.end() && eit->second && pkt.ecn == 2)
        pkt.ecn = 3;

    if(pkt.dontFragment && egress->link &&
       pkt.payload.size() + IpPacket::kHeaderSize > egress->link->mtu)
    {
        port->CountDrop(DropReason::Mtu);
        SendIcmpError(port, *frame, pkt, IcmpMessage::kDestUnreachable,
                      IcmpMessage::kFragNeeded, egress->link->mtu,
                      egress->ip);
        return;
    }

    Mac nextMac;
    if(!arp.Lookup(nextIp, nextMac))
    {
        uint64_t now = clock ? clock->Now() : 0;
        std::vector<Pending> &q = pending[nextIp];
        if(q.size() >= kMaxPendingPerDest)
        {
            ++droppedPending;
            port->CountDrop(DropReason::ArpPending);
            return;
        }
        q.push_back(Pending{egress, pkt, now});
        arp.SendArpRequest(nextIp, egress);
        return;
    }

    egress->Send(std::make_shared<const EthernetFrame>(
        nextMac, egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
}

void Router::SendIcmp6(Port *egress, const Ipv6 &src, const Ipv6 &dst,
                       const Mac &dstMac, const Icmpv6Message &msg)
{
    if(!egress)
        return;
    Ipv6Packet pkt(src, dst, Icmpv6Message::kNextHeader,
                   msg.ToBytes(src, dst));
    if(msg.type == Icmpv6Message::kNeighborSolicit ||
       msg.type == Icmpv6Message::kNeighborAdvert)
        pkt.hopLimit = 255;
    egress->Send(std::make_shared<const EthernetFrame>(
        dstMac, egress->mac, EthernetFrame::kIPv6, pkt.ToBytes()));
}

void Router::SendNs6(Port *egress, const Ipv6 &target)
{
    if(!egress || !egress->hasIp6)
        return;
    Icmpv6Message ns;
    ns.type = Icmpv6Message::kNeighborSolicit;
    ns.target = target;
    ns.options = NdpLinkLayerOption(1, egress->mac);
    SendIcmp6(egress, egress->ip6, SolicitedNode6(target),
              SolicitedMac6(target), ns);
}

void Router::SendIcmp6Error(Port *ingress, const EthernetFrame &origin,
                            const Ipv6Packet &pkt, uint8_t type, uint8_t code)
{
    if(!ingress || !ingress->hasIp6)
        return;
    Icmpv6Message err;
    err.type = type;
    err.code = code;
    std::vector<uint8_t> quoted = pkt.ToBytes();
    if(quoted.size() > 1280)
        quoted.resize(1280);
    err.payload = quoted;
    SendIcmp6(ingress, ingress->ip6, pkt.srcIp, origin.src, err);
}

void Router::FlushPending6(const Ipv6 &neighbor, const Mac &mac)
{
    auto it = pending6.find(neighbor);
    if(it == pending6.end())
        return;
    for(const Pending6 &p : it->second)
        p.egress->Send(std::make_shared<const EthernetFrame>(
            mac, p.egress->mac, EthernetFrame::kIPv6, p.pkt.ToBytes()));
    pending6.erase(it);
}

void Router::AgePending6(uint64_t now)
{
    for(auto it = pending6.begin(); it != pending6.end();)
    {
        std::vector<Pending6> &q = it->second;
        std::size_t before = q.size();
        q.erase(std::remove_if(q.begin(), q.end(),
                [now](const Pending6 &p) {
                    return now - p.enqueuedAt > kPendingTimeout;
                }), q.end());
        droppedPending6 += (before - q.size());
        if(q.empty()) it = pending6.erase(it);
        else ++it;
    }
}

void Router::HandleIpv6(Port *port, FramePtr frame)
{
    if(!port)
        return;
    AgePending6(clock ? clock->Now() : 0);

    Ipv6Packet pkt;
    if(!Ipv6Packet::TryFromBytes(frame->payload, pkt))
    {
        port->CountDrop(DropReason::Parse);
        return;
    }
    if(pkt.nextHeader != Icmpv6Message::kNextHeader)
        return;
    if(!Acl6Allows(acl6In, pkt))
    {
        port->CountDrop(DropReason::Acl);
        return;
    }

    Icmpv6Message msg;
    if(!Icmpv6Message::TryFromBytes(pkt.payload, pkt.srcIp, pkt.dstIp, msg))
        return;

    bool multicast = pkt.dstIp.bytes[0] == 0xFF;
    if(multicast || IsMyIp6(pkt.dstIp))
    {
        if(msg.type == Icmpv6Message::kNeighborSolicit)
        {
            Port *targetPort = nullptr;
            for(Port *p : portList)
                if(p->hasIp6 && p->ip6 == msg.target)
                {
                    targetPort = p;
                    break;
                }
            if(!targetPort)
                return;
            Icmpv6Message na;
            na.type = Icmpv6Message::kNeighborAdvert;
            na.ndFlags = 0x60000000u;
            na.target = msg.target;
            na.options = NdpLinkLayerOption(2, targetPort->mac);
            SendIcmp6(targetPort, msg.target, pkt.srcIp, frame->src, na);
            return;
        }
        if(msg.type == Icmpv6Message::kNeighborAdvert)
        {
            nd6Cache[msg.target] = frame->src;
            FlushPending6(msg.target, frame->src);
            return;
        }
        if(msg.type == Icmpv6Message::kEchoRequest)
        {
            Port *targetPort = nullptr;
            for(Port *p : portList)
                if(p->hasIp6 && p->ip6 == pkt.dstIp)
                {
                    targetPort = p;
                    break;
                }
            if(!targetPort)
                return;
            Icmpv6Message rep = msg;
            rep.type = Icmpv6Message::kEchoReply;
            SendIcmp6(targetPort, pkt.dstIp, pkt.srcIp, frame->src, rep);
        }
        return;
    }

    const Ipv6Route *r = FindRoute6(pkt.dstIp);
    if(!r)
    {
        port->CountDrop(DropReason::NoRoute);
        SendIcmp6Error(port, *frame, pkt, Icmpv6Message::kDestUnreachable, 0);
        return;
    }
    Ipv6 nextHop = r->direct ? pkt.dstIp : r->nextHop;
    Port *egress = r->port ? r->port : PortForIpv6NextHop(nextHop);
    if(!egress)
    {
        port->CountDrop(DropReason::NoEgress);
        SendIcmp6Error(port, *frame, pkt, Icmpv6Message::kDestUnreachable, 0);
        return;
    }
    if(!Acl6Allows(acl6Out, pkt))
    {
        port->CountDrop(DropReason::Acl);
        return;
    }
    if(pkt.hopLimit <= 1)
    {
        port->CountDrop(DropReason::Ttl);
        SendIcmp6Error(port, *frame, pkt, Icmpv6Message::kTimeExceeded, 0);
        return;
    }
    pkt.hopLimit--;

    auto cit = nd6Cache.find(nextHop);
    if(cit != nd6Cache.end())
    {
        egress->Send(std::make_shared<const EthernetFrame>(
            cit->second, egress->mac, EthernetFrame::kIPv6, pkt.ToBytes()));
        return;
    }

    std::vector<Pending6> &q = pending6[nextHop];
    if(q.size() >= kMaxPendingPerDest)
    {
        ++droppedPending6;
        port->CountDrop(DropReason::Resource);
        return;
    }
    q.push_back(Pending6{ egress, pkt, clock ? clock->Now() : 0 });
    SendNs6(egress, nextHop);
}

void Router::SendIcmpError(Port *ingress, const EthernetFrame &origin,
                           const IpPacket &pkt, uint8_t type,
                           uint8_t code, uint16_t mtu, Ipv4 source)
{
    if(!ingress || !ingress->hasIp) return;

    IcmpMessage err;
    err.type = type;
    err.code = code;
    err.nextHopMtu = mtu;

    std::vector<uint8_t> orig = pkt.ToBytes();
    if(orig.size() > 28) orig.resize(28);
    err.payload = orig;

    Ipv4 saddr = (source == Ipv4::Any()) ? ingress->ip : source;
    IpPacket out(saddr, pkt.srcIp, IpPacket::kIcmp, err.ToBytes());
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
