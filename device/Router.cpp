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


    struct OspfHelloEvent : Event
    {
        Router *router;
        uint64_t gen;

        OspfHelloEvent(Router *r, uint64_t g) : router(r), gen(g) {}

        void Execute(Engine &) override { router->OspfTick(gen); }
        const char *Name() const override { return "ospf-hello"; }
    };

    Ipv4 OspfAllSpf()
    {
        return Ipv4(224, 0, 0, 5);
    }

    Mac OspfAllSpfMac()
    {
        return Mac(0x01, 0x00, 0x5e, 0x00, 0x00, 0x05);
    }

    void FillOspfHeader(OspfPacket &p, const Router &r)
    {
        p.routerId = Ipv4(r.ospfRouterId);
        p.areaId = r.ospfAreaId;
        p.authType = r.ospfAuthType;
        for(std::size_t i = 0; i < 8; ++i)
            p.auth[i] = r.ospfPassword[i];
    }

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

uint32_t Router::ComputeOspfRouterId() const
{
    uint32_t id = 0;
    for(const Port *p : portList)
        if(p->hasIp && p->ip.value > id)
            id = p->ip.value;
    return id;
}

void Router::SetOspf(bool on)
{
    ++ospfGen;
    ospfEnabled = on;
    ospfIfaces.clear();

    if(!on)
        return;

    ospfRouterId = ComputeOspfRouterId();
    ospfAreaId = Ipv4::Any();
    uint64_t now = clock ? clock->Now() : 0;

    for(Port *p : portList)
    {
        if(!p->hasIp)
            continue;
        OspfInterface ifc;
        ifc.port = p;
        ifc.state = OspfIfWaiting;
        ifc.priority = 1;
        ifc.waitUntil = now + kOspfDeadInterval;
        ospfIfaces.push_back(ifc);
    }

    SendOspfHellos();

    ospfNextHello = now + kOspfHelloInterval;
    if(scheduler)
        scheduler->ScheduleAfter(kOspfHelloInterval,
            std::make_unique<OspfHelloEvent>(this, ospfGen));
}

void Router::OspfTick(uint64_t gen)
{
    if(!ospfEnabled || gen != ospfGen)
        return;

    uint64_t now = clock ? clock->Now() : 0;

    for(OspfInterface &ifc : ospfIfaces)
    {
        for(auto it = ifc.neighbors.begin(); it != ifc.neighbors.end(); )
        {
            if(now - it->second.lastHello > kOspfDeadInterval)
                it = ifc.neighbors.erase(it);
            else
                ++it;
        }

        if(ifc.state == OspfIfWaiting)
        {
            if(now >= ifc.waitUntil)
                OspfElect(ifc);
        }
        else
        {
            OspfElect(ifc);
        }

        for(auto &kv : ifc.neighbors)
            OspfMaybeAdjacency(ifc, kv.second);

        for(auto &kv : ifc.neighbors)
        {
            OspfNeighbor &n = kv.second;
            if(n.nextResend != 0 && now >= n.nextResend)
            {
                if(!n.retrans.empty())
                    OspfSendLsu(ifc, n, n.retrans);
                else if(n.state == OspfNbrExStart)
                    OspfSendDdInitial(ifc, n);
                else if(n.state == OspfNbrExchange)
                    OspfSendDdFull(ifc, n);
                else if(n.state == OspfNbrLoading)
                    OspfSendLsr(ifc, n);
                else if(n.state == OspfNbrFull)
                    OspfSendDdFull(ifc, n);
                else
                    n.nextResend = 0;
            }
        }

        SendOspfHello(ifc.port);
    }

    bool aged = false;
    for(auto it = ospfLsdb.begin(); it != ospfLsdb.end(); )
    {
        OspfLsa &lsa = it->second;
        if(lsa.header.age < 3600)
            lsa.header.age = uint16_t(lsa.header.age + kOspfHelloInterval);

        bool own = lsa.header.advRouter.value == ospfRouterId;
        if(own)
        {
            if(lsa.header.age >= 1800)
            {
                lsa.header.age = 0;
                OspfFlood(lsa, nullptr);
            }
        }
        else if(lsa.header.age >= 3600)
        {
            it = ospfLsdb.erase(it);
            aged = true;
            continue;
        }
        ++it;
    }
    if(aged)
        OspfSync();

    OspfConverge();

    ospfNextHello = now + kOspfHelloInterval;
    if(scheduler)
        scheduler->ScheduleAfter(kOspfHelloInterval,
            std::make_unique<OspfHelloEvent>(this, ospfGen));
}

void Router::SendOspfHellos()
{
    for(OspfInterface &ifc : ospfIfaces)
        SendOspfHello(ifc.port);
}

void Router::SendOspfHello(Port *p)
{
    if(!p || !p->hasIp)
        return;

    OspfInterface *ifc = nullptr;
    for(OspfInterface &i : ospfIfaces)
        if(i.port == p)
        {
            ifc = &i;
            break;
        }
    if(!ifc)
        return;

    OspfPacket pkt;
    pkt.type = OspfPacket::Hello;
    pkt.routerId = Ipv4(ospfRouterId);
    pkt.areaId = ospfAreaId;
    pkt.authType = ospfAuthType;
    for(std::size_t i = 0; i < 8; ++i)
        pkt.auth[i] = ospfPassword[i];

    pkt.helloMask = p->subnet.Mask();
    pkt.helloInterval = uint16_t(kOspfHelloInterval);
    pkt.helloOptions = 0x02;
    pkt.helloPriority = ifc->priority;
    pkt.deadInterval = uint32_t(kOspfDeadInterval);
    pkt.dr = ifc->dr;
    pkt.bdr = ifc->bdr;

    for(const auto &kv : ifc->neighbors)
        if(kv.second.state >= OspfNbrInit)
            pkt.neighbors.push_back(Ipv4(kv.first));

    SendOspfPacket(p, pkt, OspfAllSpf(), OspfAllSpfMac());
}

void Router::SendOspfPacket(Port *egress, const OspfPacket &pkt,
                            const Ipv4 &dstIp, const Mac &dstMac)
{
    if(!egress || !egress->hasIp)
        return;

    IpPacket ip(egress->ip, dstIp, IpPacket::kOspf, pkt.ToBytes());
    ip.ttl = 1;

    egress->Send(std::make_shared<const EthernetFrame>(
        dstMac, egress->mac, EthernetFrame::kIPv4, ip.ToBytes()));
}

void Router::HandleOspf(Port *ingress, const IpPacket &pkt, const Mac &srcMac)
{
    OspfPacket op;
    if(!OspfPacket::TryFromBytes(pkt.payload, op))
        return;
    if(op.routerId.value == 0 || op.routerId.value == ospfRouterId)
        return;
    if(!(op.areaId == ospfAreaId))
        return;
    if(op.authType != ospfAuthType)
        return;
    if(op.authType == OspfPacket::AuthSimple)
        for(std::size_t i = 0; i < 8; ++i)
            if(op.auth[i] != ospfPassword[i])
                return;

    if(op.type == OspfPacket::Hello)
        HandleOspfHello(ingress, op, srcMac, pkt.srcIp);
    else if(op.type == OspfPacket::DatabaseDescription)
        OspfHandleDd(ingress, op, srcMac, pkt.srcIp);
    else if(op.type == OspfPacket::LinkStateRequest)
        OspfHandleLsr(ingress, op, srcMac, pkt.srcIp);
    else if(op.type == OspfPacket::LinkStateUpdate)
        OspfHandleLsu(ingress, op, srcMac, pkt.srcIp);
    else if(op.type == OspfPacket::LinkStateAck)
        OspfHandleLsaAck(ingress, op);
}

void Router::HandleOspfHello(Port *ingress, const OspfPacket &pkt,
                             const Mac &srcMac, const Ipv4 &srcIp)
{
    OspfInterface *ifc = nullptr;
    for(OspfInterface &i : ospfIfaces)
        if(i.port == ingress)
        {
            ifc = &i;
            break;
        }
    if(!ifc)
        return;

    if(pkt.helloInterval != uint16_t(kOspfHelloInterval) ||
       pkt.deadInterval != uint32_t(kOspfDeadInterval))
        return;
    if(!(pkt.helloMask == ingress->subnet.Mask()))
        return;

    uint64_t now = clock ? clock->Now() : 0;
    auto it = ifc->neighbors.find(pkt.routerId.value);
    if(it == ifc->neighbors.end())
    {
        OspfNeighbor n;
        n.routerId = pkt.routerId.value;
        n.state = OspfNbrDown;
        n.priority = pkt.helloPriority;
        ifc->neighbors[n.routerId] = n;
        it = ifc->neighbors.find(n.routerId);
    }

    OspfNeighbor &n = it->second;
    n.ip = srcIp;
    n.mac = srcMac;
    n.priority = pkt.helloPriority;
    n.lastHello = now;

    bool listed = false;
    for(const Ipv4 &x : pkt.neighbors)
        if(x.value == ospfRouterId)
        {
            listed = true;
            break;
        }

    if(listed)
    {
        if(n.state < OspfNbrTwoWay)
            n.state = OspfNbrTwoWay;
    }
    else
    {
        n.state = OspfNbrInit;
    }

    if(n.state >= OspfNbrTwoWay && ifc->state != OspfIfWaiting)
    {
        OspfElect(*ifc);
        if(n.state == OspfNbrTwoWay)
            OspfMaybeAdjacency(*ifc, n);
    }
}

void Router::OspfElect(OspfInterface &ifc)
{
    struct Cand
    {
        uint8_t pri;
        uint32_t rid;
    };

    Cand best{ 0, 0 };
    Cand second{ 0, 0 };
    bool hasBest = false;
    bool hasSecond = false;

    auto consider = [&](uint8_t pri, uint32_t rid) {
        if(pri == 0 || rid == 0)
            return;
        Cand c{ pri, rid };
        if(!hasBest || c.pri > best.pri ||
           (c.pri == best.pri && c.rid > best.rid))
        {
            second = best;
            hasSecond = hasBest;
            best = c;
            hasBest = true;
        }
        else if(!hasSecond || c.pri > second.pri ||
                (c.pri == second.pri && c.rid > second.rid))
        {
            second = c;
            hasSecond = true;
        }
    };

    if(ifc.priority > 0)
        consider(ifc.priority, ospfRouterId);

    for(const auto &kv : ifc.neighbors)
        if(kv.second.state >= OspfNbrTwoWay)
            consider(kv.second.priority, kv.first);

    if(!hasBest)
    {
        ifc.dr = Ipv4::Any();
        ifc.bdr = Ipv4::Any();
        ifc.drIp = Ipv4::Any();
        ifc.bdrIp = Ipv4::Any();
        ifc.state = OspfIfDrOther;
        return;
    }

    auto ipFor = [&](uint32_t rid) -> Ipv4 {
        if(rid == ospfRouterId)
            return ifc.port->ip;
        auto it = ifc.neighbors.find(rid);
        if(it != ifc.neighbors.end())
            return it->second.ip;
        return Ipv4::Any();
    };

    ifc.dr = Ipv4(best.rid);
    ifc.bdr = hasSecond ? Ipv4(second.rid) : Ipv4::Any();
    ifc.drIp = ipFor(best.rid);
    ifc.bdrIp = hasSecond ? ipFor(second.rid) : Ipv4::Any();

    if(best.rid == ospfRouterId)
        ifc.state = OspfIfDr;
    else if(hasSecond && second.rid == ospfRouterId)
        ifc.state = OspfIfBdr;
    else
        ifc.state = OspfIfDrOther;
}

void Router::OspfMaybeAdjacency(OspfInterface &ifc, OspfNeighbor &n)
{
    if(n.state != OspfNbrTwoWay)
        return;
    if(ifc.state == OspfIfWaiting || ifc.state == OspfIfDown)
        return;

    bool eligible = ifc.state == OspfIfDr || ifc.state == OspfIfBdr ||
                    ifc.dr == Ipv4(n.routerId) || ifc.bdr == Ipv4(n.routerId);
    if(!eligible)
        return;

    n.state = OspfNbrExStart;
    n.master = ospfRouterId > n.routerId;
    n.sentFull = false;
    n.gotFull = false;
    n.ddSeq = 0x1000u + n.routerId;
    n.requests.clear();

    OspfSendDdInitial(ifc, n);
}

void Router::OspfSendDdInitial(OspfInterface &ifc, OspfNeighbor &n)
{
    OspfPacket p;
    FillOspfHeader(p, *this);
    p.type = OspfPacket::DatabaseDescription;
    p.ddMtu = 1500;
    p.ddOptions = 0x02;
    p.ddFlags = 0x04 | 0x02 | (n.master ? 0x01 : 0);
    p.ddSeq = n.ddSeq;

    n.nextResend = (clock ? clock->Now() : 0) + 5;
    SendOspfPacket(ifc.port, p, n.ip, n.mac);
}

void Router::OspfSendDdFull(OspfInterface &ifc, OspfNeighbor &n)
{
    OspfPacket p;
    FillOspfHeader(p, *this);
    p.type = OspfPacket::DatabaseDescription;
    p.ddMtu = 1500;
    p.ddOptions = 0x02;
    p.ddFlags = n.master ? 0x01 : 0;
    p.ddSeq = n.ddSeq;

    for(const auto &kv : ospfLsdb)
        p.ddHeaders.push_back(kv.second.header);

    n.nextResend = (clock ? clock->Now() : 0) + 5;
    SendOspfPacket(ifc.port, p, n.ip, n.mac);
}

void Router::OspfHandleDd(Port *ingress, const OspfPacket &pkt,
                          const Mac &srcMac, const Ipv4 &srcIp)
{
    OspfInterface *ifc = nullptr;
    for(OspfInterface &i : ospfIfaces)
        if(i.port == ingress)
        {
            ifc = &i;
            break;
        }
    if(!ifc)
        return;

    auto it = ifc->neighbors.find(pkt.routerId.value);
    if(it == ifc->neighbors.end())
        return;

    OspfNeighbor &n = it->second;
    n.ip = srcIp;
    n.mac = srcMac;

    if(n.state == OspfNbrFull)
    {
        if(pkt.ddFlags & 0x04)
        {
            OspfSendDdFull(*ifc, n);
        }
        else
        {
            OspfPacket a;
            FillOspfHeader(a, *this);
            a.type = OspfPacket::LinkStateAck;
            SendOspfPacket(ingress, a, n.ip, n.mac);
        }
        return;
    }

    if(n.state < OspfNbrExStart)
        return;

    if((pkt.ddFlags & 0x04) && n.state != OspfNbrExStart)
    {
        OspfSendDdFull(*ifc, n);
        return;
    }

    if(pkt.ddFlags & 0x04)
    {
        n.master = !(pkt.ddFlags & 0x01);
        n.ddSeq = pkt.ddSeq + (n.master ? 1u : 0u);
        n.state = OspfNbrExchange;
        n.sentFull = true;
        n.gotFull = false;
        OspfProcessHeaders(*ifc, n, pkt.ddHeaders);
        OspfSendDdFull(*ifc, n);
        return;
    }

    if(n.state == OspfNbrExStart)
    {
        n.state = OspfNbrExchange;
        n.sentFull = false;
        n.gotFull = false;
    }

    if(pkt.ddSeq > n.ddSeq)
        n.ddSeq = pkt.ddSeq;

    OspfProcessHeaders(*ifc, n, pkt.ddHeaders);

    if(!(pkt.ddFlags & 0x02))
        n.gotFull = true;

    if(!n.sentFull)
    {
        n.sentFull = true;
        OspfSendDdFull(*ifc, n);
    }

    if(n.gotFull && n.sentFull)
    {
        if(n.requests.empty())
        {
            n.state = OspfNbrFull;
            OspfConverge();
        }
        else
        {
            n.state = OspfNbrLoading;
            OspfSendLsr(*ifc, n);
        }
    }
}

void Router::OspfProcessHeaders(OspfInterface &, OspfNeighbor &n,
                                const std::vector<OspfLsaHeader> &headers)
{
    for(const OspfLsaHeader &h : headers)
    {
        auto key = std::make_tuple(h.type, h.id.value, h.advRouter.value);
        auto it = ospfLsdb.find(key);
        bool need = (it == ospfLsdb.end()) ||
                    (h.seq > it->second.header.seq);
        if(!need)
            continue;

        bool dup = false;
        for(const OspfLsrItem &r : n.requests)
            if(r.type == h.type && r.id == h.id && r.advRouter == h.advRouter)
            {
                dup = true;
                break;
            }
        if(!dup)
            n.requests.push_back(OspfLsrItem{ h.type, h.id, h.advRouter });
    }
}

void Router::OspfSendLsr(OspfInterface &ifc, OspfNeighbor &n)
{
    if(n.requests.empty())
        return;

    OspfPacket p;
    FillOspfHeader(p, *this);
    p.type = OspfPacket::LinkStateRequest;
    p.requests = n.requests;

    n.nextResend = (clock ? clock->Now() : 0) + 5;
    SendOspfPacket(ifc.port, p, n.ip, n.mac);
}

void Router::OspfHandleLsr(Port *ingress, const OspfPacket &pkt,
                           const Mac &srcMac, const Ipv4 &srcIp)
{
    std::vector<OspfLsa> lsas;
    for(const OspfLsrItem &r : pkt.requests)
    {
        auto key = std::make_tuple(uint8_t(r.type), r.id.value, r.advRouter.value);
        auto it = ospfLsdb.find(key);
        if(it != ospfLsdb.end())
            lsas.push_back(it->second);
    }
    if(lsas.empty())
        return;

    OspfPacket p;
    FillOspfHeader(p, *this);
    p.type = OspfPacket::LinkStateUpdate;
    p.lsas = lsas;

    SendOspfPacket(ingress, p, srcIp, srcMac);
}

void Router::OspfHandleLsu(Port *ingress, const OspfPacket &pkt,
                           const Mac &srcMac, const Ipv4 &srcIp)
{
    std::vector<OspfLsa> installed;
    std::vector<OspfLsaHeader> acks;

    for(const OspfLsa &lsa : pkt.lsas)
    {
        if(lsa.header.age >= 3600)
            continue;
        auto key = std::make_tuple(lsa.header.type, lsa.header.id.value,
                                   lsa.header.advRouter.value);
        auto it = ospfLsdb.find(key);
        bool newer = (it == ospfLsdb.end()) ||
                     (lsa.header.seq > it->second.header.seq) ||
                     (lsa.header.seq == it->second.header.seq &&
                      (lsa.header.checksum != it->second.header.checksum ||
                       lsa.header.age < it->second.header.age));
        if(!newer)
            continue;

        ospfLsdb[key] = lsa;
        installed.push_back(lsa);
        acks.push_back(lsa.header);
    }

    if(!acks.empty())
    {
        OspfPacket a;
        FillOspfHeader(a, *this);
        a.type = OspfPacket::LinkStateAck;
        a.acks = acks;
        SendOspfPacket(ingress, a, srcIp, srcMac);
    }

    for(const OspfLsa &lsa : installed)
        OspfFlood(lsa, ingress);

    OspfInterface *ifc = nullptr;
    for(OspfInterface &i : ospfIfaces)
        if(i.port == ingress)
        {
            ifc = &i;
            break;
        }

    if(ifc)
    {
        auto it = ifc->neighbors.find(pkt.routerId.value);
        if(it != ifc->neighbors.end())
        {
            for(const OspfLsa &lsa : installed)
            {
                auto key = std::make_tuple(lsa.header.type, lsa.header.id.value,
                                           lsa.header.advRouter.value);
                for(auto r = it->second.requests.begin();
                    r != it->second.requests.end(); )
                {
                    if(std::make_tuple(uint8_t(r->type), r->id.value,
                                       r->advRouter.value) == key)
                        r = it->second.requests.erase(r);
                    else
                        ++r;
                }
            }

            if(it->second.state == OspfNbrLoading && it->second.requests.empty())
            {
                it->second.state = OspfNbrFull;
                OspfConverge();
            }
        }
    }

    if(!installed.empty())
        OspfConverge();
}

void Router::OspfHandleLsaAck(Port *ingress, const OspfPacket &pkt)
{
    OspfInterface *ifc = nullptr;
    for(OspfInterface &i : ospfIfaces)
        if(i.port == ingress)
        {
            ifc = &i;
            break;
        }
    if(!ifc)
        return;

    auto it = ifc->neighbors.find(pkt.routerId.value);
    if(it == ifc->neighbors.end())
        return;

    OspfNeighbor &n = it->second;
    for(const OspfLsaHeader &h : pkt.acks)
    {
        auto key = std::make_tuple(h.type, h.id.value, h.advRouter.value);
        for(auto r = n.retrans.begin(); r != n.retrans.end(); )
        {
            if(std::make_tuple(r->header.type, r->header.id.value,
                               r->header.advRouter.value) == key)
                r = n.retrans.erase(r);
            else
                ++r;
        }
    }
    if(n.retrans.empty())
        n.nextResend = 0;
}

void Router::OspfSendLsu(OspfInterface &ifc, OspfNeighbor &n,
                         const std::vector<OspfLsa> &lsas)
{
    if(lsas.empty())
        return;

    for(const OspfLsa &lsa : lsas)
    {
        auto key = std::make_tuple(lsa.header.type, lsa.header.id.value,
                                   lsa.header.advRouter.value);
        bool replaced = false;
        for(OspfLsa &cur : n.retrans)
            if(std::make_tuple(cur.header.type, cur.header.id.value,
                               cur.header.advRouter.value) == key)
            {
                cur = lsa;
                replaced = true;
                break;
            }
        if(!replaced)
            n.retrans.push_back(lsa);
    }

    n.nextResend = (clock ? clock->Now() : 0) + 5;

    OspfPacket p;
    FillOspfHeader(p, *this);
    p.type = OspfPacket::LinkStateUpdate;
    p.lsas = lsas;

    SendOspfPacket(ifc.port, p, n.ip, n.mac);
}

void Router::OspfFlood(const OspfLsa &lsa, Port *except)
{
    for(OspfInterface &ifc : ospfIfaces)
    {
        if(ifc.port == except)
            continue;
        for(auto &kv : ifc.neighbors)
            if(kv.second.state >= OspfNbrExchange)
                OspfSendLsu(ifc, kv.second, std::vector<OspfLsa>{ lsa });
    }
}

OspfLsa Router::OspfBuildRouterLsa()
{
    OspfLsa lsa;
    lsa.header.type = OspfPacket::RouterLsa;
    lsa.header.options = 0x02;
    lsa.header.id = Ipv4(ospfRouterId);
    lsa.header.advRouter = Ipv4(ospfRouterId);
    lsa.flags = 0;

    for(OspfInterface &ifc : ospfIfaces)
    {
        bool full = false;
        for(const auto &kv : ifc.neighbors)
            if(kv.second.state == OspfNbrFull)
            {
                full = true;
                break;
            }

        if(full && ifc.drIp.value != 0)
            lsa.links.push_back(OspfRouterLink{
                ifc.drIp, ifc.port->ip, 2, 1 });
        else
            lsa.links.push_back(OspfRouterLink{
                ifc.port->subnet.network, ifc.port->subnet.Mask(), 3, 1 });
    }

    return lsa;
}

OspfLsa Router::OspfBuildNetworkLsa(OspfInterface &ifc)
{
    OspfLsa lsa;
    lsa.header.type = OspfPacket::NetworkLsa;
    lsa.header.options = 0x02;
    lsa.header.id = ifc.port->ip;
    lsa.header.advRouter = Ipv4(ospfRouterId);
    lsa.mask = ifc.port->subnet.Mask();
    lsa.attached.push_back(Ipv4(ospfRouterId));

    for(const auto &kv : ifc.neighbors)
        if(kv.second.state == OspfNbrFull)
            lsa.attached.push_back(Ipv4(kv.first));

    return lsa;
}

void Router::OspfConverge()
{
    if(!ospfEnabled)
        return;

    OspfLsa own = OspfBuildRouterLsa();
    auto key = std::make_tuple(uint8_t(OspfPacket::RouterLsa),
                               ospfRouterId, ospfRouterId);
    auto it = ospfLsdb.find(key);
    bool changed = (it == ospfLsdb.end()) || it->second.links.size() != own.links.size();
    if(!changed)
        for(std::size_t i = 0; i < own.links.size(); ++i)
        {
            const OspfRouterLink &a = own.links[i];
            const OspfRouterLink &b = it->second.links[i];
            if(!(a.id == b.id) || !(a.data == b.data) ||
               a.type != b.type || a.metric != b.metric)
            {
                changed = true;
                break;
            }
        }

    if(changed)
    {
        own.header.seq = (it == ospfLsdb.end())
            ? 0x80000001u : (it->second.header.seq + 1);
        ospfSeq = own.header.seq;
        ospfLsdb[key] = own;
        OspfFlood(own, nullptr);
    }

    for(OspfInterface &ifc : ospfIfaces)
    {
        auto nkey = std::make_tuple(uint8_t(OspfPacket::NetworkLsa),
                                    ifc.port->ip.value, ospfRouterId);
        auto nit = ospfLsdb.find(nkey);
        bool haveFull = false;
        for(const auto &kv : ifc.neighbors)
            if(kv.second.state == OspfNbrFull)
            {
                haveFull = true;
                break;
            }

        if(ifc.state == OspfIfDr && haveFull)
        {
            OspfLsa nl = OspfBuildNetworkLsa(ifc);
            bool nchanged = (nit == ospfLsdb.end()) ||
                            nit->second.attached.size() != nl.attached.size();
            if(!nchanged)
                for(std::size_t i = 0; i < nl.attached.size(); ++i)
                    if(!(nl.attached[i] == nit->second.attached[i]))
                    {
                        nchanged = true;
                        break;
                    }
            if(nchanged)
            {
                nl.header.seq = (nit == ospfLsdb.end())
                    ? 0x80000001u : (nit->second.header.seq + 1);
                ospfLsdb[nkey] = nl;
                OspfFlood(nl, nullptr);
            }
        }
    }

    OspfSync();
}

void Router::OspfSync()
{
    routeTable.erase(std::remove_if(routeTable.begin(), routeTable.end(),
                     [](const Route &r) { return r.ospf; }),
                     routeTable.end());

    auto rkey = [](uint32_t id) { return (uint64_t(1) << 32) | id; };
    auto nkey = [](uint32_t id) { return (uint64_t(2) << 32) | id; };

    std::map<uint64_t, std::vector<std::pair<uint64_t, uint16_t>>> adj;
    std::map<uint64_t, const OspfLsa *> routers;
    std::map<uint64_t, const OspfLsa *> nets;

    for(const auto &kv : ospfLsdb)
    {
        const OspfLsa &lsa = kv.second;
        if(lsa.header.age >= 3600)
            continue;

        if(lsa.header.type == OspfPacket::RouterLsa)
        {
            uint64_t v = rkey(lsa.header.advRouter.value);
            routers[v] = &lsa;
            for(const OspfRouterLink &l : lsa.links)
            {
                if(l.type == 2)
                    adj[v].push_back({ nkey(l.id.value), l.metric });
                else if(l.type == 1)
                    adj[v].push_back({ rkey(l.id.value), l.metric });
            }
        }
        else if(lsa.header.type == OspfPacket::NetworkLsa)
        {
            uint64_t v = nkey(lsa.header.id.value);
            nets[v] = &lsa;
            for(const Ipv4 &a : lsa.attached)
                adj[v].push_back({ rkey(a.value), 0 });
        }
    }

    uint64_t self = rkey(ospfRouterId);
    std::map<uint64_t, uint32_t> dist;
    std::map<uint64_t, uint64_t> pred;
    std::set<uint64_t> done;
    dist[self] = 0;

    while(true)
    {
        uint64_t u = 0;
        uint32_t best = 0xFFFFFFFFu;
        bool found = false;
        for(const auto &kv : dist)
            if(!done.count(kv.first) && kv.second < best)
            {
                best = kv.second;
                u = kv.first;
                found = true;
            }
        if(!found)
            break;

        done.insert(u);
        auto ait = adj.find(u);
        if(ait == adj.end())
            continue;

        for(const auto &e : ait->second)
        {
            uint32_t nd = best + e.second;
            auto dit = dist.find(e.first);
            if(dit == dist.end() || nd < dit->second)
            {
                dist[e.first] = nd;
                pred[e.first] = u;
            }
        }
    }

    auto firstRouter = [&](uint64_t dest) -> uint32_t {
        if(dest == self)
            return 0;
        std::vector<uint64_t> path;
        uint64_t cur = dest;
        while(cur != self)
        {
            path.push_back(cur);
            auto it = pred.find(cur);
            if(it == pred.end())
                return 0;
            cur = it->second;
            if(path.size() > 1024)
                return 0;
        }
        for(auto it = path.rbegin(); it != path.rend(); ++it)
            if((*it >> 32) == 1)
                return uint32_t(*it & 0xFFFFFFFFu);
        return 0;
    };

    auto neighborInfo = [&](uint32_t rid, Ipv4 &ip, Port *&port) -> bool {
        for(OspfInterface &ifc : ospfIfaces)
        {
            auto it = ifc.neighbors.find(rid);
            if(it != ifc.neighbors.end() && it->second.state >= OspfNbrFull)
            {
                ip = it->second.ip;
                port = ifc.port;
                return true;
            }
        }
        return false;
    };

    auto directExists = [&](const Ipv4Subnet &dst) {
        for(const Route &r : routeTable)
            if(r.direct && r.dst == dst)
                return true;
        return false;
    };

    auto addRoute = [&](const Ipv4Subnet &dst, uint32_t metric,
                        const Ipv4 &nh, Port *port) {
        if(dst.prefix == 0 || directExists(dst))
            return;
        for(const Route &r : routeTable)
            if(r.ospf && r.dst == dst && r.metric <= metric)
                return;
        routeTable.push_back(Route(dst, nh, false));
        Route &nr = routeTable.back();
        nr.metric = uint16_t(metric > 65535 ? 65535 : metric);
        nr.dynamic = true;
        nr.ospf = true;
        nr.ospfOrigin = 0;
        nr.learnedFromPort = port;
        nr.expiresAt = 0;
    };

    for(const auto &kv : nets)
    {
        auto dit = dist.find(kv.first);
        if(dit == dist.end())
            continue;
        const OspfLsa &nl = *kv.second;
        uint8_t prefix = PrefixFromMask(nl.mask);
        if(prefix == 0)
            continue;
        Ipv4 net(uint32_t(nl.header.id.value & nl.mask.value));
        uint32_t fr = firstRouter(kv.first);
        Ipv4 nh;
        Port *p = nullptr;
        if(fr == 0 || !neighborInfo(fr, nh, p))
            continue;
        addRoute(Ipv4Subnet(net, prefix), dit->second, nh, p);
    }

    for(const auto &kv : routers)
    {
        auto dit = dist.find(kv.first);
        if(dit == dist.end())
            continue;
        const OspfLsa &rl = *kv.second;
        uint32_t fr = firstRouter(kv.first);
        if(fr == 0)
            continue;
        Ipv4 nh;
        Port *p = nullptr;
        if(!neighborInfo(fr, nh, p))
            continue;
        for(const OspfRouterLink &l : rl.links)
        {
            if(l.type != 3 || l.data.value == 0)
                continue;
            uint8_t prefix = PrefixFromMask(l.data);
            Ipv4 net(uint32_t(l.id.value & l.data.value));
            addRoute(Ipv4Subnet(net, prefix), dit->second + l.metric, nh, p);
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
