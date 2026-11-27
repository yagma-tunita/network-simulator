#include "Router.hpp"
#include "Port.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/OspfPacket.hpp"
#include "../engine/Clock.hpp"
#include "../engine/Event.hpp"
#include "../engine/Scheduler.hpp"
#include <algorithm>
#include <cstddef>
#include <memory>
#include <set>
#include <vector>

namespace
{
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

    void FillOspfHeader(OspfPacket &p, Router &r)
    {
        p.routerId = Ipv4(r.ospfRouterId);
        p.areaId = r.ospfAreaId;
        p.authType = r.ospfAuthType;
        if(r.ospfAuthType == OspfPacket::AuthMd5)
        {
            p.md5Key = r.ospfKey;
            p.authKeyId = r.ospfKeyId;
            p.cryptoSeq = ++r.ospfCryptoSeq;
            p.digestAlg = r.ospfDigestAlg;
        }
        else
        {
            for(std::size_t i = 0; i < 8; ++i)
                p.auth[i] = r.ospfPassword[i];
        }
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

uint32_t Router::ComputeOspfRouterId() const
{
    if(ospfRouterIdCfg != 0)
        return ospfRouterIdCfg;
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
    ospfCryptoSeq = 0;
    uint64_t now = clock ? clock->Now() : 0;

    for(Port *p : portList)
    {
        if(!p->hasIp)
            continue;
        OspfInterface ifc;
        ifc.port = p;
        ifc.state = OspfIfWaiting;
        ifc.priority = 1;
        auto ait = ospfAreaCfg.find(p);
        ifc.area = (ait != ospfAreaCfg.end()) ? ait->second : ospfAreaId;
        auto cit = ospfCostCfg.find(p);
        if(cit != ospfCostCfg.end())
            ifc.cost = cit->second;
        auto pit = ospfPassiveCfg.find(p);
        if(pit != ospfPassiveCfg.end())
            ifc.passive = pit->second;
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
        if(ifc.passive)
            continue;

        for(auto it = ifc.neighbors.begin(); it != ifc.neighbors.end(); )
        {
            if(now - it->second.lastHello > kOspfDeadInterval)
                it = ifc.neighbors.erase(it);
            else
                ++it;
        }

        if(ifc.state == OspfIfWaiting)
        {
            if(!ifc.virtualLink && now >= ifc.waitUntil)
                OspfElect(ifc);
        }
        else if(!ifc.virtualLink)
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
        if(ifc.virtualLink)
            SendOspfHelloVirtual(ifc);
    }

    bool aged = false;
    for(auto ait = ospfLsdb.begin(); ait != ospfLsdb.end(); ++ait)
    {
        uint32_t area = ait->first;
        auto &lsas = ait->second;
        for(auto it = lsas.begin(); it != lsas.end(); )
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
                    OspfFlood(area, lsa, nullptr);
                }
            }
            else if(lsa.header.age >= 3600)
            {
                it = lsas.erase(it);
                aged = true;
                continue;
            }
            ++it;
        }
    }
    for(auto it = ospfExternalLsdb.begin(); it != ospfExternalLsdb.end(); )
    {
        OspfLsa &lsa = it->second.lsa;
        if(lsa.header.age < 3600)
            lsa.header.age = uint16_t(lsa.header.age + kOspfHelloInterval);
        bool own = lsa.header.advRouter.value == ospfRouterId;
        if(own)
        {
            if(lsa.header.age >= 1800)
            {
                lsa.header.age = 0;
                OspfFloodExternal(lsa, nullptr);
            }
        }
        else if(lsa.header.age >= 3600)
        {
            it = ospfExternalLsdb.erase(it);
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
        if(!ifc.virtualLink)
            SendOspfHello(ifc.port);
}

void Router::SendVirtualOspfHellos()
{
    for(OspfInterface &ifc : ospfIfaces)
        if(ifc.virtualLink)
            SendOspfHelloVirtual(ifc);
}

void Router::SendOspfHelloVirtual(OspfInterface &ifc)
{
    if(!ospfEnabled || ifc.passive || ifc.vlinkPeer == 0)
        return;

    const Route *r = FindRoute(Ipv4(ifc.vlinkPeer));
    if(!r)
        return;
    Ipv4 nextHop = r->direct ? Ipv4(ifc.vlinkPeer) : r->nextHop;
    Port *egress = PortForNextHop(nextHop);
    if(!egress)
        return;

    Mac dstMac;
    if(!arp.Lookup(nextHop, dstMac))
    {
        arp.SendArpRequest(nextHop, egress);
        return;
    }
    ifc.port = egress;

    OspfPacket pkt;
    pkt.type = OspfPacket::Hello;
    FillOspfHeader(pkt, *this);
    pkt.areaId = Ipv4::Any();
    pkt.helloMask = Ipv4::Any();
    pkt.helloInterval = uint16_t(kOspfHelloInterval);
    pkt.helloOptions = 0x02;
    pkt.helloPriority = 0;
    pkt.deadInterval = uint32_t(kOspfDeadInterval);
    for(const auto &kv : ifc.neighbors)
        if(kv.second.state >= OspfNbrInit)
            pkt.neighbors.push_back(Ipv4(kv.first));

    SendOspfPacket(egress, pkt, Ipv4(ifc.vlinkPeer), dstMac, 64);
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
    if(ifc->passive)
        return;

    OspfPacket pkt;
    pkt.type = OspfPacket::Hello;
    FillOspfHeader(pkt, *this);
    pkt.areaId = ifc->area;

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
                            const Ipv4 &dstIp, const Mac &dstMac,
                            uint8_t ttl)
{
    if(!egress || !egress->hasIp)
        return;

    IpPacket ip(egress->ip, dstIp, IpPacket::kOspf, pkt.ToBytes());
    ip.ttl = ttl;

    if(ip.payload.empty())
        return;

    egress->Send(std::make_shared<const EthernetFrame>(
        dstMac, egress->mac, EthernetFrame::kIPv4, ip.ToBytes()));
}

Router::OspfInterface *Router::OspfIfcForPort(Port *p)
{
    for(OspfInterface &ifc : ospfIfaces)
        if(!ifc.virtualLink && ifc.port == p)
            return &ifc;
    return nullptr;
}

Router::OspfInterface *Router::OspfIfcForOspf(Port *ingress,
                                              const OspfPacket &pkt)
{
    for(OspfInterface &ifc : ospfIfaces)
        if(!ifc.virtualLink && ifc.port == ingress &&
           pkt.areaId == ifc.area)
            return &ifc;
    if(pkt.areaId.value == 0)
        for(OspfInterface &ifc : ospfIfaces)
            if(ifc.virtualLink && ifc.vlinkPeer == pkt.routerId.value)
                return &ifc;
    return nullptr;
}

void Router::HandleOspf(Port *ingress, const IpPacket &pkt, const Mac &srcMac)
{
    OspfPacket op;
    if(!OspfPacket::TryFromBytes(pkt.payload, op, ospfKey, ospfDigestAlg))
        return;
    if(op.routerId.value == 0 || op.routerId.value == ospfRouterId)
        return;
    OspfInterface *ifc = OspfIfcForOspf(ingress, op);
    if(!ifc || ifc->passive)
        return;
    if(op.authType != ospfAuthType)
        return;
    if(op.authType == OspfPacket::AuthSimple)
        for(std::size_t i = 0; i < 8; ++i)
            if(op.auth[i] != ospfPassword[i])
                return;
    if(op.authType == OspfPacket::AuthMd5)
    {
        if(op.authKeyId != ospfKeyId)
            return;
        for(OspfInterface &ifc : ospfIfaces)
        {
            auto it = ifc.neighbors.find(op.routerId.value);
            if(it != ifc.neighbors.end())
            {
                if(op.cryptoSeq < it->second.cryptoSeq)
                    return;
                it->second.cryptoSeq = op.cryptoSeq;
            }
        }
    }

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
    OspfInterface *ifc = OspfIfcForOspf(ingress, pkt);
    if(!ifc)
        return;

    if(pkt.helloInterval != uint16_t(kOspfHelloInterval) ||
       pkt.deadInterval != uint32_t(kOspfDeadInterval))
        return;
    if(ifc->virtualLink)
    {
        if(!(pkt.helloMask == Ipv4::Any()))
            return;
        ifc->port = ingress;
    }
    else if(!(pkt.helloMask == ingress->subnet.Mask()))
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
    n.cryptoSeq = pkt.cryptoSeq;
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

    bool eligible = ifc.virtualLink ||
                    ifc.state == OspfIfDr || ifc.state == OspfIfBdr ||
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
    p.areaId = ifc.area;
    p.type = OspfPacket::DatabaseDescription;
    p.ddMtu = 1500;
    p.ddOptions = 0x02;
    p.ddFlags = 0x04 | 0x02 | (n.master ? 0x01 : 0);
    p.ddSeq = n.ddSeq;

    n.nextResend = (clock ? clock->Now() : 0) + 5;
    SendOspfPacket(ifc.port, p, n.ip, n.mac, ifc.virtualLink ? 64 : 1);
}

void Router::OspfSendDdFull(OspfInterface &ifc, OspfNeighbor &n)
{
    OspfPacket p;
    FillOspfHeader(p, *this);
    p.areaId = ifc.area;
    p.type = OspfPacket::DatabaseDescription;
    p.ddMtu = 1500;
    p.ddOptions = 0x02;
    p.ddFlags = n.master ? 0x01 : 0;
    p.ddSeq = n.ddSeq;

    auto lit = ospfLsdb.find(ifc.area.value);
    if(lit != ospfLsdb.end())
        for(const auto &kv : lit->second)
            p.ddHeaders.push_back(kv.second.header);
    auto sit = ospfStubAreas.find(ifc.area.value);
    auto nit = ospfNssaAreas.find(ifc.area.value);
    bool noType5 = (sit != ospfStubAreas.end() && sit->second) ||
                   (nit != ospfNssaAreas.end() && nit->second);
    if(!noType5)
        for(const auto &kv : ospfExternalLsdb)
            p.ddHeaders.push_back(kv.second.lsa.header);

    n.nextResend = (clock ? clock->Now() : 0) + 5;
    SendOspfPacket(ifc.port, p, n.ip, n.mac, ifc.virtualLink ? 64 : 1);
}

void Router::OspfHandleDd(Port *ingress, const OspfPacket &pkt,
                          const Mac &srcMac, const Ipv4 &srcIp)
{
    OspfInterface *ifc = OspfIfcForOspf(ingress, pkt);
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
            a.areaId = ifc->area;
            a.type = OspfPacket::LinkStateAck;
            SendOspfPacket(ingress, a, n.ip, n.mac, ifc->virtualLink ? 64 : 1);
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

void Router::OspfProcessHeaders(OspfInterface &ifc, OspfNeighbor &n,
                                const std::vector<OspfLsaHeader> &headers)
{
    for(const OspfLsaHeader &h : headers)
    {
        auto sit = ospfStubAreas.find(ifc.area.value);
        auto nit = ospfNssaAreas.find(ifc.area.value);
        bool stub = sit != ospfStubAreas.end() && sit->second;
        bool nssa = nit != ospfNssaAreas.end() && nit->second;
        if(h.type == OspfPacket::ExternalLsa && (stub || nssa))
            continue;
        if(h.type == OspfPacket::NssaExternalLsa && !nssa)
            continue;
        auto key = std::make_tuple(h.type, h.id.value, h.advRouter.value);
        bool need;
        if(h.type == OspfPacket::ExternalLsa)
        {
            auto it = ospfExternalLsdb.find(key);
            need = (it == ospfExternalLsdb.end()) ||
                   (h.seq > it->second.lsa.header.seq);
        }
        else
        {
            auto &lsas = ospfLsdb[ifc.area.value];
            auto it = lsas.find(key);
            need = (it == lsas.end()) || (h.seq > it->second.header.seq);
        }
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
    p.areaId = ifc.area;
    p.type = OspfPacket::LinkStateRequest;
    p.requests = n.requests;

    n.nextResend = (clock ? clock->Now() : 0) + 5;
    SendOspfPacket(ifc.port, p, n.ip, n.mac, ifc.virtualLink ? 64 : 1);
}

void Router::OspfHandleLsr(Port *ingress, const OspfPacket &pkt,
                           const Mac &srcMac, const Ipv4 &srcIp)
{
    OspfInterface *ifc = OspfIfcForOspf(ingress, pkt);
    if(!ifc)
        return;

    auto &lsasMap = ospfLsdb[ifc->area.value];
    std::vector<OspfLsa> lsas;
    for(const OspfLsrItem &r : pkt.requests)
    {
        auto key = std::make_tuple(uint8_t(r.type), r.id.value, r.advRouter.value);
        if(r.type == OspfPacket::ExternalLsa)
        {
            auto it = ospfExternalLsdb.find(key);
            if(it != ospfExternalLsdb.end())
                lsas.push_back(it->second.lsa);
        }
        else
        {
            auto it = lsasMap.find(key);
            if(it != lsasMap.end())
                lsas.push_back(it->second);
        }
    }
    if(lsas.empty())
        return;

    OspfPacket p;
    FillOspfHeader(p, *this);
    p.areaId = ifc->area;
    p.type = OspfPacket::LinkStateUpdate;
    p.lsas = lsas;

    SendOspfPacket(ingress, p, srcIp, srcMac, ifc->virtualLink ? 64 : 1);
}

void Router::OspfHandleLsu(Port *ingress, const OspfPacket &pkt,
                           const Mac &srcMac, const Ipv4 &srcIp)
{
    OspfInterface *ifc = OspfIfcForOspf(ingress, pkt);
    if(!ifc)
        return;

    auto &lsasMap = ospfLsdb[ifc->area.value];
    std::vector<OspfLsa> installedArea;
    std::vector<OspfLsa> installedExt;
    std::vector<OspfLsaHeader> acks;

    for(const OspfLsa &lsa : pkt.lsas)
    {
        if(lsa.header.type == OspfPacket::ExternalLsa)
        {
            auto sit = ospfStubAreas.find(ifc->area.value);
            auto nit = ospfNssaAreas.find(ifc->area.value);
            if((sit != ospfStubAreas.end() && sit->second) ||
               (nit != ospfNssaAreas.end() && nit->second))
                continue;
        }
        else if(lsa.header.type == OspfPacket::NssaExternalLsa)
        {
            auto nit = ospfNssaAreas.find(ifc->area.value);
            if(nit == ospfNssaAreas.end() || !nit->second)
                continue;
        }
        auto key = std::make_tuple(lsa.header.type, lsa.header.id.value,
                                   lsa.header.advRouter.value);
        bool newer = false;

        if(lsa.header.type == OspfPacket::ExternalLsa)
        {
            auto it = ospfExternalLsdb.find(key);
            newer = (it == ospfExternalLsdb.end()) ||
                    (lsa.header.seq > it->second.lsa.header.seq) ||
                    (lsa.header.seq == it->second.lsa.header.seq &&
                     (lsa.header.checksum != it->second.lsa.header.checksum ||
                      lsa.header.age < it->second.lsa.header.age));
            if(newer)
            {
                ospfExternalLsdb[key] = OspfExtLsa{ lsa, srcIp, ingress };
                installedExt.push_back(lsa);
            }
        }
        else
        {
            auto it = lsasMap.find(key);
            newer = (it == lsasMap.end()) ||
                    (lsa.header.seq > it->second.header.seq) ||
                    (lsa.header.seq == it->second.header.seq &&
                     (lsa.header.checksum != it->second.header.checksum ||
                      lsa.header.age < it->second.header.age));
            if(newer)
            {
                lsasMap[key] = lsa;
                installedArea.push_back(lsa);
            }
        }

        if(newer)
            acks.push_back(lsa.header);
    }

    if(!acks.empty())
    {
        OspfPacket a;
        FillOspfHeader(a, *this);
        a.areaId = ifc->area;
        a.type = OspfPacket::LinkStateAck;
        a.acks = acks;
        SendOspfPacket(ingress, a, srcIp, srcMac, ifc->virtualLink ? 64 : 1);
    }

    for(const OspfLsa &lsa : installedArea)
        OspfFlood(ifc->area.value, lsa, ingress);
    for(const OspfLsa &lsa : installedExt)
        OspfFloodExternal(lsa, ingress);

    {
        auto it = ifc->neighbors.find(pkt.routerId.value);
        if(it != ifc->neighbors.end())
        {
            for(const OspfLsa &lsa : installedArea)
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
            for(const OspfLsa &lsa : installedExt)
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

    if(!installedArea.empty() || !installedExt.empty())
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
    p.areaId = ifc.area;
    p.type = OspfPacket::LinkStateUpdate;
    p.lsas = lsas;

    SendOspfPacket(ifc.port, p, n.ip, n.mac, ifc.virtualLink ? 64 : 1);
}

void Router::OspfFlood(uint32_t area, const OspfLsa &lsa, Port *except)
{
    for(OspfInterface &ifc : ospfIfaces)
    {
        if(ifc.port == except || ifc.area.value != area)
            continue;
        for(auto &kv : ifc.neighbors)
            if(kv.second.state >= OspfNbrExchange)
                OspfSendLsu(ifc, kv.second, std::vector<OspfLsa>{ lsa });
    }
}

OspfLsa Router::OspfBuildRouterLsa(uint32_t area)
{
    OspfLsa lsa;
    lsa.header.type = OspfPacket::RouterLsa;
    lsa.header.options = 0x02;
    lsa.header.id = Ipv4(ospfRouterId);
    lsa.header.advRouter = Ipv4(ospfRouterId);
    lsa.flags = 0;

    for(OspfInterface &ifc : ospfIfaces)
    {
        if(ifc.area.value != area)
            continue;
        bool full = false;
        for(const auto &kv : ifc.neighbors)
            if(kv.second.state == OspfNbrFull)
            {
                full = true;
                break;
            }

        if(ifc.virtualLink)
        {
            if(full)
                lsa.links.push_back(OspfRouterLink{
                    Ipv4(ifc.vlinkPeer),
                    ifc.port ? ifc.port->ip : Ipv4::Any(), 4, ifc.cost });
            continue;
        }
        if(!ifc.port)
            continue;

        if(full && ifc.drIp.value != 0)
            lsa.links.push_back(OspfRouterLink{
                ifc.drIp, ifc.port->ip, 2, ifc.cost });
        else
            lsa.links.push_back(OspfRouterLink{
                ifc.port->subnet.network, ifc.port->subnet.Mask(), 3, ifc.cost });
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

    std::set<uint32_t> areas;
    for(OspfInterface &ifc : ospfIfaces)
        areas.insert(ifc.area.value);

    for(uint32_t area : areas)
    {
        OspfLsa own = OspfBuildRouterLsa(area);
        auto &lsas = ospfLsdb[area];
        auto key = std::make_tuple(uint8_t(OspfPacket::RouterLsa),
                                   ospfRouterId, ospfRouterId);
        auto it = lsas.find(key);
        bool changed = (it == lsas.end()) ||
                       it->second.links.size() != own.links.size();
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
            own.header.seq = (it == lsas.end())
                ? 0x80000001u : (it->second.header.seq + 1);
            ospfSeq = own.header.seq;
            lsas[key] = own;
            OspfFlood(area, own, nullptr);
        }
    }

    for(OspfInterface &ifc : ospfIfaces)
    {
        if(ifc.virtualLink || !ifc.port)
            continue;
        uint32_t area = ifc.area.value;
        auto &lsas = ospfLsdb[area];
        auto nkey = std::make_tuple(uint8_t(OspfPacket::NetworkLsa),
                                    ifc.port->ip.value, ospfRouterId);
        auto nit = lsas.find(nkey);
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
            bool nchanged = (nit == lsas.end()) ||
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
                nl.header.seq = (nit == lsas.end())
                    ? 0x80000001u : (nit->second.header.seq + 1);
                lsas[nkey] = nl;
                OspfFlood(area, nl, nullptr);
            }
        }
    }

    OspfSync();
    OspfOriginateSummaries();
    OspfSync();
    OspfOriginateExternals();
    OspfOriginateAsbrSummaries();
    OspfSync();
}

void Router::AddOspfExternal(const Ipv4Subnet &dst, uint32_t metric, bool type2)
{
    ospfExternals.push_back(OspfExternal{ dst, metric, type2 });
}

void Router::SetOspfDefaultOriginate(bool on, uint32_t metric, bool type2)
{
    ospfDefaultOriginate = on;
    ospfDefaultMetric = metric;
    ospfDefaultType2 = type2;
    if(ospfEnabled)
        OspfOriginateExternals();
}

void Router::SetOspfRedistribute(bool connected, bool isStatic,
                                 uint32_t metric, bool type2)
{
    ospfRedistConnected = connected;
    ospfRedistStatic = isStatic;
    ospfRedistMetric = metric;
    ospfRedistType2 = type2;
    if(ospfEnabled)
        OspfOriginateExternals();
}

void Router::AddOspfSummary(uint32_t area, const Ipv4Subnet &dst,
                            bool notAdvertise)
{
    std::vector<OspfSummary> &list = ospfSummaries[area];
    for(OspfSummary &s : list)
        if(s.dst == dst)
        {
            s.notAdvertise = notAdvertise;
            if(ospfEnabled)
                OspfOriginateSummaries();
            return;
        }
    list.push_back(OspfSummary{ dst, notAdvertise });
    if(ospfEnabled)
        OspfOriginateSummaries();
}

void Router::ClearOspfSummaries(uint32_t area)
{
    ospfSummaries.erase(area);
    if(ospfEnabled)
        OspfOriginateSummaries();
}

void Router::OspfFloodExternal(const OspfLsa &lsa, Port *except)
{
    for(OspfInterface &ifc : ospfIfaces)
    {
        if(ifc.port == except)
            continue;
        auto sit = ospfStubAreas.find(ifc.area.value);
        auto nit = ospfNssaAreas.find(ifc.area.value);
        if((sit != ospfStubAreas.end() && sit->second) ||
           (nit != ospfNssaAreas.end() && nit->second))
            continue;
        for(auto &kv : ifc.neighbors)
            if(kv.second.state >= OspfNbrExchange)
                OspfSendLsu(ifc, kv.second, std::vector<OspfLsa>{ lsa });
    }
}

void Router::OspfOriginateExternals()
{
    if(!ospfEnabled)
        return;

    std::set<uint32_t> nssaAreas;
    bool hasNormal = false;
    for(OspfInterface &ifc : ospfIfaces)
    {
        auto sit = ospfStubAreas.find(ifc.area.value);
        auto nit = ospfNssaAreas.find(ifc.area.value);
        bool stub = sit != ospfStubAreas.end() && sit->second;
        bool nssa = nit != ospfNssaAreas.end() && nit->second;
        if(nssa)
            nssaAreas.insert(ifc.area.value);
        if(!stub && !nssa)
            hasNormal = true;
    }

    std::set<OspfKey> desired;
    std::map<uint32_t, std::set<OspfKey>> desired7;

    std::vector<OspfExternal> externals;
    std::set<std::pair<uint32_t, uint8_t>> seen;
    auto addExternal = [&](const Ipv4Subnet &dst, uint32_t metric,
                           bool type2)
    {
        std::pair<uint32_t, uint8_t> key{ dst.network.value, dst.prefix };
        if(!seen.insert(key).second)
            return;
        externals.push_back(OspfExternal{ dst, metric, type2 });
    };

    for(const OspfExternal &ext : ospfExternals)
        addExternal(ext.dst, ext.metric, ext.type2);
    if(ospfDefaultOriginate)
        addExternal(Ipv4Subnet("0.0.0.0/0"), ospfDefaultMetric,
                    ospfDefaultType2);
    if(ospfRedistConnected || ospfRedistStatic)
    {
        for(const Route &r : routeTable)
        {
            if(r.ospf || r.dynamic)
                continue;
            if(r.direct && !ospfRedistConnected)
                continue;
            if(!r.direct && !ospfRedistStatic)
                continue;
            addExternal(r.dst, ospfRedistMetric, ospfRedistType2);
        }
    }

    for(const OspfExternal &ext : externals)
    {
        if(hasNormal)
        {
            OspfLsa lsa;
            lsa.header.type = OspfPacket::ExternalLsa;
            lsa.header.options = 0x02;
            lsa.header.id = ext.dst.network;
            lsa.header.advRouter = Ipv4(ospfRouterId);
            lsa.mask = ext.dst.Mask();
            lsa.metric = (ext.metric & 0x00FFFFFFu) | (ext.type2 ? 0x80000000u : 0);
            lsa.forwarding = Ipv4::Any();

            auto key = std::make_tuple(uint8_t(OspfPacket::ExternalLsa),
                                       lsa.header.id.value, ospfRouterId);
            desired.insert(key);
            auto it = ospfExternalLsdb.find(key);
            bool changed = (it == ospfExternalLsdb.end()) ||
                           it->second.lsa.mask.value != lsa.mask.value ||
                           it->second.lsa.metric != lsa.metric;
            if(changed)
            {
                lsa.header.seq = (it == ospfExternalLsdb.end())
                    ? 0x80000001u : (it->second.lsa.header.seq + 1);
                ospfExternalLsdb[key] = OspfExtLsa{ lsa, Ipv4::Any(), nullptr };
                OspfFloodExternal(lsa, nullptr);
            }
        }

        for(uint32_t area : nssaAreas)
        {
            OspfLsa lsa;
            lsa.header.type = OspfPacket::NssaExternalLsa;
            lsa.header.options = 0x0A;
            lsa.header.id = ext.dst.network;
            lsa.header.advRouter = Ipv4(ospfRouterId);
            lsa.mask = ext.dst.Mask();
            lsa.metric = (ext.metric & 0x00FFFFFFu) | (ext.type2 ? 0x80000000u : 0);
            lsa.forwarding = Ipv4::Any();

            auto key = std::make_tuple(uint8_t(OspfPacket::NssaExternalLsa),
                                       lsa.header.id.value, ospfRouterId);
            desired7[area].insert(key);
            auto &lsas = ospfLsdb[area];
            auto it = lsas.find(key);
            bool changed = (it == lsas.end()) ||
                           it->second.mask.value != lsa.mask.value ||
                           it->second.metric != lsa.metric;
            if(!changed)
                continue;
            lsa.header.seq = (it == lsas.end())
                ? 0x80000001u : (it->second.header.seq + 1);
            lsas[key] = lsa;
            OspfFlood(area, lsa, nullptr);
        }
    }

    if(hasNormal)
    {
        for(uint32_t area : nssaAreas)
        {
            auto lit = ospfLsdb.find(area);
            if(lit == ospfLsdb.end())
                continue;
            for(const auto &kv : lit->second)
            {
                const OspfLsa &t7 = kv.second;
                if(t7.header.type != OspfPacket::NssaExternalLsa ||
                   t7.header.advRouter.value == ospfRouterId ||
                   t7.header.age >= 3600 ||
                   !(t7.header.options & 0x08))
                    continue;

                auto key = std::make_tuple(uint8_t(OspfPacket::ExternalLsa),
                                           t7.header.id.value, ospfRouterId);
                if(desired.count(key))
                    continue;

                OspfLsa t5;
                t5.header.type = OspfPacket::ExternalLsa;
                t5.header.options = 0x02;
                t5.header.id = t7.header.id;
                t5.header.advRouter = Ipv4(ospfRouterId);
                t5.mask = t7.mask;
                t5.metric = t7.metric;
                t5.forwarding = t7.forwarding;

                auto it = ospfExternalLsdb.find(key);
                bool changed = (it == ospfExternalLsdb.end()) ||
                               it->second.lsa.mask.value != t5.mask.value ||
                               it->second.lsa.metric != t5.metric;
                if(changed)
                {
                    t5.header.seq = (it == ospfExternalLsdb.end())
                        ? 0x80000001u : (it->second.lsa.header.seq + 1);
                    ospfExternalLsdb[key] = OspfExtLsa{ t5, Ipv4::Any(), nullptr };
                    OspfFloodExternal(t5, nullptr);
                }
                desired.insert(key);
            }
        }
    }

    for(auto it = ospfExternalLsdb.begin(); it != ospfExternalLsdb.end(); )
    {
        if(it->second.lsa.header.advRouter.value == ospfRouterId &&
           !desired.count(it->first))
        {
            OspfLsa flush = it->second.lsa;
            flush.header.age = 3600;
            flush.header.seq = flush.header.seq + 1;
            OspfFloodExternal(flush, nullptr);
            it = ospfExternalLsdb.erase(it);
        }
        else
            ++it;
    }

    for(auto &akv : ospfLsdb)
    {
        uint32_t area = akv.first;
        auto &lsas = akv.second;
        for(auto it = lsas.begin(); it != lsas.end(); )
        {
            const OspfLsa &lsa = it->second;
            if(lsa.header.type == OspfPacket::NssaExternalLsa &&
               lsa.header.advRouter.value == ospfRouterId &&
               !desired7[area].count(it->first))
            {
                OspfLsa flush = lsa;
                flush.header.age = 3600;
                flush.header.seq = flush.header.seq + 1;
                OspfFlood(area, flush, nullptr);
                it = lsas.erase(it);
            }
            else
                ++it;
        }
    }
}

void Router::OspfSync()
{
    routeTable.erase(std::remove_if(routeTable.begin(), routeTable.end(),
                     [](const Route &r) { return r.ospf; }),
                     routeTable.end());
    MarkRoutesDirty();

    ospfAreaNets.clear();
    ospfAreaRouterDist.clear();
    ospfAsbrReach.clear();

    std::set<uint32_t> areas;
    for(OspfInterface &ifc : ospfIfaces)
        areas.insert(ifc.area.value);
    for(const auto &kv : ospfLsdb)
        areas.insert(kv.first);

    for(uint32_t area : areas)
        OspfSyncArea(area);

    for(const auto &kv : ospfExternalLsdb)
    {
        bool allStub = true;
        for(OspfInterface &ifc : ospfIfaces)
        {
            auto sit = ospfStubAreas.find(ifc.area.value);
            if(sit == ospfStubAreas.end() || !sit->second)
            {
                allStub = false;
                break;
            }
        }
        if(allStub)
            break;

        const OspfLsa &lsa = kv.second.lsa;
        if(lsa.header.advRouter.value == ospfRouterId ||
           lsa.header.age >= 3600)
            continue;
        auto rit = ospfAsbrReach.find(lsa.header.advRouter.value);
        if(rit == ospfAsbrReach.end() ||
           !rit->second.port || rit->second.nextHop.value == 0)
            continue;
        uint8_t prefix = PrefixFromMask(lsa.mask);
        if(prefix == 0)
            continue;
        Ipv4 net(uint32_t(lsa.header.id.value & lsa.mask.value));
        Ipv4Subnet dst(net, prefix);

        uint32_t metric = lsa.metric & 0x00FFFFFFu;
        bool blocked = false;
        for(const Route &r : routeTable)
        {
            if(!(r.dst == dst))
                continue;
            if(r.direct || (r.ospf && !r.external) ||
               (r.external && r.metric <= metric))
            {
                blocked = true;
                break;
            }
        }
        if(blocked)
            continue;

        routeTable.push_back(Route(dst, rit->second.nextHop, false));
        MarkRoutesDirty();
        Route &nr = routeTable.back();
        nr.metric = uint16_t(metric > 65535 ? 65535 : metric);
        nr.dynamic = true;
        nr.ospf = true;
        nr.external = true;
        nr.learnedFromPort = rit->second.port;
        nr.expiresAt = 0;
    }
}

void Router::OspfSyncArea(uint32_t area)
{
    auto lit = ospfLsdb.find(area);
    if(lit == ospfLsdb.end())
        return;
    const auto &lsas = lit->second;

    auto rkey = [](uint32_t id) { return (uint64_t(1) << 32) | id; };
    auto nkey = [](uint32_t id) { return (uint64_t(2) << 32) | id; };

    std::map<uint64_t, std::vector<std::pair<uint64_t, uint16_t>>> adj;
    std::map<uint64_t, const OspfLsa *> routers;
    std::map<uint64_t, const OspfLsa *> nets;

    for(const auto &kv : lsas)
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
                else if(l.type == 1 || l.type == 4)
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
            if(ifc.area.value != area)
                continue;
            auto it = ifc.neighbors.find(rid);
            if(it == ifc.neighbors.end() ||
               it->second.state < OspfNbrFull)
                continue;
            if(ifc.virtualLink)
            {
                const Route *r = FindRoute(Ipv4(rid));
                if(!r)
                    continue;
                Ipv4 nh = r->direct ? Ipv4(rid) : r->nextHop;
                Port *p = r->learnedFromPort ? r->learnedFromPort
                                             : PortForNextHop(nh);
                if(!p)
                    continue;
                ip = nh;
                port = p;
                return true;
            }
            ip = it->second.ip;
            port = ifc.port;
            return true;
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
        if(directExists(dst))
            return;
        for(const Route &r : routeTable)
            if(r.ospf && r.dst == dst && r.metric <= metric)
                return;
        routeTable.push_back(Route(dst, nh, false));
        MarkRoutesDirty();
        Route &nr = routeTable.back();
        nr.metric = uint16_t(metric > 65535 ? 65535 : metric);
        nr.dynamic = true;
        nr.ospf = true;
        nr.ospfOrigin = 0;
        nr.learnedFromPort = port;
        nr.expiresAt = 0;
    };

    auto &netsOut = ospfAreaNets[area];
    auto noteNet = [&](const Ipv4Subnet &dst, uint32_t metric) {
        auto it = netsOut.find(dst);
        if(it == netsOut.end() || metric < it->second)
            netsOut[dst] = metric;
    };

    std::set<Ipv4Subnet> intra;

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
        Ipv4Subnet dst(net, prefix);
        uint32_t fr = firstRouter(kv.first);
        Ipv4 nh;
        Port *p = nullptr;
        bool reachable = fr != 0 && neighborInfo(fr, nh, p);
        if(reachable)
            addRoute(dst, dit->second, nh, p);
        if(reachable || fr == 0)
        {
            intra.insert(dst);
            noteNet(dst, dit->second);
        }
    }

    for(const auto &kv : routers)
    {
        auto dit = dist.find(kv.first);
        if(dit == dist.end())
            continue;
        const OspfLsa &rl = *kv.second;
        uint32_t fr = firstRouter(kv.first);
        Ipv4 nh;
        Port *p = nullptr;
        bool reachable = fr != 0 && neighborInfo(fr, nh, p);
        if(!reachable)
            continue;
        for(const OspfRouterLink &l : rl.links)
        {
            if(l.type != 3 || l.data.value == 0)
                continue;
            uint8_t prefix = PrefixFromMask(l.data);
            Ipv4 net(uint32_t(l.id.value & l.data.value));
            Ipv4Subnet dst(net, prefix);
            uint32_t metric = dit->second + l.metric;
            addRoute(dst, metric, nh, p);
            intra.insert(dst);
            noteNet(dst, metric);
        }
    }

    for(const auto &kv : routers)
    {
        const OspfLsa &rl = *kv.second;
        if(rl.header.advRouter.value != ospfRouterId)
            continue;
        auto dit = dist.find(kv.first);
        if(dit == dist.end())
            continue;
        for(const OspfRouterLink &l : rl.links)
        {
            if(l.type != 3 || l.data.value == 0)
                continue;
            uint8_t prefix = PrefixFromMask(l.data);
            Ipv4 net(uint32_t(l.id.value & l.data.value));
            Ipv4Subnet dst(net, prefix);
            intra.insert(dst);
            noteNet(dst, dit->second + l.metric);
        }
    }

    for(const auto &kv : lsas)
    {
        const OspfLsa &sl = kv.second;
        if(sl.header.type != OspfPacket::SummaryLsa ||
           sl.header.advRouter.value == ospfRouterId ||
           sl.header.age >= 3600)
            continue;
        uint8_t prefix = PrefixFromMask(sl.mask);
        if(prefix == 0 && sl.mask.value != 0)
            continue;
        Ipv4 net(uint32_t(sl.header.id.value & sl.mask.value));
        Ipv4Subnet dst(net, prefix);
        if(intra.count(dst))
            continue;
        auto dit = dist.find(rkey(sl.header.advRouter.value));
        if(dit == dist.end())
            continue;
        uint32_t fr = firstRouter(rkey(sl.header.advRouter.value));
        if(fr == 0)
            continue;
        Ipv4 nh;
        Port *p = nullptr;
        if(!neighborInfo(fr, nh, p))
            continue;
        uint32_t metric = dit->second + sl.metric;
        addRoute(dst, metric, nh, p);
        noteNet(dst, metric);
    }

    auto &rdist = ospfAreaRouterDist[area];
    for(const auto &kv : routers)
    {
        uint32_t rid = kv.second->header.advRouter.value;
        auto dit = dist.find(kv.first);
        if(dit != dist.end())
            rdist[rid] = dit->second;
    }

    for(const auto &kv : routers)
    {
        uint32_t rid = kv.second->header.advRouter.value;
        if(rid == ospfRouterId)
            continue;
        auto dit = dist.find(kv.first);
        if(dit == dist.end())
            continue;
        uint32_t fr = firstRouter(kv.first);
        Ipv4 nh;
        Port *p = nullptr;
        if(fr == 0 || !neighborInfo(fr, nh, p))
            continue;
        auto slot = ospfAsbrReach.find(rid);
        if(slot == ospfAsbrReach.end() || dit->second < slot->second.lsa.metric)
        {
            OspfExtLsa reach;
            reach.lsa.header.id = Ipv4(rid);
            reach.lsa.metric = dit->second;
            reach.nextHop = nh;
            reach.port = p;
            ospfAsbrReach[rid] = reach;
        }
    }

    for(const auto &kv : lsas)
    {
        const OspfLsa &sl = kv.second;
        if(sl.header.type != OspfPacket::SummaryAsbrLsa ||
           sl.header.advRouter.value == ospfRouterId ||
           sl.header.age >= 3600)
            continue;
        uint32_t asbr = sl.header.id.value;
        auto dit = dist.find(rkey(sl.header.advRouter.value));
        if(dit == dist.end())
            continue;
        uint32_t fr = firstRouter(rkey(sl.header.advRouter.value));
        Ipv4 nh;
        Port *p = nullptr;
        if(fr == 0 || !neighborInfo(fr, nh, p))
            continue;
        uint32_t metric = dit->second + sl.metric;
        auto slot = ospfAsbrReach.find(asbr);
        if(slot == ospfAsbrReach.end() || metric < slot->second.lsa.metric)
        {
            OspfExtLsa reach;
            reach.lsa.header.id = Ipv4(asbr);
            reach.lsa.metric = metric;
            reach.nextHop = nh;
            reach.port = p;
            ospfAsbrReach[asbr] = reach;
        }
        auto rit = rdist.find(asbr);
        if(rit == rdist.end() || metric < rit->second)
            rdist[asbr] = metric;
    }

    for(const auto &kv : lsas)
    {
        const OspfLsa &sl = kv.second;
        if(sl.header.type != OspfPacket::NssaExternalLsa ||
           sl.header.advRouter.value == ospfRouterId ||
           sl.header.age >= 3600)
            continue;
        uint8_t prefix = PrefixFromMask(sl.mask);
        if(prefix == 0)
            continue;
        auto rit = ospfAsbrReach.find(sl.header.advRouter.value);
        if(rit == ospfAsbrReach.end() || !rit->second.port ||
           rit->second.nextHop.value == 0)
            continue;
        Ipv4 net(uint32_t(sl.header.id.value & sl.mask.value));
        Ipv4Subnet dst(net, prefix);
        if(intra.count(dst))
            continue;
        uint32_t metric = sl.metric & 0x00FFFFFFu;
        bool blocked = false;
        for(const Route &r : routeTable)
        {
            if(!(r.dst == dst))
                continue;
            if(r.direct || (r.ospf && !r.external) ||
               (r.external && r.metric <= metric))
            {
                blocked = true;
                break;
            }
        }
        if(blocked)
            continue;
        routeTable.push_back(Route(dst, rit->second.nextHop, false));
        MarkRoutesDirty();
        Route &nr = routeTable.back();
        nr.metric = uint16_t(metric > 65535 ? 65535 : metric);
        nr.dynamic = true;
        nr.ospf = true;
        nr.external = true;
        nr.learnedFromPort = rit->second.port;
        nr.expiresAt = 0;
    }
}

void Router::OspfOriginateAsbrSummaries()
{
    if(!ospfEnabled)
        return;

    std::set<uint32_t> asbrs;
    for(const auto &kv : ospfExternalLsdb)
        if(kv.second.lsa.header.advRouter.value != ospfRouterId)
            asbrs.insert(kv.second.lsa.header.advRouter.value);

    std::set<uint32_t> areas;
    for(OspfInterface &ifc : ospfIfaces)
        areas.insert(ifc.area.value);
    for(const auto &kv : ospfAreaRouterDist)
        areas.insert(kv.first);

    bool backbone = areas.count(0) != 0;
    std::set<OspfKey> desired;

    for(uint32_t dst : areas)
    {
        auto sit = ospfStubAreas.find(dst);
        if(sit != ospfStubAreas.end() && sit->second)
            continue;
        for(uint32_t asbr : asbrs)
        {
            auto dit = ospfAreaRouterDist.find(dst);
            if(dit != ospfAreaRouterDist.end() &&
               dit->second.count(asbr))
                continue;

            uint32_t best = 0xFFFFFFFFu;
            for(uint32_t src : areas)
            {
                if(src == dst)
                    continue;
                if(backbone && dst != 0 && src != 0)
                    continue;
                if(backbone && dst == 0 && src == 0)
                    continue;
                auto sit = ospfAreaRouterDist.find(src);
                if(sit == ospfAreaRouterDist.end())
                    continue;
                auto rit = sit->second.find(asbr);
                if(rit != sit->second.end() && rit->second < best)
                    best = rit->second;
            }
            if(best == 0xFFFFFFFFu)
                continue;

            OspfLsa s;
            s.header.type = OspfPacket::SummaryAsbrLsa;
            s.header.options = 0x02;
            s.header.id = Ipv4(asbr);
            s.header.advRouter = Ipv4(ospfRouterId);
            s.metric = best;
            s.header.seq = 0x80000001u;

            auto &lsas = ospfLsdb[dst];
            auto key = std::make_tuple(uint8_t(OspfPacket::SummaryAsbrLsa),
                                       asbr, ospfRouterId);
            desired.insert(key);
            auto it = lsas.find(key);
            bool changed = (it == lsas.end()) || it->second.metric != best;
            if(!changed)
                continue;
            if(it != lsas.end())
                s.header.seq = it->second.header.seq + 1;
            lsas[key] = s;
            OspfFlood(dst, s, nullptr);
        }
    }

    for(auto &akv : ospfLsdb)
    {
        uint32_t area = akv.first;
        auto &lsas = akv.second;
        for(auto it = lsas.begin(); it != lsas.end(); )
        {
            const OspfLsa &lsa = it->second;
            if(lsa.header.type == OspfPacket::SummaryAsbrLsa &&
               lsa.header.advRouter.value == ospfRouterId &&
               !desired.count(it->first))
            {
                OspfLsa flush = lsa;
                flush.header.age = 3600;
                flush.header.seq = flush.header.seq + 1;
                OspfFlood(area, flush, nullptr);
                it = lsas.erase(it);
            }
            else
                ++it;
        }
    }
}

void Router::OspfOriginateSummaries()
{
    if(!ospfEnabled)
        return;

    std::set<uint32_t> areas;
    std::map<uint32_t, std::set<Ipv4Subnet>> direct;
    for(OspfInterface &ifc : ospfIfaces)
    {
        areas.insert(ifc.area.value);
        if(!ifc.virtualLink && ifc.port)
            direct[ifc.area.value].insert(ifc.port->subnet);
    }
    for(const auto &kv : ospfAreaNets)
        areas.insert(kv.first);

    bool backbone = areas.count(0) != 0;
    std::map<uint32_t, std::set<OspfKey>> desired;

    for(uint32_t src : areas)
    {
        auto sit = ospfAreaNets.find(src);
        if(sit == ospfAreaNets.end())
            continue;

        std::set<Ipv4Subnet> suppressed;
        std::vector<std::pair<Ipv4Subnet, uint32_t>> aggregates;
        auto shit = ospfSummaries.find(src);
        if(shit != ospfSummaries.end())
        {
            for(const OspfSummary &sum : shit->second)
            {
                bool matched = false;
                uint32_t metric = 0;
                for(const auto &net : sit->second)
                {
                    if(net.first.prefix < sum.dst.prefix ||
                       !sum.dst.Contains(net.first.network))
                        continue;
                    matched = true;
                    suppressed.insert(net.first);
                    if(net.second > metric)
                        metric = net.second;
                }
                if(matched && !sum.notAdvertise)
                    aggregates.push_back({ sum.dst, metric });
            }
        }

        auto advertise = [&](uint32_t dst, const Ipv4Subnet &net,
                             uint32_t metric)
        {
            auto &lsas = ospfLsdb[dst];
            OspfLsa s;
            s.header.type = OspfPacket::SummaryLsa;
            s.header.options = 0x02;
            s.header.id = net.network;
            s.header.advRouter = Ipv4(ospfRouterId);
            s.mask = net.Mask();
            s.metric = metric > 0xFFFFFFu ? 0xFFFFFFu : metric;

            auto key = std::make_tuple(uint8_t(OspfPacket::SummaryLsa),
                                       s.header.id.value, ospfRouterId);
            desired[dst].insert(key);
            auto it = lsas.find(key);
            bool changed = (it == lsas.end()) ||
                           it->second.mask.value != s.mask.value ||
                           it->second.metric != s.metric;
            if(!changed)
                return;
            s.header.seq = (it == lsas.end())
                ? 0x80000001u : (it->second.header.seq + 1);
            lsas[key] = s;
            OspfFlood(dst, s, nullptr);
        };

        for(uint32_t dst : areas)
        {
            if(src == dst)
                continue;
            if(backbone && src != 0 && dst != 0)
                continue;

            for(const auto &net : sit->second)
            {
                if(suppressed.count(net.first) || direct[dst].count(net.first))
                    continue;
                advertise(dst, net.first, net.second);
            }
            for(const auto &agg : aggregates)
            {
                if(!direct[dst].count(agg.first))
                    advertise(dst, agg.first, agg.second);
            }
        }
    }

    std::set<uint32_t> defaultAreas;
    for(const auto &kv : ospfStubAreas)
        if(kv.second)
            defaultAreas.insert(kv.first);
    for(const auto &kv : ospfNssaAreas)
        if(kv.second)
            defaultAreas.insert(kv.first);

    for(uint32_t area : defaultAreas)
    {
        if(!areas.count(area))
            continue;
        bool hasOther = false;
        for(OspfInterface &ifc : ospfIfaces)
        {
            auto sit = ospfStubAreas.find(ifc.area.value);
            auto nit = ospfNssaAreas.find(ifc.area.value);
            bool special = (sit != ospfStubAreas.end() && sit->second) ||
                           (nit != ospfNssaAreas.end() && nit->second);
            if(!special)
            {
                hasOther = true;
                break;
            }
        }
        if(!hasOther)
            continue;

        OspfLsa s;
        s.header.type = OspfPacket::SummaryLsa;
        s.header.options = 0x02;
        s.header.id = Ipv4::Any();
        s.header.advRouter = Ipv4(ospfRouterId);
        s.mask = Ipv4::Any();
        s.metric = 0;

        auto &lsas = ospfLsdb[area];
        auto key = std::make_tuple(uint8_t(OspfPacket::SummaryLsa),
                                   uint32_t(0), ospfRouterId);
        desired[area].insert(key);
        auto it = lsas.find(key);
        bool changed = (it == lsas.end()) ||
                       it->second.mask.value != 0 ||
                       it->second.metric != 0;
        if(!changed)
            continue;
        s.header.seq = (it == lsas.end())
            ? 0x80000001u : (it->second.header.seq + 1);
        lsas[key] = s;
        OspfFlood(area, s, nullptr);
    }

    for(auto &akv : ospfLsdb)
    {
        uint32_t area = akv.first;
        auto &lsas = akv.second;
        for(auto it = lsas.begin(); it != lsas.end(); )
        {
            const OspfLsa &lsa = it->second;
            if(lsa.header.type == OspfPacket::SummaryLsa &&
               lsa.header.advRouter.value == ospfRouterId &&
               !desired[area].count(it->first))
            {
                OspfLsa flush = lsa;
                flush.header.age = 3600;
                flush.header.seq = flush.header.seq + 1;
                OspfFlood(area, flush, nullptr);
                it = lsas.erase(it);
            }
            else
                ++it;
        }
    }
}

