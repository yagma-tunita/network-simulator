#include "../Router.hpp"
#include "../Port.hpp"
#include "../../link/Link.hpp"
#include "../../core/TcpSegment.hpp"
#include "../../engine/Clock.hpp"
#include "../../engine/Scheduler.hpp"
#include "../../engine/Event.hpp"
#include <memory>
#include <algorithm>
#include <cstddef>
#include <vector>

namespace
{
    struct BgpKeepaliveEvent : Event
    {
        Router *router;
        Router::BgpSession *session;
        uint64_t routerGen;
        uint64_t keepGen;

        BgpKeepaliveEvent(Router *r, Router::BgpSession *s,
                          uint64_t rg, uint64_t kg)
            : router(r), session(s), routerGen(rg), keepGen(kg) {}

        void Execute(Engine &) override
        {
            if(router->bgpGen != routerGen)
                return;
            router->BgpKeepaliveTick(*session, keepGen);
        }
        const char *Name() const override { return "bgp-keepalive"; }
    };

    struct BgpReconnectEvent : Event
    {
        Router *router;
        Router::BgpSession *session;
        uint64_t routerGen;
        uint64_t reconnectGen;

        BgpReconnectEvent(Router *r, Router::BgpSession *s,
                          uint64_t rg, uint64_t cg)
            : router(r), session(s), routerGen(rg), reconnectGen(cg) {}

        void Execute(Engine &) override
        {
            if(router->bgpGen != routerGen)
                return;
            router->BgpReconnectTick(*session, reconnectGen);
        }
        const char *Name() const override { return "bgp-reconnect"; }
    };
}

void Router::BgpStart()
{
    BgpStop();
    if(!bgpEnabled)
        return;
    if(bgpRouterId == Ipv4::Any())
        bgpRouterId = Ipv4(ComputeOspfRouterId());

    for(Port *p : portList)
    {
        if(!p->hasIp)
            continue;
        bgpSessions.emplace_back();
        BgpSession &s = bgpSessions.back();
        s.listener = true;
        s.localIp = p->ip;
        BgpSetupSession(s);
        s.conn.Listen(p->ip, 179);
    }

    for(const auto &kv : bgpNeighbors)
    {
        Ipv4 peer = kv.first;
        auto shut = bgpShutdown.find(peer);
        if(shut != bgpShutdown.end() && shut->second)
            continue;
        const Route *r = FindRoute(peer);
        if(!r)
            continue;
        Ipv4 nextHop = r->direct ? peer : r->nextHop;
        Port *egress = PortForNextHop(nextHop);
        if(!egress || egress->ip.value >= peer.value)
            continue;

        bgpSessions.emplace_back();
        BgpSession &s = bgpSessions.back();
        s.listener = false;
        s.localIp = egress->ip;
        s.peerIp = peer;
        s.remoteAs = kv.second;
        BgpSetupSession(s);
        s.conn.OpenActive(egress->ip, 179, peer, 179);
    }
    BgpSelect();
}

void Router::BgpStop()
{
    ++bgpGen;
    for(BgpSession &s : bgpSessions)
        s.conn.Abort();
    bgpSessions.clear();
    routeTable.erase(std::remove_if(routeTable.begin(), routeTable.end(),
                     [](const Route &r) { return r.bgp; }),
                     routeTable.end());
    MarkRoutesDirty();
}

void Router::BgpScheduleKeepalive(BgpSession &s)
{
    if(!scheduler || !bgpEnabled)
        return;
    uint64_t gen = ++s.keepGen;
    scheduler->ScheduleAfter(30,
        std::make_unique<BgpKeepaliveEvent>(this, &s, bgpGen, gen));
}

void Router::BgpKeepaliveTick(BgpSession &s, uint64_t gen)
{
    if(!bgpEnabled || gen != s.keepGen)
        return;
    if(s.state == 0)
        return;

    uint64_t now = clock ? clock->Now() : 0;
    if(now - s.lastRx > 90)
    {
        s.state = 0;
        s.conn.Abort();
        BgpWithdrawPeer(s.peerIp);
        BgpScheduleReconnect(s);
        return;
    }

    if(s.state == 3)
    {
        BgpMessage keep;
        keep.type = BgpMessage::Keepalive;
        BgpSend(s, keep);
    }
    BgpScheduleKeepalive(s);
}

void Router::BgpScheduleReconnect(BgpSession &s)
{
    if(!scheduler || !bgpEnabled)
        return;
    uint64_t gen = ++s.reconnectGen;
    scheduler->ScheduleAfter(30,
        std::make_unique<BgpReconnectEvent>(this, &s, bgpGen, gen));
}

void Router::BgpReconnectTick(BgpSession &s, uint64_t gen)
{
    if(!bgpEnabled || gen != s.reconnectGen || s.state != 0)
        return;
    s.rx.clear();
    s.sentUpdates = false;
    if(s.listener)
        s.conn.Listen(s.localIp, 179);
    else
        s.conn.OpenActive(s.localIp, 179, s.peerIp, 179);
}

void Router::BgpSetupSession(BgpSession &s)
{
    s.conn.SetScheduler(scheduler);
    s.lastRx = clock ? clock->Now() : 0;
    s.conn.out = [this, &s](const TcpSegment &seg) {
        SendBgpTcpSegment(s.conn, seg);
    };
    s.conn.onConnected = [this, &s]() { BgpOnConnected(s); };
    s.conn.onData = [this, &s](const std::vector<uint8_t> &data) {
        BgpOnData(s, data);
    };
    s.conn.onReset = [this, &s]() {
        s.state = 0;
        s.rx.clear();
        s.sentUpdates = false;
        if(!(s.peerIp == Ipv4::Any()))
            BgpWithdrawPeer(s.peerIp);
        BgpScheduleReconnect(s);
    };
}

void Router::BgpSend(BgpSession &s, const BgpMessage &msg)
{
    s.conn.SendData(msg.ToBytes());
}

void Router::BgpOnConnected(BgpSession &s)
{
    if(s.listener)
    {
        auto it = bgpNeighbors.find(s.conn.remoteIp);
        if(it == bgpNeighbors.end())
        {
            s.conn.Abort();
            s.state = 0;
            BgpScheduleReconnect(s);
            return;
        }
        auto shut = bgpShutdown.find(s.conn.remoteIp);
        if(shut != bgpShutdown.end() && shut->second)
        {
            s.conn.Abort();
            s.state = 0;
            BgpScheduleReconnect(s);
            return;
        }
        s.peerIp = s.conn.remoteIp;
        s.remoteAs = it->second;
    }

    s.lastRx = clock ? clock->Now() : 0;
    s.state = 1;
    BgpMessage open;
    open.type = BgpMessage::Open;
    open.version = 4;
    open.myAs = bgpLocalAs;
    open.holdTime = 90;
    open.bgpId = bgpRouterId;
    BgpSend(s, open);
    BgpScheduleKeepalive(s);
}

void Router::BgpOnData(BgpSession &s, const std::vector<uint8_t> &data)
{
    s.lastRx = clock ? clock->Now() : 0;
    s.rx.insert(s.rx.end(), data.begin(), data.end());
    while(s.rx.size() >= BgpMessage::kHeaderSize)
    {
        uint16_t length = uint16_t((uint16_t(s.rx[16]) << 8) | s.rx[17]);
        if(length < BgpMessage::kHeaderSize || length > BgpMessage::kMaxLength)
        {
            s.conn.Abort();
            s.state = 0;
            return;
        }
        if(s.rx.size() < length)
            return;
        std::vector<uint8_t> frame(s.rx.begin(),
                                   s.rx.begin() + std::ptrdiff_t(length));
        s.rx.erase(s.rx.begin(), s.rx.begin() + std::ptrdiff_t(length));
        BgpMessage msg;
        if(!BgpMessage::TryFromBytes(frame, msg))
        {
            s.conn.Abort();
            s.state = 0;
            return;
        }
        BgpHandle(s, msg);
    }
}

void Router::BgpHandle(BgpSession &s, const BgpMessage &msg)
{
    if(msg.type == BgpMessage::Open)
    {
        if(msg.version != 4 ||
           (s.remoteAs != 0 && msg.myAs != s.remoteAs))
        {
            s.conn.Abort();
            s.state = 0;
            return;
        }
        s.state = 2;
        BgpMessage keep;
        keep.type = BgpMessage::Keepalive;
        BgpSend(s, keep);
        return;
    }

    if(msg.type == BgpMessage::Keepalive)
    {
        if(s.state < 1)
            return;
        bool first = s.state < 3;
        s.state = 3;
        if(!first || s.sentUpdates)
            return;
        s.sentUpdates = true;
        for(const Ipv4Subnet &prefix : bgpNetworks)
        {
            auto fit = bgpOutFilters.find(s.peerIp);
            if(fit != bgpOutFilters.end() &&
               !BgpFilterAllows(fit->second, prefix))
                continue;
            BgpMessage u;
            u.type = BgpMessage::Update;
            u.origin = 0;
            u.asPath = { bgpLocalAs };
            auto pit = bgpPrependOut.find(prefix);
            if(pit != bgpPrependOut.end())
                for(uint8_t i = 0; i < pit->second; ++i)
                    u.asPath.push_back(bgpLocalAs);
            u.nextHop = s.conn.localIp;
            auto mit = bgpMedOut.find(prefix);
            if(mit != bgpMedOut.end())
            {
                u.hasMed = true;
                u.med = mit->second;
            }
            auto cit = bgpCommunitiesOut.find(prefix);
            if(cit != bgpCommunitiesOut.end())
                u.communities = cit->second;
            u.nlri.push_back(prefix);
            BgpSend(s, u);
        }
        return;
    }

    if(msg.type == BgpMessage::Update)
    {
        for(const Ipv4Subnet &prefix : msg.withdrawn)
            BgpWithdraw(s.peerIp, prefix);
        for(const Ipv4Subnet &prefix : msg.nlri)
        {
            auto fit = bgpInFilters.find(s.peerIp);
            if(fit != bgpInFilters.end() &&
               !BgpFilterAllows(fit->second, prefix))
                continue;
            auto ait = bgpInAsFilters.find(s.peerIp);
            if(ait != bgpInAsFilters.end() &&
               !BgpAsFilterAllows(ait->second, msg.asPath))
                continue;
            auto cfit = bgpCommunityFilters.find(s.peerIp);
            if(cfit != bgpCommunityFilters.end() &&
               !BgpCommunityFilterAllows(cfit->second, msg.communities))
                continue;
            auto mitLimit = bgpMaxPrefix.find(s.peerIp);
            if(mitLimit != bgpMaxPrefix.end() && mitLimit->second > 0)
            {
                std::size_t count = 0;
                bool exists = false;
                for(const BgpPath &p : bgpPaths)
                    if(p.peer == s.peerIp)
                    {
                        ++count;
                        if(p.prefix == prefix)
                            exists = true;
                    }
                if(!exists && count >= mitLimit->second)
                    continue;
            }
            BgpPath p;
            p.prefix = prefix;
            p.peer = s.peerIp;
            p.nextHop = msg.nextHop == Ipv4::Any() ? s.peerIp : msg.nextHop;
            p.asPath = msg.asPath;
            p.receivedLocalPref = msg.hasLocalPref ? msg.localPref : 100;
            auto pit = bgpLocalPrefIn.find(s.peerIp);
            p.localPref = pit != bgpLocalPrefIn.end()
                ? pit->second : p.receivedLocalPref;
            p.med = msg.hasMed ? msg.med : 0;
            p.origin = msg.origin;
            p.routerId = s.peerIp;
            p.ebgp = !msg.asPath.empty() && msg.asPath.front() != bgpLocalAs;
            p.communities = msg.communities;
            BgpAddPath(p);
        }
        return;
    }

    if(msg.type == BgpMessage::Notification)
    {
        s.conn.Abort();
        s.state = 0;
        BgpWithdrawPeer(s.peerIp);
        BgpScheduleReconnect(s);
    }
}

void Router::SendBgpTcpSegment(TcpConnection &conn, const TcpSegment &seg)
{
    const Route *r = FindRoute(conn.remoteIp);
    if(!r)
        return;
    Ipv4 nextHop = r->direct ? conn.remoteIp : r->nextHop;
    Port *egress = PortForNextHop(nextHop);
    if(!egress)
        return;

    Mac dstMac;
    if(!arp.Lookup(nextHop, dstMac))
    {
        arp.SendArpRequest(nextHop, egress);
        return;
    }

    std::vector<uint8_t> bytes = seg.ToBytes(conn.localIp, conn.remoteIp);
    IpPacket pkt(conn.localIp, conn.remoteIp, IpPacket::kTcp, bytes);
    pkt.ttl = 64;
    egress->Send(std::make_shared<const EthernetFrame>(
        dstMac, egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
}

void Router::HandleBgpTcp(Port *port, const IpPacket &pkt, const Mac &srcMac)
{
    (void)port;
    (void)srcMac;
    TcpSegment seg;
    if(!TcpSegment::TryFromBytes(pkt.payload, seg, pkt.srcIp, pkt.dstIp))
        return;

    for(BgpSession &s : bgpSessions)
    {
        TcpConnection &c = s.conn;
        bool match;
        if(s.listener)
            match = c.localIp == pkt.dstIp && c.localPort == seg.dstPort &&
                    (c.state == TcpConnection::Listening ||
                     (c.remoteIp == pkt.srcIp &&
                      c.remotePort == seg.srcPort));
        else
            match = c.state != TcpConnection::Closed &&
                    c.localPort == seg.dstPort &&
                    c.remoteIp == pkt.srcIp &&
                    c.remotePort == seg.srcPort;
        if(match)
        {
            c.OnSegment(seg, pkt.srcIp, pkt.ecn);
            return;
        }
    }
}

