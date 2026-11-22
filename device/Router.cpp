#include "Router.hpp"
#include "Port.hpp"
#include "../core/IcmpMessage.hpp"
#include "../engine/Clock.hpp"
#include <memory>
#include <algorithm>
#include <cstddef>
#include <vector>

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
            if (!best || r.dst.prefix > best->dst.prefix)
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

void Router::OnFrame(Port *port, FramePtr frame)
{
    if(!port) return;

    if((port->mac != frame->dst) && !frame->IsBroadcast()) return;

    if(frame->type == EthernetFrame::kARP)
    {
        arp.HandleArp(port, *frame);
        FlushPending();
        return;
    }

    if(frame->type != EthernetFrame::kIPv4) return;

    IpPacket pkt;
    if(!IpPacket::TryFromBytes(frame->payload, pkt)) return;

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
