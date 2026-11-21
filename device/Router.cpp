#include "Router.hpp"
#include "Port.hpp"
#include "../core/IpPacket.hpp"

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

void Router::OnFrame(Port *port, const EthernetFrame &frame)
{
    if (!port)
        return;

    if (port->mac != frame.dst && !frame.IsBroadcast())
        return;

    if (frame.type == EthernetFrame::kARP)
    {
        arp.HandleArp(port, frame);
        return;
    }


    if (frame.type != EthernetFrame::kIPv4)
        return;

    IpPacket pkt;
    if (!IpPacket::TryFromBytes(frame.payload, pkt))
        return;


    if (IsMyIp(pkt.dstIp))
        return;


    if (pkt.ttl <= 1)
        return;
    pkt.DecTtl();


    const Route *r = FindRoute(pkt.dstIp);
    if (!r)
        return;


    Ipv4 nextIp = r->direct ? pkt.dstIp : r->nextHop;


    Port *egress = PortForNextHop(nextIp);
    if (!egress)
        return;


    Mac nextMac;
    if (!arp.Lookup(nextIp, nextMac))
    {
        arp.SendArpRequest(nextIp, egress);
        return;
    }


    EthernetFrame out(nextMac, egress->mac, EthernetFrame::kIPv4, pkt.ToBytes());
    egress->Send(out);
}
