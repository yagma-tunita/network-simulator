#include "Router.hpp"
#include "Port.hpp"
#include "../core/ARP.hpp"

void Router::OnFrame(Port *port, const EthernetFrame &frame)
{
    if(port->mac != frame.dst && !frame.IsBroadcast()) return;
    if(frame.type != EthernetFrame::kIPv4) return;

    IpPacket pkt;
    if(!IpPacket::TryFromBytes(frame.payload, pkt)) return;
    if(IsMyIp(pkt.dstIp)) return;

    if(pkt.ttl <= 1) return;
    pkt.DecTtl();

}

bool Router::IsMyIp(Ipv4 ip) const
{
    for(const Port *p : portList)
    {
        if(p->hasIp && p->ip==ip) return true;
    }
    
    return false;
}
