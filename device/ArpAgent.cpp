#include "ArpAgent.hpp"
#include "Port.hpp"
#include "../core/EthernetFrame.hpp"
#include "../core/ARP.hpp"

bool ArpAgent::Lookup(Ipv4 ip, Mac &outMac) const
{
    auto it = cache.find(ip);
    if (it == cache.end())
        return false;

    outMac = it->second;
    return true;
}

void ArpAgent::HandleArp(Port *port, const EthernetFrame &frame)
{
    if (!port)
        return;

    ARP msg;
    if (!ARP::TryFromBytes(frame.payload, msg))
        return;

    if (msg.IsRequest())
    {
        if (port->hasIp && msg.targetIp == port->ip)
        {
            ARP reply = ARP::MakeReply(port->ip, port->mac,
                                       msg.senderIp, msg.senderMac);
            port->Send(EthernetFrame(msg.senderMac, port->mac,
                                     EthernetFrame::kARP, reply.ToBytes()));
        }
    }
    else if (msg.IsReply())
    {
        cache[msg.senderIp] = msg.senderMac;
    }
}

void ArpAgent::SendArpRequest(Ipv4 targetIp, Port *outPort)
{
    if (!outPort)
        return;

    ARP req = ARP::MakeRequest(outPort->ip, outPort->mac, targetIp);
    outPort->Send(EthernetFrame(Mac::Broadcast(), outPort->mac,
                                EthernetFrame::kARP, req.ToBytes()));
}
