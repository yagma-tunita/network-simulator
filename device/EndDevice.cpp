#include "EndDevice.hpp"
#include "Port.hpp"
#include "../core/ARP.hpp"

void EndDevice::OnFrame(Port *port, const EthernetFrame &frame)
{
    if((port->mac != frame.dst) && !frame.IsBroadcast()) return;
    if(frame.type == frame.kARP) HandleArp(port, frame);
    else if(frame.type == frame.kIPv4) return;
}

void EndDevice::SendArpRequest(Ipv4 targetIp)
{
    Port *chosen = nullptr;
    for(Port* p : portList)
    {
        if(p->hasIp && p->subnet.Contains(targetIp))
        {
            chosen = p;
            break;
        }
    }

    if(chosen == nullptr)return;

    ARP req =ARP::MakeRequest(chosen->ip, chosen->mac, targetIp);
    EthernetFrame out(Mac::Broadcast(), chosen->mac, EthernetFrame::kARP, req.ToBytes());

    chosen->Send(out);
}

void EndDevice::HandleArp(Port *port, const EthernetFrame &frame)
{
    ARP arp;
    bool lac = ARP::TryFromBytes(frame.payload,arp);
    if(!lac) return;

    if(arp.IsRequest())
    {
        if(port->hasIp && (arp.targetIp == port->ip))
        {
            ARP reply = ARP::MakeReply(port->ip, port->mac, arp.senderIp, arp.senderMac);
            EthernetFrame out(arp.senderMac, port->mac, EthernetFrame::kARP,reply.ToBytes());
            port->Send(out);
        }
    }

    if(arp.IsReply()) arpCache[arp.senderIp] = arp.senderMac;
}

bool EndDevice::Lookup(Ipv4 ip, Mac &outMac)
{
    auto it = arpCache.find(ip);

    if(it == arpCache.end()) return false;

    outMac = it->second;
    return true;
}
