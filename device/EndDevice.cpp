#include "EndDevice.hpp"
#include "Port.hpp"

void EndDevice::OnFrame(Port *port, const EthernetFrame &frame)
{
    if (!port)
        return;


    if ((port->mac != frame.dst) && !frame.IsBroadcast())
        return;

    if (frame.type == EthernetFrame::kARP)
        arp.HandleArp(port, frame);
    else if (frame.type == EthernetFrame::kIPv4)
        return;
}

void EndDevice::SendArpRequest(Ipv4 targetIp)
{

    Port *chosen = nullptr;
    for (Port *p : portList)
    {
        if (p->hasIp && p->subnet.Contains(targetIp))
        {
            chosen = p;
            break;
        }
    }

    arp.SendArpRequest(targetIp, chosen);
}

bool EndDevice::Lookup(Ipv4 ip, Mac &outMac)
{
    return arp.Lookup(ip, outMac);
}
