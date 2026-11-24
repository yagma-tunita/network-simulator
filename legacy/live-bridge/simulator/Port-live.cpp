#include "Port.hpp"
#include "../link/Link.hpp"
#include "Device.hpp"
#include <utility>

void Port::Send(FramePtr frame)
{
    ++tx;
    if(bridge)
    {
        bridge(std::move(frame));
        return;
    }
    if(!link) return;
    link->Transmit(this, std::move(frame));
}

void Port::Receive(FramePtr frame)
{
    ++rx;
    if(!owner) return;
    owner->OnFrame(this, std::move(frame));
}

void Port::SetIp(Ipv4 newip, uint8_t prefix)
{
    ip = newip;
    subnet = Ipv4Subnet(newip, prefix);
    hasIp = true;
}

void Port::Attach(Link *l){ link = l;}

Port::Port(Mac mac, Device *owner, Ipv4 newip, uint8_t prefix, Link *l)
    :mac(mac), owner(owner)
{
    SetIp(newip, prefix);
    Attach(l);
}
