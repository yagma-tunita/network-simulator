#include "Port.hpp"
#include "Link.hpp"
#include "Device.hpp"

void Port::Send(const EthernetFrame &frame)
{
    if(!link) return;
    link->Transmit(this, frame);
}

void Port::Receive(const EthernetFrame &frame)
{
    if(!owner) return;
    owner->OnFrame(this, frame);
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
