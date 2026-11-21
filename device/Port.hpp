#pragma once

#include "../core/Mac.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/EthernetFrame.hpp"
#include <cstdint>

struct Link;
struct Device;

struct Port
{
    Mac mac;
    bool hasIp = false;
    Ipv4 ip;
    Ipv4Subnet subnet;

    Link *link = nullptr;
    Device *owner = nullptr;

    void Send(const EthernetFrame &frame);
    void Receive(const EthernetFrame &frame);

    void SetIp(Ipv4 newip, uint8_t prefix);
    void Attach(Link *l);

    Port() = default;
    Port(Mac mac, Device *owner, Ipv4 newip, uint8_t prefix, Link *l);
};
