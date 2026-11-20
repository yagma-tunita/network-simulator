#pragma once

#include "Ipv4.hpp"
#include <cstdint>
#include <string>

struct Ipv4Subnet
{
    Ipv4 network;
    uint8_t prefix = 0;

    bool operator==(const Ipv4Subnet &o) const;
    bool operator<(const Ipv4Subnet &o) const;
    std::string ToString() const;

    Ipv4 Mask() const;
    Ipv4 Broadcast() const;
    bool Contains(const Ipv4 &ip) const;
    static bool TryParse(const std::string &s, Ipv4Subnet &out);

    Ipv4Subnet() = default;
    Ipv4Subnet(const Ipv4 &network, uint8_t prefix);
    Ipv4Subnet(const std::string &s);
};
