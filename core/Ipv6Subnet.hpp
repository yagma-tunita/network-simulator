#pragma once

#include "Ipv6.hpp"
#include <cstdint>
#include <string>

struct Ipv6Subnet
{
    Ipv6 network;
    uint8_t prefix = 0;

    Ipv6 Mask() const;
    bool Contains(const Ipv6 &ip) const;
    std::string ToString() const;
    bool operator==(const Ipv6Subnet &o) const;
    bool operator<(const Ipv6Subnet &o) const;

    static bool TryParse(const std::string &s, Ipv6Subnet &out);

    Ipv6Subnet() = default;
    Ipv6Subnet(const Ipv6 &ip, uint8_t prefix);
};
