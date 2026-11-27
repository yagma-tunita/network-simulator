#pragma once

#include "Ipv6.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

struct Ipv6Packet
{
    static constexpr std::size_t kHeaderSize = 40;
    static constexpr uint8_t kHopLimit = 64;

    uint8_t trafficClass = 0;
    uint32_t flowLabel = 0;
    uint8_t nextHeader = 0;
    uint8_t hopLimit = kHopLimit;
    Ipv6 srcIp;
    Ipv6 dstIp;
    std::vector<uint8_t> payload;

    bool operator==(const Ipv6Packet &o) const;
    std::string ToString() const;
    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, Ipv6Packet &out);

    Ipv6Packet() = default;
    Ipv6Packet(Ipv6 src, Ipv6 dst, uint8_t proto, std::vector<uint8_t> data);
};
