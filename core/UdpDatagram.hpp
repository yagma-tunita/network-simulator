#pragma once

#include <cstdint>
#include <vector>

struct UdpDatagram
{
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    std::vector<uint8_t> payload;

    bool operator==(const UdpDatagram &o) const;
    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, UdpDatagram &out);
};
