#pragma once

#include "Ipv4.hpp"
#include <cstdint>
#include <vector>

struct RipEntry
{
    Ipv4 dst;
    Ipv4 mask;
    uint16_t metric = 16;
};

struct RipMessage
{
    static constexpr uint8_t kRequest = 1;
    static constexpr uint8_t kResponse = 2;

    uint8_t command = kResponse;
    std::vector<RipEntry> entries;

    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, RipMessage &out);
};
