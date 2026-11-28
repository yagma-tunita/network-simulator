#pragma once

#include "Mac.hpp"
#include <cstdint>
#include <string>
#include <vector>

struct LldpFrame
{
    Mac chassis;
    std::string portId;
    uint16_t ttl = 120;
    std::string systemName;

    static constexpr uint16_t kEtherType = 0x88CC;

    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, LldpFrame &out);
    bool operator==(const LldpFrame &o) const;

    static Mac Multicast();
};
