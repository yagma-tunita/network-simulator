#pragma once

#include "../core/Mac.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>

struct StpBpdu
{
    static constexpr uint16_t kProtocolId = 0x0000;
    static constexpr uint8_t  kVersion = 0x00;
    static constexpr uint8_t  kRstpVersion = 0x02;
    static constexpr uint8_t  kConfig = 0x00;
    static constexpr std::size_t kSize = 35;

    uint8_t version = kVersion;
    uint8_t flags = 0;
    uint16_t rootPriority = 0;
    Mac rootMac;
    uint32_t rootPathCost = 0;
    uint16_t bridgePriority = 0;
    Mac bridgeMac;
    uint16_t portId = 0;
    uint16_t messageAge = 0;
    uint16_t maxAge = 20;
    uint16_t helloTime = 2;
    uint16_t forwardDelay = 15;

    bool operator==(const StpBpdu &o) const;

    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, StpBpdu &out);
    static Mac Multicast();
};
