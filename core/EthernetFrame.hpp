#pragma once

#include "Mac.hpp"
#include <cstdint>
#include <vector>
#include <string>

struct EthernetFrame
{
    static constexpr uint16_t kIPv4 = 0x0800;
    static constexpr uint16_t kARP  = 0x0806;

    Mac dst;
    Mac src;
    uint16_t type = 0;
    std::vector<uint8_t> payload;

    bool operator==(const EthernetFrame &e)const;
    bool IsBroadcast() const;
    std::string ToString() const;

    EthernetFrame() = default;
    EthernetFrame(Mac dst, Mac src, uint16_t type, std::vector<uint8_t> payload);
};