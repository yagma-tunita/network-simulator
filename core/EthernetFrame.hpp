#pragma once

#include "Mac.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <memory>

struct EthernetFrame
{
    static constexpr uint16_t kIPv4 = 0x0800;
    static constexpr uint16_t kIPv6 = 0x86DD;
    static constexpr uint16_t kARP  = 0x0806;
    static constexpr uint16_t kLLDP = 0x88CC;
    static constexpr uint16_t kVlanTpid = 0x8100;
    static constexpr uint16_t kSTP  = 0x8E01;

    Mac dst;
    Mac src;
    uint16_t type = 0;
    std::vector<uint8_t> payload;

    bool hasVlanTag = false;
    uint16_t vlanId = 0;
    uint8_t vlanPcp = 0;
    bool vlanDei = false;

    bool HasVlan() const { return hasVlanTag; }
    uint16_t VlanId() const { return vlanId; }
    uint16_t Tci() const;

    EthernetFrame WithVlan(uint16_t vid, uint8_t pcp = 0, bool dei = false) const;
    EthernetFrame WithoutVlan() const;

    bool operator==(const EthernetFrame &e)const;
    bool IsBroadcast() const;
    std::string ToString() const;

    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const uint8_t *data, std::size_t len, EthernetFrame &out);
    static bool TryFromBytes(const std::vector<uint8_t> &data, EthernetFrame &out);

    EthernetFrame() = default;
    EthernetFrame(Mac dst, Mac src, uint16_t type, std::vector<uint8_t> payload);
};

using FramePtr = std::shared_ptr<const EthernetFrame>;
