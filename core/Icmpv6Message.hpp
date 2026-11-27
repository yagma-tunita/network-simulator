#pragma once

#include "Ipv6.hpp"
#include "Mac.hpp"
#include <cstdint>
#include <string>
#include <vector>

struct Icmpv6Message
{
    static constexpr uint8_t kEchoRequest = 128;
    static constexpr uint8_t kEchoReply = 129;
    static constexpr uint8_t kDestUnreachable = 1;
    static constexpr uint8_t kPacketTooBig = 2;
    static constexpr uint8_t kTimeExceeded = 3;
    static constexpr uint8_t kNeighborSolicit = 135;
    static constexpr uint8_t kNeighborAdvert = 136;
    static constexpr uint8_t kNextHeader = 58;

    uint8_t type = kEchoRequest;
    uint8_t code = 0;
    uint16_t id = 0;
    uint16_t seq = 0;
    uint32_t ndFlags = 0;
    Ipv6 target;
    std::vector<uint8_t> options;
    std::vector<uint8_t> payload;

    std::vector<uint8_t> ToBytes(const Ipv6 &src, const Ipv6 &dst) const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf,
                             const Ipv6 &src, const Ipv6 &dst,
                             Icmpv6Message &out);
    bool operator==(const Icmpv6Message &o) const;
};

std::vector<uint8_t> NdpLinkLayerOption(uint8_t type, const Mac &mac);
bool NdpParseLinkLayerOption(const std::vector<uint8_t> &options,
                             uint8_t type, Mac &mac);
Ipv6 NdpSolicitedNode(const Ipv6 &target);
Mac NdpSolicitedMac(const Ipv6 &target);
