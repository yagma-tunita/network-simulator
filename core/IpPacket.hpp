#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include "Ipv4.hpp"

struct IpPacket
{
    static constexpr uint8_t kDefaultTtl = 64;
    static constexpr size_t  kHeaderSize = 20;
    static constexpr uint8_t kIcmp = 1;
    static constexpr uint8_t kTcp = 6;
    static constexpr uint8_t kUdp = 17;
    static constexpr uint8_t kOspf = 89;

    uint8_t ttl = kDefaultTtl;
    uint8_t protocol = 0;
    uint8_t ecn = 0;
    uint16_t identification = 0;
    bool dontFragment = false;
    bool moreFragments = false;
    uint16_t fragmentOffset = 0;
    Ipv4 srcIp;
    Ipv4 dstIp;
    std::vector<uint8_t>payload;

    bool operator==(const IpPacket &o)const;
    std::string ToString() const;

    void DecTtl();
    bool IsFragment() const { return moreFragments || fragmentOffset != 0; }
    std::vector<uint8_t>ToBytes()const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, IpPacket &out);

    IpPacket() = default;
    IpPacket(Ipv4 src, Ipv4 dst, uint8_t proto, std::vector<uint8_t> data);
};
