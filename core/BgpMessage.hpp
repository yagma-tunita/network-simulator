#pragma once

#include "Ipv4.hpp"
#include "Ipv4Subnet.hpp"
#include <cstdint>
#include <string>
#include <vector>

struct BgpMessage
{
    enum Type : uint8_t
    {
        Open = 1,
        Update = 2,
        Notification = 3,
        Keepalive = 4
    };

    uint8_t type = Keepalive;

    uint8_t version = 4;
    uint16_t myAs = 0;
    uint16_t holdTime = 0;
    Ipv4 bgpId;

    uint8_t errorCode = 0;
    uint8_t errorSubcode = 0;
    std::vector<uint8_t> data;

    std::vector<Ipv4Subnet> withdrawn;
    std::vector<Ipv4Subnet> nlri;
    uint8_t origin = 0;
    std::vector<uint16_t> asPath;
    Ipv4 nextHop;
    bool hasLocalPref = false;
    uint32_t localPref = 0;
    bool hasMed = false;
    uint32_t med = 0;

    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, BgpMessage &out);
    bool operator==(const BgpMessage &o) const;
    std::string ToString() const;

    static constexpr std::size_t kHeaderSize = 19;
    static constexpr std::size_t kMaxLength = 4096;
};
