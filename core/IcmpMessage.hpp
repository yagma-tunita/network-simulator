#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct IcmpMessage
{
    static constexpr uint8_t kEchoRequest = 8;
    static constexpr uint8_t kEchoReply = 0;
    static constexpr uint8_t kDestUnreachable = 3;
    static constexpr uint8_t kTimeExceeded = 11;

    uint8_t type = kEchoRequest;
    uint8_t code = 0;
    uint16_t id = 0;
    uint16_t seq = 0;
    std::vector<uint8_t> payload;

    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, IcmpMessage &out);
    bool operator==(const IcmpMessage &o) const;
    std::string ToString() const;
};
