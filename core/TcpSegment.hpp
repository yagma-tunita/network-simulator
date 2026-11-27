#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include "Ipv4.hpp"

struct TcpSegment
{
    static constexpr uint8_t kFin = 0x01;
    static constexpr uint8_t kSyn = 0x02;
    static constexpr uint8_t kRst = 0x04;
    static constexpr uint8_t kPsh = 0x08;
    static constexpr uint8_t kAck = 0x10;
    static constexpr uint8_t kEce = 0x40;
    static constexpr uint8_t kCwr = 0x80;
    static constexpr std::size_t kHeaderSize = 20;
    static constexpr std::size_t kMaxOptions = 40;

    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t flags = 0;
    uint16_t window = 64240;
    std::vector<uint8_t> options;
    std::vector<uint8_t> payload;
    uint8_t ecn = 0;

    bool operator==(const TcpSegment &o) const;

    std::vector<uint8_t> ToBytes() const;
    std::vector<uint8_t> ToBytes(const Ipv4 &src, const Ipv4 &dst) const;
    uint16_t ComputeChecksum(const Ipv4 &src, const Ipv4 &dst) const;

    static bool TryFromBytes(const std::vector<uint8_t> &buf, TcpSegment &out);
    static bool TryFromBytes(const std::vector<uint8_t> &buf, TcpSegment &out,
                             const Ipv4 &src, const Ipv4 &dst);
};
