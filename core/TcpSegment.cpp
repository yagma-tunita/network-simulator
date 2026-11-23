#include "TcpSegment.hpp"
#include "ByteIO.hpp"
#include <stdexcept>

using namespace ByteIO;

namespace
{
    uint32_t SumBytes(uint32_t sum, const uint8_t *data, std::size_t len)
    {
        std::size_t i = 0;
        for(; i + 1 < len; i += 2)
            sum += (uint32_t(data[i]) << 8) | uint32_t(data[i + 1]);
        if(i < len)
            sum += uint32_t(data[i]) << 8;
        return sum;
    }

    uint16_t Fold(uint32_t sum)
    {
        while(sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return uint16_t(~sum & 0xFFFF);
    }
}

bool TcpSegment::operator==(const TcpSegment &o) const
{
    return srcPort == o.srcPort && dstPort == o.dstPort && seq == o.seq &&
           ack == o.ack && flags == o.flags && window == o.window &&
           options == o.options && payload == o.payload;
}

std::vector<uint8_t> TcpSegment::ToBytes() const
{
    std::vector<uint8_t> opts = options;
    if(opts.size() > kMaxOptions)
        throw std::length_error("TcpSegment: options too large");
    while(opts.size() % 4 != 0)
        opts.push_back(0);

    std::size_t headerLen = kHeaderSize + opts.size();

    std::vector<uint8_t> buf;
    buf.reserve(headerLen + payload.size());

    AppendU16(buf, srcPort);
    AppendU16(buf, dstPort);
    AppendU32(buf, seq);
    AppendU32(buf, ack);
    AppendU8(buf, uint8_t((headerLen / 4) << 4));
    AppendU8(buf, flags);
    AppendU16(buf, window);
    AppendU16(buf, 0);
    AppendU16(buf, 0);

    for(uint8_t b : opts)
        buf.push_back(b);

    for(uint8_t b : payload)
        buf.push_back(b);

    return buf;
}

uint16_t TcpSegment::ComputeChecksum(const Ipv4 &src, const Ipv4 &dst) const
{
    std::vector<uint8_t> seg = ToBytes();

    uint8_t s[4] = {
        uint8_t((src.value >> 24) & 0xFF), uint8_t((src.value >> 16) & 0xFF),
        uint8_t((src.value >> 8) & 0xFF),  uint8_t(src.value & 0xFF)
    };
    uint8_t d[4] = {
        uint8_t((dst.value >> 24) & 0xFF), uint8_t((dst.value >> 16) & 0xFF),
        uint8_t((dst.value >> 8) & 0xFF),  uint8_t(dst.value & 0xFF)
    };

    uint32_t sum = 0;
    sum += (uint32_t(s[0]) << 8) | uint32_t(s[1]);
    sum += (uint32_t(s[2]) << 8) | uint32_t(s[3]);
    sum += (uint32_t(d[0]) << 8) | uint32_t(d[1]);
    sum += (uint32_t(d[2]) << 8) | uint32_t(d[3]);
    sum += 6;
    sum += uint32_t(seg.size());
    sum = SumBytes(sum, seg.data(), seg.size());
    return Fold(sum);
}

std::vector<uint8_t> TcpSegment::ToBytes(const Ipv4 &src, const Ipv4 &dst) const
{
    std::vector<uint8_t> buf = ToBytes();
    uint16_t cks = ComputeChecksum(src, dst);
    buf[16] = uint8_t((cks >> 8) & 0xFF);
    buf[17] = uint8_t(cks & 0xFF);
    return buf;
}

bool TcpSegment::TryFromBytes(const std::vector<uint8_t> &buf, TcpSegment &out)
{
    if(buf.size() < kHeaderSize)
        return false;

    uint8_t offset = uint8_t((buf[12] >> 4) & 0x0F);
    if(offset < 5 || offset > 15)
        return false;
    std::size_t headerLen = std::size_t(offset) * 4;
    if(headerLen > buf.size())
        return false;

    out.srcPort = ReadU16(buf, 0);
    out.dstPort = ReadU16(buf, 2);
    out.seq = ReadU32(buf, 4);
    out.ack = ReadU32(buf, 8);
    out.flags = buf[13];
    out.window = ReadU16(buf, 14);
    out.options.assign(buf.begin() + std::ptrdiff_t(kHeaderSize),
                       buf.begin() + std::ptrdiff_t(headerLen));
    out.payload.assign(buf.begin() + std::ptrdiff_t(headerLen), buf.end());
    return true;
}

bool TcpSegment::TryFromBytes(const std::vector<uint8_t> &buf, TcpSegment &out,
                              const Ipv4 &src, const Ipv4 &dst)
{
    if(!TryFromBytes(buf, out))
        return false;
    uint16_t got = ReadU16(buf, 16);
    return got == out.ComputeChecksum(src, dst);
}
