#include "Ipv6Packet.hpp"
#include "ByteIO.hpp"
#include <stdexcept>
#include <utility>

using namespace ByteIO;

bool Ipv6Packet::operator==(const Ipv6Packet &o) const
{
    return trafficClass == o.trafficClass
        && flowLabel == o.flowLabel
        && nextHeader == o.nextHeader
        && hopLimit == o.hopLimit
        && srcIp == o.srcIp
        && dstIp == o.dstIp
        && payload == o.payload;
}

std::string Ipv6Packet::ToString() const
{
    return srcIp.ToString() + " -> " + dstIp.ToString()
         + " hop=" + std::to_string(hopLimit)
         + " next=" + std::to_string(nextHeader)
         + " " + std::to_string(payload.size()) + " bytes";
}

std::vector<uint8_t> Ipv6Packet::ToBytes() const
{
    if(payload.size() > 65535u)
        throw std::length_error("Ipv6Packet: payload too large");

    std::vector<uint8_t> buf;
    buf.reserve(kHeaderSize + payload.size());

    AppendU8(buf, uint8_t(0x60 | ((trafficClass >> 4) & 0x0F)));
    AppendU8(buf, uint8_t(((trafficClass & 0x0F) << 4) |
                          ((flowLabel >> 16) & 0x0F)));
    AppendU8(buf, uint8_t((flowLabel >> 8) & 0xFF));
    AppendU8(buf, uint8_t(flowLabel & 0xFF));
    AppendU16(buf, uint16_t(payload.size()));
    AppendU8(buf, nextHeader);
    AppendU8(buf, hopLimit);
    for(uint8_t b : srcIp.bytes)
        buf.push_back(b);
    for(uint8_t b : dstIp.bytes)
        buf.push_back(b);
    for(uint8_t b : payload)
        buf.push_back(b);
    return buf;
}

bool Ipv6Packet::TryFromBytes(const std::vector<uint8_t> &buf, Ipv6Packet &out)
{
    if(buf.size() < kHeaderSize || (buf[0] >> 4) != 6)
        return false;

    uint16_t payloadLen = ReadU16(buf, 4);
    if(buf.size() < kHeaderSize + payloadLen)
        return false;

    out.trafficClass = uint8_t(((buf[0] & 0x0F) << 4) | (buf[1] >> 4));
    out.flowLabel = (uint32_t(buf[1] & 0x0F) << 16) |
                    (uint32_t(buf[2]) << 8) | uint32_t(buf[3]);
    out.nextHeader = buf[6];
    out.hopLimit = buf[7];
    for(std::size_t i = 0; i < 16; ++i)
        out.srcIp.bytes[i] = buf[8 + i];
    for(std::size_t i = 0; i < 16; ++i)
        out.dstIp.bytes[i] = buf[24 + i];
    out.payload.assign(buf.begin() + std::ptrdiff_t(kHeaderSize),
                       buf.begin() + std::ptrdiff_t(kHeaderSize + payloadLen));
    return true;
}

Ipv6Packet::Ipv6Packet(Ipv6 src, Ipv6 dst, uint8_t proto,
                       std::vector<uint8_t> data)
    : nextHeader(proto), srcIp(src), dstIp(dst), payload(std::move(data))
{}
