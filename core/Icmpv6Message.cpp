#include "Icmpv6Message.hpp"
#include "ByteIO.hpp"
#include <cstddef>

using namespace ByteIO;

namespace
{
    uint16_t Checksum16(const std::vector<uint8_t> &buf)
    {
        uint32_t sum = 0;
        std::size_t i = 0;
        for(; i + 1 < buf.size(); i += 2)
            sum += (uint32_t(buf[i]) << 8) | buf[i + 1];
        if(i < buf.size())
            sum += uint32_t(buf[i]) << 8;
        while(sum >> 16)
            sum = (sum & 0xFFFFu) + (sum >> 16);
        return uint16_t(~sum & 0xFFFFu);
    }

    std::vector<uint8_t> PseudoHeader(const Ipv6 &src, const Ipv6 &dst,
                                      const std::vector<uint8_t> &msg)
    {
        std::vector<uint8_t> buf;
        buf.reserve(40 + msg.size());
        for(uint8_t b : src.bytes)
            buf.push_back(b);
        for(uint8_t b : dst.bytes)
            buf.push_back(b);
        std::vector<uint8_t> len;
        AppendU32(len, uint32_t(msg.size()));
        buf.insert(buf.end(), len.begin(), len.end());
        buf.push_back(0);
        buf.push_back(0);
        buf.push_back(0);
        buf.push_back(Icmpv6Message::kNextHeader);
        buf.insert(buf.end(), msg.begin(), msg.end());
        return buf;
    }
}

std::vector<uint8_t> Icmpv6Message::ToBytes(const Ipv6 &src,
                                            const Ipv6 &dst) const
{
    std::vector<uint8_t> buf;
    buf.reserve(24 + options.size() + payload.size());

    AppendU8(buf, type);
    AppendU8(buf, code);
    AppendU16(buf, 0);
    bool nd = type == kNeighborSolicit || type == kNeighborAdvert;
    if(nd)
    {
        AppendU32(buf, ndFlags);
        for(uint8_t b : target.bytes)
            buf.push_back(b);
        for(uint8_t b : options)
            buf.push_back(b);
    }
    else
    {
        AppendU16(buf, id);
        AppendU16(buf, seq);
        for(uint8_t b : payload)
            buf.push_back(b);
    }

    uint16_t c = Checksum16(PseudoHeader(src, dst, buf));
    buf[2] = uint8_t(c >> 8);
    buf[3] = uint8_t(c);
    return buf;
}

bool Icmpv6Message::TryFromBytes(const std::vector<uint8_t> &buf,
                                 const Ipv6 &src, const Ipv6 &dst,
                                 Icmpv6Message &out)
{
    if(buf.size() < 8)
        return false;

    std::vector<uint8_t> check = buf;
    uint16_t stored = ReadU16(check, 2);
    check[2] = 0;
    check[3] = 0;
    if(Checksum16(PseudoHeader(src, dst, check)) != stored)
        return false;

    out = Icmpv6Message();
    out.type = buf[0];
    out.code = buf[1];
    bool nd = out.type == kNeighborSolicit ||
              out.type == kNeighborAdvert;
    if(nd)
    {
        if(buf.size() < 24)
            return false;
        out.ndFlags = ReadU32(buf, 4);
        for(std::size_t i = 0; i < 16; ++i)
            out.target.bytes[i] = buf[8 + i];
        out.options.assign(buf.begin() + 24, buf.end());
    }
    else
    {
        out.id = ReadU16(buf, 4);
        out.seq = ReadU16(buf, 6);
        out.payload.assign(buf.begin() + 8, buf.end());
    }
    return true;
}

bool Icmpv6Message::operator==(const Icmpv6Message &o) const
{
    return type == o.type && code == o.code && id == o.id && seq == o.seq
        && ndFlags == o.ndFlags && target == o.target
        && options == o.options && payload == o.payload;
}

std::vector<uint8_t> NdpLinkLayerOption(uint8_t type, const Mac &mac)
{
    std::vector<uint8_t> out;
    out.push_back(type);
    out.push_back(1);
    for(uint8_t b : mac.bytes)
        out.push_back(b);
    return out;
}

bool NdpParseLinkLayerOption(const std::vector<uint8_t> &options,
                             uint8_t type, Mac &mac)
{
    for(std::size_t i = 0; i + 8 <= options.size();)
    {
        uint8_t kind = options[i];
        uint8_t len = options[i + 1];
        if(len == 0)
            return false;
        std::size_t bytes = std::size_t(len) * 8;
        if(i + bytes > options.size())
            return false;
        if(kind == type && len == 1)
        {
            for(std::size_t j = 0; j < 6; ++j)
                mac.bytes[j] = options[i + 2 + j];
            return true;
        }
        i += bytes;
    }
    return false;
}

Ipv6 NdpSolicitedNode(const Ipv6 &target)
{
    Ipv6 out;
    out.bytes[0] = 0xFF;
    out.bytes[1] = 0x02;
    out.bytes[11] = 0x01;
    out.bytes[12] = 0xFF;
    out.bytes[13] = target.bytes[13];
    out.bytes[14] = target.bytes[14];
    out.bytes[15] = target.bytes[15];
    return out;
}

Mac NdpSolicitedMac(const Ipv6 &target)
{
    return Mac(0x33, 0x33, 0xFF, target.bytes[13],
               target.bytes[14], target.bytes[15]);
}
