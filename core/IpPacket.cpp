#include "IpPacket.hpp"
#include "ByteIO.hpp"
#include <stdexcept>

using namespace ByteIO;

namespace
{
    uint16_t HeaderChecksum(const std::vector<uint8_t> &b)
    {
        uint32_t sum = 0;
        for(std::size_t i = 0; i + 1 < IpPacket::kHeaderSize; i += 2)
            sum += (uint32_t(b[i]) << 8) | b[i + 1];
        while(sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return uint16_t(~sum & 0xFFFF);
    }
}

bool IpPacket::operator==(const IpPacket &o) const
{
    return ttl == o.ttl
        &&  protocol == o.protocol
        &&  ecn == o.ecn
        &&  identification == o.identification
        &&  dontFragment == o.dontFragment
        &&  moreFragments == o.moreFragments
        &&  fragmentOffset == o.fragmentOffset
        &&  srcIp == o.srcIp
        &&  dstIp == o.dstIp
        &&  payload == o.payload;
}

void IpPacket::DecTtl(){ if(ttl > 0) ttl--;}

std::string IpPacket::ToString() const
{
    return srcIp.ToString() + " -> " + dstIp.ToString()
         + " ttl=" + std::to_string(ttl)
         + " proto=" + std::to_string(protocol)
         + " " + std::to_string(payload.size()) + " bytes";
}

std::vector<uint8_t> IpPacket::ToBytes() const
{
    if(payload.size() > 65535u - kHeaderSize)
        throw std::length_error("IpPacket: payload too large");

    std::vector<uint8_t>buf;
    buf.reserve(kHeaderSize + payload.size());

    AppendU8(buf, 0x45);
    AppendU8(buf, uint8_t(ecn & 0x03));
    AppendU16(buf, uint16_t(kHeaderSize + payload.size()));
    AppendU16(buf, identification);
    uint16_t flagsOffset = uint16_t((dontFragment ? 0x4000u : 0u) |
                                    (moreFragments ? 0x2000u : 0u) |
                                    (fragmentOffset & 0x1FFFu));
    AppendU16(buf, flagsOffset);
    AppendU8(buf, ttl);
    AppendU8(buf, protocol);
    AppendU16(buf, 0);
    AppendIpv4(buf, srcIp);
    AppendIpv4(buf, dstIp);

    for(uint8_t b : payload)buf.push_back(b);

    uint16_t c = HeaderChecksum(buf);
    buf[10] = uint8_t(c >> 8);
    buf[11] = uint8_t(c);

    return buf;
}

bool IpPacket::TryFromBytes(const std::vector<uint8_t> &buf, IpPacket &out)
{
    if(buf.size() < kHeaderSize || buf.front() != 0x45)return false;

    uint16_t total = ReadU16(buf, 2);
    if(total < kHeaderSize || total > buf.size())return false;

    std::vector<uint8_t> hdr(buf.begin(), buf.begin() + kHeaderSize);
    uint16_t stored = ReadU16(hdr, 10);
    hdr[10] = 0;
    hdr[11] = 0;
    if(HeaderChecksum(hdr) != stored)return false;

    out.identification = ReadU16(buf, 4);
    uint16_t flagsOffset = ReadU16(buf, 6);
    out.dontFragment = (flagsOffset & 0x4000u) != 0;
    out.moreFragments = (flagsOffset & 0x2000u) != 0;
    out.fragmentOffset = uint16_t(flagsOffset & 0x1FFFu);
    out.ttl = ReadU8(buf, 8);
    out.protocol = ReadU8(buf, 9);
    out.ecn = uint8_t(ReadU8(buf, 1) & 0x03);
    out.srcIp = ReadIpv4(buf, 12);
    out.dstIp = ReadIpv4(buf, 16);
    out.payload = std::vector<uint8_t>(buf.begin() + kHeaderSize, buf.begin() + total);

    return true;
}

IpPacket::IpPacket(Ipv4 src, Ipv4 dst, uint8_t proto, std::vector<uint8_t> data)
    : protocol(proto), srcIp(src), dstIp(dst), payload(std::move(data))
{}
