#include "IpPacket.hpp"
#include "ByteIO.hpp"
#include <stdexcept>

using namespace ByteIO;

bool IpPacket::operator==(const IpPacket &o) const
{
    return ttl == o.ttl
        &&  protocol == o.protocol
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
    AppendU8(buf, 0);
    AppendU16(buf, uint16_t(kHeaderSize + payload.size()));
    AppendU16(buf, 0);
    AppendU16(buf, 0);
    AppendU8(buf, ttl);
    AppendU8(buf, protocol);
    AppendU16(buf, 0);
    AppendIpv4(buf, srcIp);
    AppendIpv4(buf, dstIp);

    for(uint8_t b : payload)buf.push_back(b);

    return buf;
}

bool IpPacket::TryFromBytes(const std::vector<uint8_t> &buf, IpPacket &out)
{
    if(buf.size() < kHeaderSize || buf.front() != 0x45)return false;

    uint16_t total = ReadU16(buf, 2);
    if(total < kHeaderSize || total > buf.size())return false;

    out.ttl = ReadU8(buf, 8);
    out.protocol = ReadU8(buf, 9);
    out.srcIp = ReadIpv4(buf, 12);
    out.dstIp = ReadIpv4(buf, 16);
    out.payload = std::vector<uint8_t>(buf.begin() + kHeaderSize, buf.begin() + total);

    return true;
}

IpPacket::IpPacket(Ipv4 src, Ipv4 dst, uint8_t proto, std::vector<uint8_t> data)
    : protocol(proto), srcIp(src), dstIp(dst), payload(std::move(data))
{}
