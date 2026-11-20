#include "IpPacket.hpp"
#include "ByteIO.hpp"

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
    std::vector<uint8_t>buf;

    AppendU8(buf, 0x45);
    AppendU8(buf, 0);
    AppendU16(buf, uint16_t(20 + payload.size()));
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
    if(buf.size() < 20 || buf.front() != 0x45)return false;

    out.ttl = ReadU8(buf, 8);
    out.protocol = ReadU8(buf, 9);
    out.srcIp = ReadIpv4(buf, 12);
    out.dstIp = ReadIpv4(buf, 16);
    out.payload = std::vector<uint8_t>(buf.begin() + 20, buf.end());

    return true;
}

IpPacket::IpPacket(Ipv4 src, Ipv4 dst, uint8_t proto, std::vector<uint8_t> data)
    : protocol(proto), srcIp(src), dstIp(dst), payload(std::move(data))
{}
