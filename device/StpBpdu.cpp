#include "StpBpdu.hpp"
#include "../core/ByteIO.hpp"

using namespace ByteIO;

namespace
{
    void AppendU32(std::vector<uint8_t> &buf, uint32_t v)
    {
        buf.push_back(uint8_t(v >> 24));
        buf.push_back(uint8_t(v >> 16));
        buf.push_back(uint8_t(v >> 8));
        buf.push_back(uint8_t(v));
    }

    uint32_t ReadU32(const std::vector<uint8_t> &buf, std::size_t off)
    {
        return (uint32_t(buf[off]) << 24)
             | (uint32_t(buf[off + 1]) << 16)
             | (uint32_t(buf[off + 2]) << 8)
             |  uint32_t(buf[off + 3]);
    }
}

bool StpBpdu::operator==(const StpBpdu &o) const
{
    return version == o.version && flags == o.flags
        && rootPriority == o.rootPriority && rootMac == o.rootMac
        && rootPathCost == o.rootPathCost
        && bridgePriority == o.bridgePriority && bridgeMac == o.bridgeMac
        && portId == o.portId && messageAge == o.messageAge
        && maxAge == o.maxAge && helloTime == o.helloTime
        && forwardDelay == o.forwardDelay;
}

std::vector<uint8_t> StpBpdu::ToBytes() const
{
    std::vector<uint8_t> buf;
    buf.reserve(kSize);

    AppendU16(buf, kProtocolId);
    AppendU8(buf, version);
    AppendU8(buf, kConfig);
    AppendU8(buf, flags);
    AppendU16(buf, rootPriority);
    AppendMac(buf, rootMac);
    AppendU32(buf, rootPathCost);
    AppendU16(buf, bridgePriority);
    AppendMac(buf, bridgeMac);
    AppendU16(buf, portId);
    AppendU16(buf, messageAge);
    AppendU16(buf, maxAge);
    AppendU16(buf, helloTime);
    AppendU16(buf, forwardDelay);

    return buf;
}

bool StpBpdu::TryFromBytes(const std::vector<uint8_t> &buf, StpBpdu &out)
{
    if (buf.size() < kSize)
        return false;
    if (ReadU16(buf, 0) != kProtocolId)
        return false;

    uint8_t ver = ReadU8(buf, 2);
    if (ver != kVersion && ver != kRstpVersion)
        return false;
    if (ReadU8(buf, 3) != kConfig)
        return false;

    out.version = ver;
    out.flags = ReadU8(buf, 4);
    out.rootPriority = ReadU16(buf, 5);
    out.rootMac = ReadMac(buf, 7);
    out.rootPathCost = ReadU32(buf, 13);
    out.bridgePriority = ReadU16(buf, 17);
    out.bridgeMac = ReadMac(buf, 19);
    out.portId = ReadU16(buf, 25);
    out.messageAge = ReadU16(buf, 27);
    out.maxAge = ReadU16(buf, 29);
    out.helloTime = ReadU16(buf, 31);
    out.forwardDelay = ReadU16(buf, 33);

    return true;
}

Mac StpBpdu::Multicast()
{
    return Mac(0x01, 0x80, 0xC2, 0x00, 0x00, 0x00);
}
