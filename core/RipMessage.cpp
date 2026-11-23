#include "RipMessage.hpp"
#include "ByteIO.hpp"
#include <cstddef>

using namespace ByteIO;

std::vector<uint8_t> RipMessage::ToBytes() const
{
    std::vector<uint8_t> buf;
    buf.reserve(4 + entries.size() * 20);

    AppendU8(buf, command);
    AppendU8(buf, 2);
    AppendU16(buf, 0);

    for (const RipEntry &e : entries)
    {
        AppendU16(buf, 0);
        AppendU16(buf, 0);
        AppendIpv4(buf, e.dst);
        AppendIpv4(buf, e.mask);
        AppendIpv4(buf, Ipv4::Any());
        AppendU32(buf, e.metric);
    }

    return buf;
}

bool RipMessage::TryFromBytes(const std::vector<uint8_t> &buf, RipMessage &out)
{
    if (buf.size() < 4)
        return false;
    if (ReadU8(buf, 1) != 2)
        return false;
    if ((buf.size() - 4) % 20 != 0)
        return false;

    out = RipMessage();
    out.command = ReadU8(buf, 0);

    for (std::size_t off = 4; off + 20 <= buf.size(); off += 20)
    {
        RipEntry e;
        e.dst = ReadIpv4(buf, off + 4);
        e.mask = ReadIpv4(buf, off + 8);
        uint32_t metric = ReadU32(buf, off + 16);
        e.metric = uint16_t(metric > 16 ? 16 : metric);
        out.entries.push_back(e);
    }

    return true;
}
