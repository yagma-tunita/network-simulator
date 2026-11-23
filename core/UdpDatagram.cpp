#include "UdpDatagram.hpp"
#include "ByteIO.hpp"

using namespace ByteIO;

bool UdpDatagram::operator==(const UdpDatagram &o) const
{
    return srcPort == o.srcPort && dstPort == o.dstPort && payload == o.payload;
}

std::vector<uint8_t> UdpDatagram::ToBytes() const
{
    std::vector<uint8_t> buf;
    buf.reserve(8 + payload.size());

    AppendU16(buf, srcPort);
    AppendU16(buf, dstPort);
    AppendU16(buf, uint16_t(8 + payload.size()));
    AppendU16(buf, 0);

    for (uint8_t b : payload)
        buf.push_back(b);

    return buf;
}

bool UdpDatagram::TryFromBytes(const std::vector<uint8_t> &buf, UdpDatagram &out)
{
    if (buf.size() < 8)
        return false;

    uint16_t length = ReadU16(buf, 4);
    if (length < 8 || length > buf.size())
        return false;

    out.srcPort = ReadU16(buf, 0);
    out.dstPort = ReadU16(buf, 2);
    out.payload.assign(buf.begin() + 8, buf.begin() + length);
    return true;
}
