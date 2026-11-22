#include "IcmpMessage.hpp"
#include "ByteIO.hpp"

using namespace ByteIO;

std::vector<uint8_t> IcmpMessage::ToBytes() const
{
    std::vector<uint8_t> buf;
    buf.reserve(8 + payload.size());

    AppendU8(buf, type);
    AppendU8(buf, code);
    AppendU16(buf, 0);
    AppendU16(buf, id);
    AppendU16(buf, seq);

    for (uint8_t b : payload)
        buf.push_back(b);

    return buf;
}

bool IcmpMessage::TryFromBytes(const std::vector<uint8_t> &buf, IcmpMessage &out)
{
    if (buf.size() < 8)
        return false;

    out.type = buf[0];
    out.code = buf[1];
    out.id = ReadU16(buf, 4);
    out.seq = ReadU16(buf, 6);
    out.payload.assign(buf.begin() + 8, buf.end());
    return true;
}

bool IcmpMessage::operator==(const IcmpMessage &o) const
{
    return type == o.type && code == o.code && id == o.id && seq == o.seq
        && payload == o.payload;
}

std::string IcmpMessage::ToString() const
{
    return std::string("ICMP type=") + std::to_string(type)
         + " seq=" + std::to_string(seq);
}
