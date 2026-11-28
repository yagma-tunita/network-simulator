#include "Lldp.hpp"
#include "ByteIO.hpp"

using namespace ByteIO;

namespace
{
    void AppendTlv(std::vector<uint8_t> &buf, uint8_t type,
                   const std::vector<uint8_t> &value)
    {
        uint16_t h = (uint16_t(type) << 9) | uint16_t(value.size() & 0x1FF);
        AppendU16(buf, h);
        buf.insert(buf.end(), value.begin(), value.end());
    }
}

Mac LldpFrame::Multicast()
{
    return Mac(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E);
}

std::vector<uint8_t> LldpFrame::ToBytes() const
{
    std::vector<uint8_t> out;

    std::vector<uint8_t> chassisVal;
    chassisVal.push_back(4);
    for(uint8_t b : chassis.bytes)
        chassisVal.push_back(b);
    AppendTlv(out, 1, chassisVal);

    std::vector<uint8_t> portVal;
    portVal.push_back(5);
    for(char c : portId)
        portVal.push_back(uint8_t(c));
    AppendTlv(out, 2, portVal);

    std::vector<uint8_t> ttlVal;
    AppendU16(ttlVal, ttl);
    AppendTlv(out, 3, ttlVal);

    if(!systemName.empty())
    {
        std::vector<uint8_t> nameVal(systemName.begin(), systemName.end());
        AppendTlv(out, 5, nameVal);
    }

    AppendTlv(out, 0, {});
    return out;
}

bool LldpFrame::TryFromBytes(const std::vector<uint8_t> &buf, LldpFrame &out)
{
    out = LldpFrame();
    bool haveChassis = false;
    bool havePort = false;
    bool haveTtl = false;

    std::size_t off = 0;
    while(off + 2 <= buf.size())
    {
        uint16_t h = ReadU16(buf, off);
        off += 2;
        uint8_t type = uint8_t(h >> 9);
        std::size_t len = h & 0x1FF;
        if(off + len > buf.size())
            return false;

        if(type == 0)
            break;
        if(type == 1 && len == 7 && buf[off] == 4)
        {
            for(std::size_t i = 0; i < 6; ++i)
                out.chassis.bytes[i] = buf[off + 1 + i];
            haveChassis = true;
        }
        else if(type == 2 && len >= 2 && buf[off] == 5)
        {
            out.portId.assign(buf.begin() + std::ptrdiff_t(off + 1),
                              buf.begin() + std::ptrdiff_t(off + len));
            havePort = true;
        }
        else if(type == 3 && len == 2)
        {
            out.ttl = ReadU16(buf, off);
            haveTtl = true;
        }
        else if(type == 5 && len > 0)
        {
            out.systemName.assign(buf.begin() + std::ptrdiff_t(off),
                                  buf.begin() + std::ptrdiff_t(off + len));
        }
        off += len;
    }
    return haveChassis && havePort && haveTtl;
}

bool LldpFrame::operator==(const LldpFrame &o) const
{
    return chassis == o.chassis && portId == o.portId && ttl == o.ttl
        && systemName == o.systemName;
}
