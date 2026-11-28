#include "BgpMessage.hpp"
#include "ByteIO.hpp"
#include <algorithm>
#include <cstddef>

using namespace ByteIO;

namespace
{
    void AppendPrefix(std::vector<uint8_t> &buf, const Ipv4Subnet &s)
    {
        AppendU8(buf, s.prefix);
        std::size_t bytes = (std::size_t(s.prefix) + 7) / 8;
        for(std::size_t i = 0; i < bytes; ++i)
        {
            unsigned shift = unsigned(24 - i * 8);
            buf.push_back(uint8_t((s.network.value >> shift) & 0xFF));
        }
    }

    bool ReadPrefixes(const std::vector<uint8_t> &body, std::size_t &off,
                      std::size_t end, std::vector<Ipv4Subnet> &out)
    {
        while(off < end)
        {
            uint8_t prefix = body[off++];
            if(prefix > 32)
                return false;
            std::size_t bytes = (std::size_t(prefix) + 7) / 8;
            if(off + bytes > end)
                return false;
            uint32_t value = 0;
            for(std::size_t i = 0; i < bytes; ++i)
                value |= uint32_t(body[off + i]) << (24 - i * 8);
            off += bytes;
            out.push_back(Ipv4Subnet(Ipv4(value), prefix));
        }
        return true;
    }

    void AppendAttribute(std::vector<uint8_t> &attrs, uint8_t flags,
                         uint8_t code, const std::vector<uint8_t> &value)
    {
        attrs.push_back(flags);
        attrs.push_back(code);
        if(value.size() > 255)
        {
            attrs[attrs.size() - 2] = uint8_t(flags | 0x10);
            AppendU16(attrs, uint16_t(value.size()));
        }
        else
            attrs.push_back(uint8_t(value.size()));
        attrs.insert(attrs.end(), value.begin(), value.end());
    }
}

std::vector<uint8_t> BgpMessage::ToBytes() const
{
    std::vector<uint8_t> body;

    if(type == Open)
    {
        AppendU8(body, version);
        AppendU16(body, myAs);
        AppendU16(body, holdTime);
        AppendIpv4(body, bgpId);
        AppendU8(body, 0);
    }
    else if(type == Notification)
    {
        AppendU8(body, errorCode);
        AppendU8(body, errorSubcode);
        body.insert(body.end(), data.begin(), data.end());
    }
    else if(type == Update)
    {
        std::vector<uint8_t> withdrawnBytes;
        for(const Ipv4Subnet &w : withdrawn)
            AppendPrefix(withdrawnBytes, w);

        std::vector<uint8_t> attrs;
        if(!nlri.empty())
        {
            std::vector<uint8_t> originVal{ origin };
            AppendAttribute(attrs, 0x40, 1, originVal);

            std::vector<uint8_t> path;
            path.push_back(2);
            path.push_back(uint8_t(std::min<std::size_t>(asPath.size(), 255)));
            std::size_t count = std::min<std::size_t>(asPath.size(), 255);
            for(std::size_t i = 0; i < count; ++i)
                AppendU16(path, asPath[i]);
            AppendAttribute(attrs, 0x40, 2, path);

            std::vector<uint8_t> nh;
            AppendIpv4(nh, nextHop);
            AppendAttribute(attrs, 0x40, 3, nh);

            if(hasLocalPref)
            {
                std::vector<uint8_t> lp;
                AppendU32(lp, localPref);
                AppendAttribute(attrs, 0x40, 5, lp);
            }
            if(hasMed)
            {
                std::vector<uint8_t> medBytes;
                AppendU32(medBytes, med);
                AppendAttribute(attrs, 0x80, 4, medBytes);
            }
            if(!communities.empty())
            {
                std::vector<uint8_t> comm;
                for(uint32_t c : communities)
                    AppendU32(comm, c);
                AppendAttribute(attrs, 0xC0, 8, comm);
            }
        }

        AppendU16(body, uint16_t(withdrawnBytes.size()));
        body.insert(body.end(), withdrawnBytes.begin(), withdrawnBytes.end());
        AppendU16(body, uint16_t(attrs.size()));
        body.insert(body.end(), attrs.begin(), attrs.end());
        for(const Ipv4Subnet &n : nlri)
            AppendPrefix(body, n);
    }

    std::vector<uint8_t> out;
    out.reserve(kHeaderSize + body.size());
    for(int i = 0; i < 16; ++i)
        out.push_back(0xFF);
    AppendU16(out, uint16_t(kHeaderSize + body.size()));
    AppendU8(out, type);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

bool BgpMessage::TryFromBytes(const std::vector<uint8_t> &buf, BgpMessage &out)
{
    if(buf.size() < kHeaderSize)
        return false;
    for(int i = 0; i < 16; ++i)
        if(buf[i] != 0xFF)
            return false;
    uint16_t length = ReadU16(buf, 16);
    if(length < kHeaderSize || length > kMaxLength || length > buf.size())
        return false;

    out = BgpMessage();
    out.type = buf[18];
    std::size_t off = kHeaderSize;
    std::size_t end = length;

    if(out.type == Open)
    {
        if(end - off < 10)
            return false;
        out.version = buf[off++];
        out.myAs = ReadU16(buf, off);
        off += 2;
        out.holdTime = ReadU16(buf, off);
        off += 2;
        out.bgpId = Ipv4(ReadU32(buf, off));
        off += 4;
        uint8_t optLen = buf[off++];
        if(off + optLen > end)
            return false;
        return out.version == 4;
    }
    if(out.type == Keepalive)
        return end == off;
    if(out.type == Notification)
    {
        if(end - off < 2)
            return false;
        out.errorCode = buf[off++];
        out.errorSubcode = buf[off++];
        out.data.assign(buf.begin() + std::ptrdiff_t(off),
                        buf.begin() + std::ptrdiff_t(end));
        return true;
    }
    if(out.type != Update)
        return false;

    if(end - off < 2)
        return false;
    uint16_t withdrawnLen = ReadU16(buf, off);
    off += 2;
    if(off + withdrawnLen > end)
        return false;
    std::size_t withdrawnEnd = off + withdrawnLen;
    if(!ReadPrefixes(buf, off, withdrawnEnd, out.withdrawn))
        return false;
    off = withdrawnEnd;

    if(end - off < 2)
        return false;
    uint16_t attrLen = ReadU16(buf, off);
    off += 2;
    if(off + attrLen > end)
        return false;
    std::size_t attrEnd = off + attrLen;
    while(off < attrEnd)
    {
        if(attrEnd - off < 3)
            return false;
        uint8_t flags = buf[off++];
        uint8_t code = buf[off++];
        std::size_t vlen;
        if(flags & 0x10)
        {
            if(attrEnd - off < 2)
                return false;
            vlen = ReadU16(buf, off);
            off += 2;
        }
        else
        {
            if(off >= attrEnd)
                return false;
            vlen = buf[off++];
        }
        if(off + vlen > attrEnd)
            return false;
        std::size_t vend = off + vlen;

        if(code == 1 && vlen == 1)
            out.origin = buf[off];
        else if(code == 2 && vlen >= 2)
        {
            std::size_t p = off;
            while(p < vend)
            {
                if(vend - p < 2)
                    return false;
                ++p;
                uint8_t count = buf[p++];
                for(uint8_t i = 0; i < count; ++i)
                {
                    if(vend - p < 2)
                        return false;
                    out.asPath.push_back(ReadU16(buf, p));
                    p += 2;
                }
            }
        }
        else if(code == 3 && vlen == 4)
            out.nextHop = Ipv4(ReadU32(buf, off));
        else if(code == 5 && vlen == 4)
        {
            out.hasLocalPref = true;
            out.localPref = ReadU32(buf, off);
        }
        else if(code == 4 && vlen == 4)
        {
            out.hasMed = true;
            out.med = ReadU32(buf, off);
        }
        else if(code == 8 && vlen % 4 == 0)
        {
            for(std::size_t p = off; p < vend; p += 4)
                out.communities.push_back(ReadU32(buf, p));
        }
        off = vend;
    }

    if(!ReadPrefixes(buf, off, end, out.nlri))
        return false;
    return true;
}

bool BgpMessage::operator==(const BgpMessage &o) const
{
    return type == o.type && version == o.version && myAs == o.myAs
        && holdTime == o.holdTime && bgpId == o.bgpId
        && errorCode == o.errorCode && errorSubcode == o.errorSubcode
        && data == o.data && withdrawn == o.withdrawn && nlri == o.nlri
        && origin == o.origin && asPath == o.asPath
        && nextHop == o.nextHop && hasLocalPref == o.hasLocalPref
        && localPref == o.localPref && hasMed == o.hasMed && med == o.med
        && communities == o.communities;
}

std::string BgpMessage::ToString() const
{
    switch(type)
    {
        case Open: return "BGP OPEN as=" + std::to_string(myAs)
                        + " id=" + bgpId.ToString();
        case Update: return "BGP UPDATE nlri=" + std::to_string(nlri.size())
                         + " withdrawn=" + std::to_string(withdrawn.size());
        case Notification: return "BGP NOTIFICATION code="
                               + std::to_string(errorCode) + "/"
                               + std::to_string(errorSubcode);
        default: return "BGP KEEPALIVE";
    }
}
