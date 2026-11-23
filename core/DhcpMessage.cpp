#include "DhcpMessage.hpp"
#include "ByteIO.hpp"
#include <cstddef>

using namespace ByteIO;

namespace
{
    void AppendOption(std::vector<uint8_t> &buf, uint8_t code,
                      const std::vector<uint8_t> &value)
    {
        buf.push_back(code);
        buf.push_back(uint8_t(value.size()));
        for (uint8_t b : value)
            buf.push_back(b);
    }

    std::vector<uint8_t> U32Bytes(uint32_t v)
    {
        std::vector<uint8_t> b;
        AppendU32(b, v);
        return b;
    }

    std::vector<uint8_t> IpBytes(const Ipv4 &ip)
    {
        std::vector<uint8_t> b;
        AppendIpv4(b, ip);
        return b;
    }
}

std::vector<uint8_t> DhcpMessage::ToBytes() const
{
    std::vector<uint8_t> buf;
    buf.reserve(300);

    AppendU8(buf, op);
    AppendU8(buf, htype);
    AppendU8(buf, hlen);
    AppendU8(buf, hops);
    AppendU32(buf, xid);
    AppendU16(buf, secs);
    AppendU16(buf, flags);
    AppendIpv4(buf, ciaddr);
    AppendIpv4(buf, yiaddr);
    AppendIpv4(buf, siaddr);
    AppendIpv4(buf, giaddr);

    for (std::size_t i = 0; i < 16; ++i)
        buf.push_back(i < 6 ? chaddr.bytes[i] : 0);

    for (std::size_t i = 0; i < 64; ++i)
        buf.push_back(0);
    for (std::size_t i = 0; i < 128; ++i)
        buf.push_back(0);

    AppendU32(buf, 0x63825363u);

    AppendOption(buf, 53, std::vector<uint8_t>{ type });
    if (hasServerId)
        AppendOption(buf, 54, IpBytes(serverId));
    if (hasRequested)
        AppendOption(buf, 50, IpBytes(requestedIp));
    if (hasLease)
        AppendOption(buf, 51, U32Bytes(leaseTime));
    if (hasSubnetMask)
        AppendOption(buf, 1, IpBytes(subnetMask));
    if (hasRouter)
        AppendOption(buf, 3, IpBytes(router));
    if (hasDns)
        AppendOption(buf, 6, IpBytes(dns));

    buf.push_back(255);
    return buf;
}

bool DhcpMessage::TryFromBytes(const std::vector<uint8_t> &buf, DhcpMessage &out)
{
    if (buf.size() < 240)
        return false;
    if (ReadU32(buf, 236) != 0x63825363u)
        return false;

    out = DhcpMessage();
    out.op = ReadU8(buf, 0);
    out.htype = ReadU8(buf, 1);
    out.hlen = ReadU8(buf, 2);
    out.hops = ReadU8(buf, 3);
    out.xid = ReadU32(buf, 4);
    out.secs = ReadU16(buf, 8);
    out.flags = ReadU16(buf, 10);
    out.ciaddr = ReadIpv4(buf, 12);
    out.yiaddr = ReadIpv4(buf, 16);
    out.siaddr = ReadIpv4(buf, 20);
    out.giaddr = ReadIpv4(buf, 24);
    out.chaddr = ReadMac(buf, 28);

    std::size_t i = 240;
    while (i < buf.size())
    {
        uint8_t code = buf[i++];
        if (code == 0)
            continue;
        if (code == 255)
            break;
        if (i >= buf.size())
            return false;
        uint8_t len = buf[i++];
        if (i + len > buf.size())
            return false;

        if (code == 53 && len == 1)
        {
            out.type = buf[i];
        }
        else if (code == 54 && len == 4)
        {
            out.hasServerId = true;
            out.serverId = ReadIpv4(buf, i);
        }
        else if (code == 50 && len == 4)
        {
            out.hasRequested = true;
            out.requestedIp = ReadIpv4(buf, i);
        }
        else if (code == 51 && len == 4)
        {
            out.hasLease = true;
            out.leaseTime = ReadU32(buf, i);
        }
        else if (code == 1 && len == 4)
        {
            out.hasSubnetMask = true;
            out.subnetMask = ReadIpv4(buf, i);
        }
        else if (code == 3 && len >= 4)
        {
            out.hasRouter = true;
            out.router = ReadIpv4(buf, i);
        }
        else if (code == 6 && len >= 4)
        {
            out.hasDns = true;
            out.dns = ReadIpv4(buf, i);
        }

        i += len;
    }

    return out.type != 0;
}
