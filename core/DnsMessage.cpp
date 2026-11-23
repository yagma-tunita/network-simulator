#include "DnsMessage.hpp"
#include "ByteIO.hpp"
#include <cstddef>

using namespace ByteIO;

namespace
{
    bool AppendName(std::vector<uint8_t> &buf, const std::string &name)
    {
        if (name.empty() || name.size() > 253)
            return false;

        std::size_t start = 0;
        while (start < name.size())
        {
            std::size_t dot = name.find('.', start);
            std::size_t end = (dot == std::string::npos) ? name.size() : dot;
            std::size_t len = end - start;
            if (len == 0 || len > 63)
                return false;

            buf.push_back(uint8_t(len));
            for (std::size_t i = start; i < end; ++i)
                buf.push_back(uint8_t(name[i]));

            if (dot == std::string::npos)
                break;
            start = dot + 1;
        }

        buf.push_back(0);
        return true;
    }

    bool ReadName(const std::vector<uint8_t> &buf, std::size_t &off, std::string &out)
    {
        std::size_t pos = off;
        std::size_t resume = 0;
        bool jumped = false;
        int guard = 0;

        while (true)
        {
            if (pos >= buf.size())
                return false;

            uint8_t len = buf[pos];
            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= buf.size())
                    return false;
                std::size_t ptr = (std::size_t(len & 0x3F) << 8) | buf[pos + 1];
                if (!jumped)
                {
                    resume = pos + 2;
                    jumped = true;
                }
                pos = ptr;
                if (++guard > 64)
                    return false;
                continue;
            }
            if (len == 0)
            {
                ++pos;
                break;
            }
            if (len > 63 || pos + 1 + len > buf.size())
                return false;

            if (!out.empty())
                out.push_back('.');
            out.append(reinterpret_cast<const char *>(&buf[pos + 1]), len);
            pos += 1 + len;

            if (++guard > 128)
                return false;
        }

        off = jumped ? resume : pos;
        return true;
    }
}

std::vector<uint8_t> DnsMessage::ToBytes() const
{
    std::vector<uint8_t> buf;
    buf.reserve(64 + questions.size() * 16 + answers.size() * 16);

    AppendU16(buf, id);
    AppendU16(buf, flags);
    AppendU16(buf, uint16_t(questions.size()));
    AppendU16(buf, uint16_t(answers.size()));
    AppendU16(buf, 0);
    AppendU16(buf, 0);

    for (const DnsQuestion &q : questions)
    {
        if (!AppendName(buf, q.name))
            return {};
        AppendU16(buf, q.qtype);
        AppendU16(buf, q.qclass);
    }

    for (const DnsAnswer &a : answers)
    {
        if (!AppendName(buf, a.name))
            return {};
        AppendU16(buf, a.type);
        AppendU16(buf, a.cls);
        AppendU32(buf, a.ttl);
        AppendU16(buf, 4);
        AppendIpv4(buf, a.ip);
    }

    return buf;
}

bool DnsMessage::TryFromBytes(const std::vector<uint8_t> &buf, DnsMessage &out)
{
    if (buf.size() < 12)
        return false;

    out = DnsMessage();
    out.id = ReadU16(buf, 0);
    out.flags = ReadU16(buf, 2);
    uint16_t qd = ReadU16(buf, 4);
    uint16_t an = ReadU16(buf, 6);
    uint16_t ns = ReadU16(buf, 8);
    uint16_t ar = ReadU16(buf, 10);

    if (qd > 64 || an > 256 || ns > 64 || ar > 64)
        return false;

    std::size_t off = 12;

    for (uint16_t i = 0; i < qd; ++i)
    {
        DnsQuestion q;
        if (!ReadName(buf, off, q.name))
            return false;
        if (off + 4 > buf.size())
            return false;
        q.qtype = ReadU16(buf, off);
        q.qclass = ReadU16(buf, off + 2);
        off += 4;
        out.questions.push_back(q);
    }

    for (uint16_t i = 0; i < an; ++i)
    {
        DnsAnswer a;
        if (!ReadName(buf, off, a.name))
            return false;
        if (off + 10 > buf.size())
            return false;
        a.type = ReadU16(buf, off);
        a.cls = ReadU16(buf, off + 2);
        a.ttl = ReadU32(buf, off + 4);
        uint16_t rdlen = ReadU16(buf, off + 8);
        off += 10;
        if (off + rdlen > buf.size())
            return false;
        if (a.type == 1 && rdlen == 4)
            a.ip = ReadIpv4(buf, off);
        off += rdlen;
        out.answers.push_back(a);
    }

    for (uint16_t i = 0; i < ns + ar; ++i)
    {
        std::string skip;
        if (!ReadName(buf, off, skip))
            return false;
        if (off + 10 > buf.size())
            return false;
        uint16_t rdlen = ReadU16(buf, off + 8);
        off += 10;
        if (off + rdlen > buf.size())
            return false;
        off += rdlen;
    }

    return true;
}
