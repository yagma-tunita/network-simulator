#include "Ipv6.hpp"
#include "Ipv4.hpp"
#include <stdexcept>
#include <vector>
#include <cctype>

namespace
{
    bool ParseGroups(const std::string &part, std::vector<uint16_t> &groups,
                     bool allowIpv4)
    {
        if(part.empty())
            return true;

        std::size_t start = 0;
        while(start <= part.size())
        {
            std::size_t colon = part.find(':', start);
            std::size_t end = colon == std::string::npos ? part.size() : colon;
            if(end == start)
                return false;
            std::string token = part.substr(start, end - start);

            if(token.find('.') != std::string::npos)
            {
                if(!allowIpv4 || end != part.size())
                    return false;
                Ipv4 v4;
                if(!Ipv4::TryParse(token, v4))
                    return false;
                groups.push_back(uint16_t(v4.value >> 16));
                groups.push_back(uint16_t(v4.value & 0xFFFFu));
            }
            else
            {
                if(token.size() > 4)
                    return false;
                uint16_t value = 0;
                for(char c : token)
                {
                    int digit = -1;
                    if(c >= '0' && c <= '9')
                        digit = c - '0';
                    else if(c >= 'a' && c <= 'f')
                        digit = c - 'a' + 10;
                    else if(c >= 'A' && c <= 'F')
                        digit = c - 'A' + 10;
                    if(digit < 0)
                        return false;
                    value = uint16_t((value << 4) | digit);
                }
                groups.push_back(value);
            }

            if(colon == std::string::npos)
                break;
            start = colon + 1;
        }
        return true;
    }

    void StoreGroups(const std::vector<uint16_t> &groups, Ipv6 &out)
    {
        for(std::size_t i = 0; i < 8; ++i)
        {
            out.bytes[i * 2] = uint8_t(groups[i] >> 8);
            out.bytes[i * 2 + 1] = uint8_t(groups[i] & 0xFF);
        }
    }
}

Ipv6::Ipv6(const std::string &s)
{
    if(!TryParse(s, *this))
        throw std::invalid_argument("invalid IPv6 address");
}

bool Ipv6::TryParse(const std::string &s, Ipv6 &out)
{
    if(s.empty() || s.size() > 64)
        return false;

    std::size_t compress = s.find("::");
    if(compress != std::string::npos && s.find("::", compress + 2) != std::string::npos)
        return false;

    std::vector<uint16_t> left;
    std::vector<uint16_t> right;
    if(compress == std::string::npos)
    {
        if(!ParseGroups(s, left, true) || left.size() != 8)
            return false;
        StoreGroups(left, out);
        return true;
    }

    std::string lhs = s.substr(0, compress);
    std::string rhs = s.substr(compress + 2);
    if(!ParseGroups(lhs, left, false) || !ParseGroups(rhs, right, true))
        return false;
    if(left.size() + right.size() >= 8)
        return false;

    std::vector<uint16_t> groups;
    groups.reserve(8);
    groups.insert(groups.end(), left.begin(), left.end());
    groups.insert(groups.end(), 8 - left.size() - right.size(), 0);
    groups.insert(groups.end(), right.begin(), right.end());
    StoreGroups(groups, out);
    return true;
}

Ipv6 Ipv6::Parse(const std::string &s)
{
    Ipv6 out;
    if(!TryParse(s, out))
        throw std::invalid_argument("invalid IPv6 address");
    return out;
}

std::string Ipv6::ToString() const
{
    uint16_t groups[8] = {};
    for(int i = 0; i < 8; ++i)
        groups[i] = uint16_t((uint16_t(bytes[i * 2]) << 8) | bytes[i * 2 + 1]);

    int bestStart = -1;
    int bestLen = 0;
    int runStart = -1;
    int runLen = 0;
    for(int i = 0; i < 8; ++i)
    {
        if(groups[i] == 0)
        {
            if(runStart < 0)
            {
                runStart = i;
                runLen = 0;
            }
            ++runLen;
            if(runLen > bestLen)
            {
                bestStart = runStart;
                bestLen = runLen;
            }
        }
        else
        {
            runStart = -1;
            runLen = 0;
        }
    }
    if(bestLen < 2)
    {
        bestStart = -1;
        bestLen = 0;
    }

    static const char *hex = "0123456789abcdef";
    std::string out;
    for(int i = 0; i < 8; ++i)
    {
        if(bestStart >= 0 && i == bestStart)
        {
            out += "::";
            i += bestLen - 1;
            continue;
        }
        if(!out.empty() && out.back() != ':')
            out.push_back(':');
        uint16_t v = groups[i];
        if(v == 0)
        {
            out.push_back('0');
            continue;
        }
        char buf[5];
        int n = 0;
        while(v > 0)
        {
            buf[n++] = hex[v & 0xF];
            v >>= 4;
        }
        while(n > 0)
            out.push_back(buf[--n]);
    }
    if(out.empty())
        out = "::";
    return out;
}

bool Ipv6::IsAny() const
{
    for(uint8_t b : bytes)
        if(b != 0)
            return false;
    return true;
}
