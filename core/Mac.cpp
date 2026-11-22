#include "Mac.hpp"
#include <cstddef>
#include <stdexcept>

namespace
{
    int hexVal(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    char hexChar(int val)
    {
        if(val>=0&&val<=9) return char(val + '0');
        else if(val>=10&&val<=15) return char(val - 10 + 'a');
        return '?';
    }

    bool ParseMac(const std::string &input, Mac &out)
    {
        size_t idx = 0;
        int hi = -1;

        for(const char c : input)
        {
            if(c == '-' || c == ':')continue;

            int v = hexVal(c);
            if(v < 0)return false;

            if(hi < 0)hi = v;
            else
            {
                if(idx == 6)return false;
                out.bytes[idx++] = uint8_t((hi << 4) | v);
                hi = -1;
            }
        }

        if(idx != 6 || hi != -1)return false;
        return true;
    }
}

bool Mac::operator==(const Mac &m) const
{
    for(size_t i = 0; i < 6; i++)
    {
        if(bytes[i] != m.bytes[i])return false;
    }

    return true;
}

bool Mac::operator!=(const Mac &m) const
{
    for(size_t i = 0; i < 6; i++)
    {
        if(bytes[i] != m.bytes[i])return true;
    }

    return false;
}

bool Mac::operator<(const Mac &m) const
{
    for(size_t i = 0; i < 6; i++)
    {
        if (bytes[i] != m.bytes[i])
            return bytes[i] < m.bytes[i];
    }

    return false;
}

bool Mac::IsGroup() const { return (bytes[0] & 0x01) != 0; }

bool Mac::TryParse(const std::string &s, Mac &out){ return ParseMac(s, out);}

std::string Mac::ToString() const
{
    std::string out;

    for (size_t i = 0; i < 6; i++)
    {
        out += hexChar(bytes[i] >> 4);
        out += hexChar(bytes[i] & 0xF);
        if (i < 5) out += ':';
    }

    return out;
}

Mac Mac::Zero()
{
    return Mac(0, 0, 0, 0, 0, 0);
}

Mac Mac::Broadcast()
{
    return Mac(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
}

Mac::Mac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f):bytes{a,b,c,d,e,f}{}

Mac::Mac(const std::string &s)
{
    if (!ParseMac(s, *this))
        throw std::invalid_argument("Mac: invalid \"" + s + "\"");
}
