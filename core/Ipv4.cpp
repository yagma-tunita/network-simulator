#include "Ipv4.hpp"

#include <stdexcept>

namespace
{
    bool ParseU32(const std::string &input, uint32_t &out)
    {
        uint32_t result   = 0;
        uint32_t temp     = 0;
        uint32_t offset   = 24;
        int      segments = 1;
        int      digits   = 0;

        for (const char c : input)
        {
            if (c == '.')
            {
                if (digits == 0)
                    return false;
                result |= temp << offset;
                temp = 0;
                digits = 0;
                offset -= 8;
                if (++segments > 4)
                    return false;
            }
            else if (c >= '0' && c <= '9')
            {
                if (++digits > 3)
                    return false;
                temp = temp * 10 + (c - '0');
                if (temp > 255)
                    return false;
            }
            else
                return false;
        }

        if (digits == 0)
            return false;
        result |= temp << offset;

        if (segments != 4)
            return false;

        out = result;
        return true;
    }

    uint32_t StoU32(const std::string &input)
    {
        uint32_t value;
        if (!ParseU32(input, value))
            throw std::invalid_argument("Ipv4: invalid address \"" + input + "\"");
        return value;
    }

    std::string U32toS(uint32_t value)
    {
        uint8_t a = (value >> 24) & 0xFF;
        uint8_t b = (value >> 16) & 0xFF;
        uint8_t c = (value >> 8) & 0xFF;
        uint8_t d = (value >> 0) & 0xFF;

        return 
            std::to_string(a) + "." + 
            std::to_string(b) + "." +
            std::to_string(c) + "." +
            std::to_string(d);
    }
}

bool Ipv4::operator==(const Ipv4 &o) const{ return value == o.value;}

bool Ipv4::operator<(const Ipv4 &o) const{ return value < o.value;}


Ipv4 Ipv4::operator&(const Ipv4 &o) const{ return Ipv4(value & o.value);}

Ipv4 Ipv4::Any() { return Ipv4(0u); }

Ipv4 Ipv4::Broadcast() { return Ipv4(0xFFFFFFFFu); }

Ipv4::Ipv4(uint32_t v) : value(v) {}

Ipv4::Ipv4(const std::string &s):value(StoU32(s)){}

Ipv4::Ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
    : value((uint32_t(a) << 24) |
            (uint32_t(b) << 16) |
            (uint32_t(c) <<  8) |
             uint32_t(d))
{}

std::string Ipv4::ToString() const{ return U32toS(value);}

bool Ipv4::TryParse(const std::string &s, Ipv4 &out)
{
    uint32_t value;
    if (!ParseU32(s, value))
        return false;
    out.value = value;
    return true;
}


