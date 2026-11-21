#pragma once

#include <cstdint>
#include <string>

struct Ipv4
{
    uint32_t value = 0;

    bool operator==(const Ipv4 &o)const;
    bool operator<(const Ipv4 &o)const;
    Ipv4 operator&(const Ipv4 &o)const;
    static Ipv4 Any();
    static Ipv4 Broadcast();

    static bool TryParse(const std::string &s, Ipv4 &out);

    Ipv4() = default;
    Ipv4(uint32_t v);
    Ipv4(const std::string &s);
    Ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

    std::string ToString()const;
};
