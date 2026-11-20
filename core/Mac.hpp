#pragma once 

#include <cstdint>
#include <string>

struct Mac
{
    uint8_t bytes[6] = {};

    bool operator==(const Mac &m)const;
    bool operator!=(const Mac &m)const;
    bool operator<(const Mac &m)const;
    std::string ToString()const;

    static bool TryParse(const std::string &s, Mac &out);
    static Mac Zero();
    static Mac Broadcast();

    Mac() = default;
    Mac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);
    Mac(const std::string &s);
};
