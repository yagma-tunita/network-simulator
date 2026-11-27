#pragma once

#include <array>
#include <cstdint>
#include <string>

struct Ipv6
{
    std::array<uint8_t, 16> bytes{};

    Ipv6() = default;
    explicit Ipv6(const std::string &s);

    static bool TryParse(const std::string &s, Ipv6 &out);
    static Ipv6 Parse(const std::string &s);

    std::string ToString() const;
    bool IsAny() const;

    bool operator==(const Ipv6 &other) const { return bytes == other.bytes; }
    bool operator!=(const Ipv6 &other) const { return !(*this == other); }
    bool operator<(const Ipv6 &other) const { return bytes < other.bytes; }
};
