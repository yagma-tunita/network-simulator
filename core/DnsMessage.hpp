#pragma once

#include "Ipv4.hpp"
#include <cstdint>
#include <string>
#include <vector>

struct DnsQuestion
{
    std::string name;
    uint16_t qtype = 1;
    uint16_t qclass = 1;
};

struct DnsAnswer
{
    std::string name;
    uint16_t type = 1;
    uint16_t cls = 1;
    uint32_t ttl = 60;
    Ipv4 ip;
};

struct DnsMessage
{
    uint16_t id = 0;
    uint16_t flags = 0;
    std::vector<DnsQuestion> questions;
    std::vector<DnsAnswer> answers;

    bool IsResponse() const { return (flags & 0x8000u) != 0; }
    uint8_t Rcode() const { return uint8_t(flags & 0x000Fu); }

    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, DnsMessage &out);
};
