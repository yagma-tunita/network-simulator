#pragma once

#include "Ipv4.hpp"
#include "Ipv6.hpp"
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
    Ipv6 ip6;
    std::string target;
    uint16_t preference = 0;
    std::string mname;
    std::string rname;
    uint32_t serial = 1;
    uint32_t refresh = 3600;
    uint32_t retry = 600;
    uint32_t expire = 86400;
    uint32_t minimum = 60;
    std::string tsigAlgorithm;
    uint64_t tsigTime = 0;
    uint16_t tsigFudge = 0;
    std::vector<uint8_t> tsigMac;
    uint16_t tsigOriginalId = 0;
    uint16_t tsigError = 0;
    std::vector<uint8_t> tsigOther;
    bool noRdata = false;
};

struct DnsTsig
{
    bool present = false;
    std::string keyName;
    std::string algorithm;
    uint64_t timeSigned = 0;
    uint16_t fudge = 300;
    std::vector<uint8_t> mac;
    uint16_t originalId = 0;
    uint16_t error = 0;
    std::vector<uint8_t> other;
};

struct DnsMessage
{
    static constexpr uint16_t kTypeA = 1;
    static constexpr uint16_t kTypeNs = 2;
    static constexpr uint16_t kTypeCname = 5;
    static constexpr uint16_t kTypeSoa = 6;
    static constexpr uint16_t kTypePtr = 12;
    static constexpr uint16_t kTypeMx = 15;
    static constexpr uint16_t kTypeAaaa = 28;
    static constexpr uint16_t kTypeOpt = 41;
    static constexpr uint16_t kTypeTsig = 250;
    static constexpr uint16_t kTypeIxfr = 251;
    static constexpr uint16_t kTypeAxfr = 252;

    uint16_t id = 0;
    uint16_t flags = 0;
    std::vector<DnsQuestion> questions;
    std::vector<DnsAnswer> answers;
    std::vector<DnsAnswer> authority;
    std::vector<DnsAnswer> additional;
    bool hasOpt = false;
    uint16_t optUdpSize = 512;
    uint8_t optVersion = 0;
    uint16_t optFlags = 0;
    DnsTsig tsig;

    bool IsResponse() const { return (flags & 0x8000u) != 0; }
    uint8_t Rcode() const { return uint8_t(flags & 0x000Fu); }
    uint8_t Opcode() const { return uint8_t((flags >> 11) & 0x0Fu); }
    void SetOpcode(uint8_t opcode)
    {
        flags = uint16_t((flags & ~0x7800u) | ((uint16_t(opcode) & 0x0Fu) << 11));
    }

    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, DnsMessage &out);
    static bool TsigAlgorithmValid(const std::string &algorithm);
    bool SignTsig(const std::string &secret,
                  const std::vector<uint8_t> *requestMac = nullptr);
    bool VerifyTsig(const std::string &secret,
                    const std::vector<uint8_t> *requestMac = nullptr) const;
};
