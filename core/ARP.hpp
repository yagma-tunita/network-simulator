#pragma once

#include "Mac.hpp"
#include "Ipv4.hpp"
#include <cstdint>
#include <vector>
#include <string>

struct ARP
{
    static constexpr uint16_t kRequest = 1;
    static constexpr uint16_t kReply   = 2;

    uint16_t op = 0;
    Mac senderMac;
    Ipv4 senderIp;
    Mac targetMac;
    Ipv4 targetIp;

    bool operator==(const ARP &msg)const;
    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, ARP &out);
    std::string ToString() const;

    static ARP MakeRequest(Ipv4 senderip, Mac sendermac, Ipv4 targetip);
    static ARP MakeReply(Ipv4 senderip, Mac sendermac, Ipv4 targetip, Mac targetmac);

    bool IsRequest() const;
    bool IsReply() const;

    ARP() = default;
    ARP(uint16_t op, Mac sendermac, Ipv4 senderip, Mac targetmac, Ipv4 targetip);
};
