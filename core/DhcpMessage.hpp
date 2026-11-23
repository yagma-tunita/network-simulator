#pragma once

#include "Ipv4.hpp"
#include "Mac.hpp"
#include <cstdint>
#include <vector>

struct DhcpMessage
{
    enum Op : uint8_t { BootRequest = 1, BootReply = 2 };
    enum Type : uint8_t
    {
        Discover = 1,
        Offer = 2,
        Request = 3,
        Decline = 4,
        Ack = 5,
        Nak = 6,
        Release = 7
    };

    uint8_t op = 0;
    uint8_t htype = 1;
    uint8_t hlen = 6;
    uint8_t hops = 0;
    uint32_t xid = 0;
    uint16_t secs = 0;
    uint16_t flags = 0;
    Ipv4 ciaddr;
    Ipv4 yiaddr;
    Ipv4 siaddr;
    Ipv4 giaddr;
    Mac chaddr;

    uint8_t type = 0;

    bool hasServerId = false;
    Ipv4 serverId;

    bool hasRequested = false;
    Ipv4 requestedIp;

    bool hasLease = false;
    uint32_t leaseTime = 0;

    bool hasSubnetMask = false;
    Ipv4 subnetMask;

    bool hasRouter = false;
    Ipv4 router;

    bool hasDns = false;
    Ipv4 dns;

    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, DhcpMessage &out);
};
