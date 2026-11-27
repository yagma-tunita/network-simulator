#pragma once

#include "../core/Mac.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv6.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/EthernetFrame.hpp"
#include "StpBpdu.hpp"
#include <cstdint>
#include <map>
#include <vector>

struct Link;
struct Device;
struct IpPacket;

struct IpFragKey
{
    uint32_t src = 0;
    uint32_t dst = 0;
    uint16_t id = 0;
    uint8_t protocol = 0;

    bool operator<(const IpFragKey &o) const
    {
        if(src != o.src) return src < o.src;
        if(dst != o.dst) return dst < o.dst;
        if(id != o.id) return id < o.id;
        return protocol < o.protocol;
    }
};

struct IpFragBuffer
{
    std::map<uint32_t, std::vector<uint8_t>> chunks;
    uint32_t total = 0;
    bool hasLast = false;
    uint64_t lastSeen = 0;
};

enum class StpPortState
{
    Disabled,
    Blocking,
    Listening,
    Learning,
    Forwarding
};

enum class StpPortRole
{
    None,
    Root,
    Designated,
    Alternate
};

enum class DropReason : uint8_t
{
    None = 0,
    LinkDown,
    Loss,
    Mtu,
    Acl,
    Ttl,
    NoRoute,
    NoEgress,
    ArpPending,
    Fragment,
    Stp,
    Vlan,
    Parse,
    Resource,
    Count
};

constexpr std::size_t DropReasonCount =
    static_cast<std::size_t>(DropReason::Count);
const char *DropReasonName(DropReason reason);

struct Port
{
    Mac mac;
    uint16_t vlan = 0;
    bool tagged = false;
    bool hasIp = false;
    Ipv4 ip;
    Ipv4Subnet subnet;
    bool hasIp6 = false;
    Ipv6 ip6;
    uint8_t prefix6 = 64;

    uint32_t stpCost = 19;
    StpPortState stpState = StpPortState::Forwarding;
    StpPortRole stpRole = StpPortRole::None;
    bool stpHasBest = false;
    StpBpdu stpBest;
    uint64_t stpBestAt = 0;

    static constexpr std::size_t kMaxFragBuffers = 64;

    uint64_t rx = 0;
    uint64_t tx = 0;
    uint64_t drop = 0;
    uint64_t dropByReason[DropReasonCount] = {};

    void CountDrop(DropReason reason)
    {
        ++drop;
        ++dropByReason[static_cast<std::size_t>(reason)];
    }

    Link *link = nullptr;
    Device *owner = nullptr;
    std::map<IpFragKey, IpFragBuffer> ipFragments;

    void Send(FramePtr frame);
    void Receive(FramePtr frame);
    bool HandleIpFragment(FramePtr &frame, const IpPacket &pkt);

    void SetIp(Ipv4 newip, uint8_t prefix);
    void Attach(Link *l);

    Port() = default;
    Port(Mac mac, Device *owner, Ipv4 newip, uint8_t prefix, Link *l);
};
