#pragma once

#include "../core/Mac.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/EthernetFrame.hpp"
#include "StpBpdu.hpp"
#include <cstdint>

struct Link;
struct Device;

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

struct Port
{
    Mac mac;
    uint16_t vlan = 0;
    bool tagged = false;
    bool hasIp = false;
    Ipv4 ip;
    Ipv4Subnet subnet;

    uint32_t stpCost = 19;
    StpPortState stpState = StpPortState::Forwarding;
    StpPortRole stpRole = StpPortRole::None;
    bool stpHasBest = false;
    StpBpdu stpBest;
    uint64_t stpBestAt = 0;

    uint64_t rx = 0;
    uint64_t tx = 0;
    uint64_t drop = 0;

    Link *link = nullptr;
    Device *owner = nullptr;

    void Send(FramePtr frame);
    void Receive(FramePtr frame);

    void SetIp(Ipv4 newip, uint8_t prefix);
    void Attach(Link *l);

    Port() = default;
    Port(Mac mac, Device *owner, Ipv4 newip, uint8_t prefix, Link *l);
};
