#pragma once

#include "Device.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Mac.hpp"
#include "../core/IpPacket.hpp"
#include "../core/Ipv4Subnet.hpp"
#include <map>
#include <vector>

struct Port;

struct Route
{
    Ipv4Subnet dst;
    Ipv4 nextHop;
    bool direct = false;

    Route() = default;
};

struct Router :Device
{
    std::map<Ipv4, Mac>arpCache;
    std::vector<Route>routeTable;

    void OnFrame(Port* port, const EthernetFrame& frame) override;
    bool IsMyIp(Ipv4 ip) const;

    Router() = default;
};

