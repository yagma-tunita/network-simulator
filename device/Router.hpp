#pragma once

#include "Device.hpp"
#include "ArpAgent.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/IpPacket.hpp"
#include <vector>

struct Port;

struct Route
{
    Ipv4Subnet dst;
    Ipv4 nextHop;
    bool direct = false;

    Route() = default;
    Route(const Ipv4Subnet &dst, const Ipv4 &nextHop, bool direct);
};

struct Router : Device
{
    struct Pending
    {
        Port *egress;
        IpPacket pkt;
    };

    ArpAgent arp;
    std::vector<Route> routeTable;
    std::map<Ipv4, std::vector<Pending>> pending;

    void FlushPending();

    bool IsMyIp(Ipv4 ip) const;
    void AddRoute(const Ipv4Subnet &dst, const Ipv4 &nextHop, bool direct);
    void AddRoute(const Route &r);
    const Route* FindRoute(const Ipv4 &dstip) const;
    Port* PortForNextHop(const Ipv4 &ip);

    void AddPort(Port* p) override;
    void OnFrame(Port *port, const EthernetFrame &frame) override;

    Router() = default;
};
