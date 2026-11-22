#pragma once

#include "Device.hpp"
#include "ArpAgent.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/IpPacket.hpp"
#include <map>
#include <vector>
#include <cstddef>

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
        uint64_t enqueuedAt = 0;
    };

    static constexpr std::size_t kMaxPendingPerDest = 32;
    static constexpr uint64_t kPendingTimeout = 300;

    ArpAgent arp;
    std::vector<Route> routeTable;
    std::map<Ipv4, std::vector<Pending>> pending;
    uint64_t droppedPending = 0;

    void FlushPending();
    void AgeOutPending(uint64_t now);

    bool IsMyIp(Ipv4 ip) const;
    void AddRoute(const Ipv4Subnet &dst, const Ipv4 &nextHop, bool direct);
    void AddRoute(const Route &r);
    const Route* FindRoute(const Ipv4 &dstip) const;
    Port* PortForNextHop(const Ipv4 &ip);

    void AddPort(Port* p) override;
    void SetClock(Clock *c) override;
    void OnFrame(Port *port, FramePtr frame) override;
    void SendIcmpError(Port *ingress, const EthernetFrame &origin,
                       const IpPacket &pkt, uint8_t type);

    Router() = default;
};
