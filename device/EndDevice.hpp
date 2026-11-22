#pragma once

#include "Device.hpp"
#include "ArpAgent.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Mac.hpp"
#include "../core/IpPacket.hpp"
#include <cstdint>
#include <cstddef>
#include <map>
#include <vector>

struct EndDevice : Device
{
    struct PingOutstanding
    {
        Ipv4 dst;
        uint64_t sentAt = 0;
        bool sent = false;
    };

    struct PendingPing
    {
        Port *egress = nullptr;
        Ipv4 nextHop;
        IpPacket pkt;
        uint16_t seq = 0;
    };

    static constexpr std::size_t kMaxPending = 64;
    static constexpr uint64_t kPingTimeout = 50;

    ArpAgent arp;

    Ipv4 gateway;
    bool hasGateway = false;

    std::map<uint16_t, PingOutstanding> outstanding;
    std::vector<PendingPing> pendingPings;
    uint16_t nextPingSeq = 0;
    uint64_t droppedPending = 0;

    void OnFrame(Port *port, FramePtr frame) override;
    void SetClock(Clock *c) override;
    void SetGateway(const Ipv4 &gw) { gateway = gw; hasGateway = true; }
    void SendArpRequest(Ipv4 targetIp);
    bool Lookup(Ipv4 ip, Mac &outMac);
    void SendPing(Ipv4 targetIp, uint16_t seq = 0, uint8_t ttl = IpPacket::kDefaultTtl);
    void HandleIp(Port *port, FramePtr frame);
    void FlushPending();
    void OnPingTimeout(uint16_t seq);

    EndDevice() = default;
};
