#pragma once

#include "../core/Mac.hpp"
#include "Device.hpp"
#include <map>
#include <utility>
#include <cstdint>
#include <cstddef>


struct Switch : Device
{
    struct Entry
    {
        Port*    port = nullptr;
        uint64_t lastSeen = 0;
    };

    static constexpr uint64_t kAgingTimeout = 300;
    static constexpr uint64_t kSweepInterval = 50;
    static constexpr uint64_t kForwardDelay = 15;
    static constexpr uint64_t kHello = 2;
    static constexpr uint64_t kMaxAge = 20;

    std::map<std::pair<uint16_t, Mac>, Entry> macTable;
    uint64_t lastSweep = 0;

    bool stpEnabled = false;
    bool rstp = false;
    bool stpBridgeMacSet = false;
    Mac stpBridgeMac;
    uint16_t stpBridgePriority = 32768;
    uint16_t stpRootPriority = 32768;
    Mac stpRootMac;
    uint32_t stpRootCost = 0;
    int stpRootPort = -1;

    void OnFrame(Port* port, FramePtr frame) override;
    void OnLinkUp(Port* port) override;
    void OnLinkDown(Port* port) override;
    void Emit(Port* out, uint16_t vid, FramePtr frame);
    void Flood(Port* except, uint16_t vlan, FramePtr frame);
    void AgeOut(uint64_t now);

    void SetStpEnabled(bool on);
    void SetStpRapid(bool rapid);
    void SetBridgePriority(uint16_t prio);
    void HandleBpdu(Port* port, const EthernetFrame &frame);
    void RecomputeStp();
    void SendBpdus();
    void SendBpdu(Port* port);
    void ScheduleHello();
    void OnStpHello();
    uint16_t StpPortId(Port* port) const;
    Mac ComputeBridgeMac() const;
    void ScheduleStp(std::size_t idx, int phase);
    void OnStpTimer(std::size_t idx, int phase);
    void PrintStp() const;
};
