#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include "../core/EthernetFrame.hpp"

struct Port;
struct Clock;
struct Scheduler;

struct Device
{
    struct LldpNeighbor
    {
        Port *port = nullptr;
        Mac chassis;
        std::string portId;
        uint64_t expires = 0;
    };

    std::vector<Port*> portList;
    Clock *clock = nullptr;
    Scheduler *scheduler = nullptr;
    bool lldpEnabled = false;
    uint64_t lldpGen = 0;
    std::vector<LldpNeighbor> lldpNeighbors;

    Device() = default;
    Device(const Device &) = delete;
    Device &operator=(const Device &) = delete;

    virtual void AddPort(Port *p);
    virtual void SetClock(Clock *c);
    void SetScheduler(Scheduler *s);
    void SetLldp(bool on);
    void LldpTick(uint64_t gen);
    void SendLldp(Port *port);
    bool HandleLldp(Port *port, FramePtr frame);

    virtual void OnLinkUp(Port *) {}
    virtual void OnLinkDown(Port *) {}

    virtual void OnFrame(Port *port, FramePtr frame) = 0;
    virtual ~Device() = default;
};
