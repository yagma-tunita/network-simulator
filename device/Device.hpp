#pragma once

#include <vector>
#include "../core/EthernetFrame.hpp"

struct Port;
struct Clock;
struct Scheduler;

struct Device
{
    std::vector<Port*> portList;
    Clock *clock = nullptr;
    Scheduler *scheduler = nullptr;

    Device() = default;
    Device(const Device &) = delete;
    Device &operator=(const Device &) = delete;

    virtual void AddPort(Port *p);
    virtual void SetClock(Clock *c);
    void SetScheduler(Scheduler *s);

    virtual void OnLinkUp(Port *) {}
    virtual void OnLinkDown(Port *) {}

    virtual void OnFrame(Port *port, FramePtr frame) = 0;
    virtual ~Device() = default;
};
