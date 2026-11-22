#pragma once

#include <cstdint>
#include "../core/EthernetFrame.hpp"

struct Port;
struct Scheduler;

struct Link
{
    Port *A = nullptr;
    Port *B = nullptr;
    Scheduler *scheduler = nullptr;
    uint64_t delay = 1;
    bool enabled = true;

    void SetScheduler(Scheduler *s);
    void SetDelay(uint64_t d);
    void SetUp(bool up);
    bool IsUp() const { return enabled; }

    void Transmit(Port *from, FramePtr frame);
    Port* Other(Port*from) const;
    bool IsConnected() const;
    void Connected(Port *x, Port *y);

    Link() = default;
    Link(Port *A, Port *B);
};
