#pragma once

#include <cstdint>
#include <random>
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

    double lossPct = 0.0;
    double dupPct = 0.0;
    uint64_t jitter = 0;
    std::mt19937 rng{ 0x5eed1234u };

    void SetScheduler(Scheduler *s);
    void SetDelay(uint64_t d);
    void SetUp(bool up);
    bool IsUp() const { return enabled; }

    void SetLoss(double pct);
    void SetDup(double pct);
    void SetJitter(uint64_t max);
    void ClearImpair();

    void Transmit(Port *from, FramePtr frame);
    Port* Other(Port*from) const;
    bool IsConnected() const;
    void Connected(Port *x, Port *y);

    Link() = default;
    Link(Port *A, Port *B);
};
