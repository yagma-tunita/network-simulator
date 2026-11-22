#pragma once

#include <cstdint>
#include <memory>
#include "Event.hpp"

struct EthernetFrame;

struct Scheduler
{
    Scheduler() = default;
    Scheduler(const Scheduler&) = delete;
    Scheduler& operator=(const Scheduler&) = delete;

    virtual ~Scheduler() = default;
    virtual void ScheduleAfter(uint64_t delay, std::unique_ptr<Event>) = 0;

    virtual uint64_t Now() const { return 0; }
    virtual void TapFrame(uint64_t, const EthernetFrame &) {}
};
