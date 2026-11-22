#pragma once

#include "Event.hpp"
#include "Scheduler.hpp"
#include "Clock.hpp"
#include "EventQueue.hpp"
#include <cstdint>
#include <memory>
#include <functional>

struct EthernetFrame;

struct Engine: Scheduler, Clock
{
    EventQueue queue;
    uint64_t now = 0;
    uint64_t seq = 0;
    std::function<void(uint64_t, const char *)> trace;
    std::function<void(uint64_t, const EthernetFrame &)> frameTap;
    std::function<bool()> shouldStop;
    bool stopped = false;

    bool Step();
    uint64_t Now() const override;
    void Run();
    void RunUntil(uint64_t time);
    void Reset();

    void ScheduleAt(uint64_t time, std::unique_ptr<Event> ev);
    void ScheduleAfter(uint64_t delay, std::unique_ptr<Event> ev) override;
    void TapFrame(uint64_t time, const EthernetFrame &frame) override;
};
