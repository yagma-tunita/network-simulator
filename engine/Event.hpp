#pragma once

#include <cstdint>

struct Engine;

struct Event
{
    uint64_t time = 0;
    uint64_t seq = 0;
    bool cancelled = false;

    Event() = default;
    Event(const Event&) = delete;
    Event& operator=(const Event&) = delete;

    virtual ~Event() = default;
    virtual void Execute(Engine & engine) = 0;
    virtual const char* Name()const;
};
