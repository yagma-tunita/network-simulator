#pragma once

#include <cstdint>

struct Clock
{
    virtual ~Clock() = default;
    virtual uint64_t Now() const = 0;
};
