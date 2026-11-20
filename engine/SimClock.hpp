#pragma once

#include <cstdint>

namespace SimClock
{
    inline uint64_t g_now = 0;

    inline uint64_t Now() { return g_now; }
    inline void Advance(uint64_t delta) { g_now += delta; }
    inline void Reset() { g_now = 0; }
}
