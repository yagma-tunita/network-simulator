#pragma once

#include "../core/Mac.hpp"
#include "Device.hpp"
#include <map>
#include <cstdint>


struct Switch : Device
{
    struct Entry
    {
        Port*    port = nullptr;
        uint64_t lastSeen = 0;
    };

    static constexpr uint64_t kAgingTimeout = 300;

    std::map<Mac, Entry> macTable;

    void OnFrame(Port* port, const EthernetFrame& frame) override;
    void Flood(Port* except, const EthernetFrame& frame);
    void AgeOut(uint64_t now);
};
