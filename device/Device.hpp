#pragma once

#include <vector>
#include "../core/EthernetFrame.hpp"

struct Port;

struct Device
{
    std::vector<Port*> portList;

    void AddPort(Port *p);

    virtual void OnFrame(Port *port, const EthernetFrame &frame) = 0;
    virtual ~Device() = default;
};
