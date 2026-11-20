#pragma once

#include "Device.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Mac.hpp"
#include <map>

struct EndDevice : Device
{
    std::map<Ipv4, Mac> arpCache;

    void OnFrame(Port *port, const EthernetFrame &frame) override;
    void SendArpRequest(Ipv4 targetIp);
    void HandleArp(Port *port, const EthernetFrame &frame);
    bool Lookup(Ipv4 ip, Mac &outMac);

    EndDevice() = default;
};
