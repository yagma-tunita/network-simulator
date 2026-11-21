#pragma once

#include "Device.hpp"
#include "ArpAgent.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Mac.hpp"

struct EndDevice : Device
{
    ArpAgent arp;

    void OnFrame(Port *port, const EthernetFrame &frame) override;
    void SendArpRequest(Ipv4 targetIp);
    bool Lookup(Ipv4 ip, Mac &outMac);

    EndDevice() = default;
};
