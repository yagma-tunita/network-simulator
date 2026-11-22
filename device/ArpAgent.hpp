#pragma once

#include <map>
#include <cstdint>
#include "../core/Ipv4.hpp"
#include "../core/Mac.hpp"

struct Port;
struct EthernetFrame;
struct Clock;


struct ArpAgent
{
    struct Entry
    {
        Mac mac;
        uint64_t lastSeen = 0;
    };

    static constexpr uint64_t kTimeout = 300;

    std::map<Ipv4, Entry> cache;
    Clock *clock = nullptr;


    void SetClock(Clock *c);
    uint64_t Now() const;


    bool Lookup(Ipv4 ip, Mac &outMac);


    void HandleArp(Port *port, const EthernetFrame &frame);


    void SendArpRequest(Ipv4 targetIp, Port *outPort);


    void Learn(Ipv4 ip, const Mac &mac);
    void AgeOut(uint64_t now);
};
