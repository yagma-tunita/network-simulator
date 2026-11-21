#pragma once

#include <map>
#include "../core/Ipv4.hpp"
#include "../core/Mac.hpp"

struct Port;
struct EthernetFrame;


struct ArpAgent
{
    std::map<Ipv4, Mac> cache;


    bool Lookup(Ipv4 ip, Mac &outMac) const;



    void HandleArp(Port *port, const EthernetFrame &frame);


    void SendArpRequest(Ipv4 targetIp, Port *outPort);
};
