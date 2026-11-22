#include "ArpAgent.hpp"
#include "Port.hpp"
#include "../core/Aging.hpp"
#include "../core/EthernetFrame.hpp"
#include "../core/ARP.hpp"
#include "../engine/Clock.hpp"
#include <memory>

void ArpAgent::SetClock(Clock *c)
{
    clock = c;
}

uint64_t ArpAgent::Now() const
{
    return clock ? clock->Now() : 0;
}

bool ArpAgent::Lookup(Ipv4 ip, Mac &outMac)
{
    auto it = cache.find(ip);
    if (it == cache.end())
        return false;

    uint64_t now = Now();
    if (now - it->second.lastSeen > kTimeout)
    {
        cache.erase(it);
        return false;
    }

    it->second.lastSeen = now;
    outMac = it->second.mac;
    return true;
}

void ArpAgent::Learn(Ipv4 ip, const Mac &mac)
{
    Entry &e = cache[ip];
    e.mac = mac;
    e.lastSeen = Now();
}

void ArpAgent::AgeOut(uint64_t now)
{
    AgeOutEntries(cache, now, kTimeout);
}

void ArpAgent::HandleArp(Port *port, const EthernetFrame &frame)
{
    if (!port)
        return;

    AgeOut(Now());

    ARP msg;
    if (!ARP::TryFromBytes(frame.payload, msg))
        return;

    if (msg.IsRequest())
    {
        if (port->hasIp && msg.targetIp == port->ip)
        {
            ARP reply = ARP::MakeReply(port->ip, port->mac,
                                       msg.senderIp, msg.senderMac);
            port->Send(std::make_shared<const EthernetFrame>(
                msg.senderMac, port->mac, EthernetFrame::kARP, reply.ToBytes()));
        }
    }
    else if (msg.IsReply())
    {
        Learn(msg.senderIp, msg.senderMac);
    }
}

void ArpAgent::SendArpRequest(Ipv4 targetIp, Port *outPort)
{
    if (!outPort)
        return;

    ARP req = ARP::MakeRequest(outPort->ip, outPort->mac, targetIp);
    outPort->Send(std::make_shared<const EthernetFrame>(
        Mac::Broadcast(), outPort->mac, EthernetFrame::kARP, req.ToBytes()));
}
