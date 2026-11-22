#include "Switch.hpp"
#include "Port.hpp"
#include "../core/Aging.hpp"
#include "../engine/SimClock.hpp"

void Switch::OnFrame(Port *port, const EthernetFrame &frame)
{
    uint64_t now = SimClock::Now();
    AgeOut(now);

    if(!frame.src.IsGroup())
        macTable[frame.src] = Entry{ port, now };

    if(frame.dst.IsGroup())
    {
        Flood(port, frame);
        return;
    }
    Port* outPort = nullptr;
    if(macTable.find(frame.dst) != macTable.end())
        outPort = macTable[frame.dst].port;

    if(outPort == nullptr) Flood(port, frame);
    else if(outPort != port) outPort->Send(frame);
}

void Switch::Flood(Port *except, const EthernetFrame &frame)
{
    for(Port* p : portList)
        if(p != except) p->Send(frame);
}

void Switch::AgeOut(uint64_t now)
{
    AgeOutEntries(macTable, now, kAgingTimeout);
}
