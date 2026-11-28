#include "Device.hpp"
#include "Port.hpp"
#include "../link/Link.hpp"
#include "../core/Lldp.hpp"
#include "../engine/Clock.hpp"
#include "../engine/Scheduler.hpp"
#include "../engine/Event.hpp"
#include <memory>

namespace
{
    struct LldpEvent : Event
    {
        Device *dev;
        uint64_t gen;

        LldpEvent(Device *d, uint64_t g) : dev(d), gen(g) {}

        void Execute(Engine &) override { dev->LldpTick(gen); }
        const char *Name() const override { return "lldp"; }
    };
}

void Device::AddPort(Port *p)
{
    portList.push_back(p);
}

void Device::SetClock(Clock *c)
{
    clock = c;
}

void Device::SetScheduler(Scheduler *s)
{
    scheduler = s;
}

void Device::SetLldp(bool on)
{
    lldpEnabled = on;
    ++lldpGen;
    if(on)
        LldpTick(lldpGen);
}

void Device::LldpTick(uint64_t gen)
{
    if(!lldpEnabled || gen != lldpGen)
        return;

    for(Port *p : portList)
        SendLldp(p);

    if(scheduler)
        scheduler->ScheduleAfter(30,
            std::make_unique<LldpEvent>(this, gen));
}

void Device::SendLldp(Port *port)
{
    if(!port || !port->link)
        return;

    LldpFrame frame;
    frame.chassis = port->mac;
    frame.portId = "p";
    for(std::size_t i = 0; i < portList.size(); ++i)
        if(portList[i] == port)
        {
            frame.portId += std::to_string(i);
            break;
        }
    frame.ttl = 120;

    port->Send(std::make_shared<const EthernetFrame>(
        LldpFrame::Multicast(), port->mac, EthernetFrame::kLLDP,
        frame.ToBytes()));
}

bool Device::HandleLldp(Port *port, FramePtr frame)
{
    LldpFrame lldp;
    if(!LldpFrame::TryFromBytes(frame->payload, lldp))
        return true;

    uint64_t now = clock ? clock->Now() : 0;
    for(LldpNeighbor &n : lldpNeighbors)
        if(n.port == port && n.chassis == lldp.chassis)
        {
            n.portId = lldp.portId;
            n.expires = now + lldp.ttl;
            return true;
        }

    LldpNeighbor n;
    n.port = port;
    n.chassis = lldp.chassis;
    n.portId = lldp.portId;
    n.expires = now + lldp.ttl;
    lldpNeighbors.push_back(n);
    return true;
}
