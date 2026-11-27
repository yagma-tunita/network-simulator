#include "Switch.hpp"
#include "Port.hpp"
#include "StpBpdu.hpp"
#include "../core/Aging.hpp"
#include "../engine/Clock.hpp"
#include "../engine/Scheduler.hpp"
#include "../engine/Event.hpp"
#include <memory>
#include <iostream>
#include <cstddef>

namespace
{
    struct StpTuple
    {
        uint16_t rootPriority;
        Mac rootMac;
        uint32_t cost;
        uint16_t bridgePriority;
        Mac bridgeMac;
        uint16_t portId;
    };

    bool Less(const StpTuple &a, const StpTuple &b)
    {
        if(a.rootPriority != b.rootPriority) return a.rootPriority < b.rootPriority;
        if(a.rootMac != b.rootMac) return a.rootMac < b.rootMac;
        if(a.cost != b.cost) return a.cost < b.cost;
        if(a.bridgePriority != b.bridgePriority) return a.bridgePriority < b.bridgePriority;
        if(a.bridgeMac != b.bridgeMac) return a.bridgeMac < b.bridgeMac;
        return a.portId < b.portId;
    }

    const char *StateName(StpPortState s)
    {
        switch(s)
        {
        case StpPortState::Disabled:   return "disabled";
        case StpPortState::Blocking:   return "blocking";
        case StpPortState::Listening:  return "listening";
        case StpPortState::Learning:   return "learning";
        case StpPortState::Forwarding: return "forwarding";
        }
        return "?";
    }

    struct StpStateEvent : Event
    {
        Switch *sw;
        std::size_t idx;
        int phase;

        StpStateEvent(Switch *s, std::size_t i, int p) : sw(s), idx(i), phase(p) {}

        void Execute(Engine &) override { sw->OnStpTimer(idx, phase); }
        const char *Name() const override { return "stp-state"; }
    };

    struct StpHelloEvent : Event
    {
        Switch *sw;
        explicit StpHelloEvent(Switch *s) : sw(s) {}

        void Execute(Engine &) override { sw->OnStpHello(); }
        const char *Name() const override { return "stp-hello"; }
    };
}

void Switch::OnFrame(Port *port, FramePtr frame)
{
    if(!port) return;

    if(frame->type == EthernetFrame::kSTP)
    {
        HandleBpdu(port, *frame);
        return;
    }

    if(stpEnabled &&
       port->stpState != StpPortState::Learning &&
       port->stpState != StpPortState::Forwarding)
    {
        port->CountDrop(DropReason::Stp);
        return;
    }

    if(spanSource == port && spanDest && spanDest != port)
        Emit(spanDest, frame->HasVlan() ? frame->VlanId() : port->vlan, frame);

    uint64_t now = clock ? clock->Now() : 0;

    if(now - lastSweep >= kSweepInterval)
    {
        AgeOut(now);
        lastSweep = now;
    }

    uint16_t vid = frame->HasVlan() ? frame->VlanId() : port->vlan;

    if(!frame->src.IsGroup())
        macTable[{vid, frame->src}] = Entry{ port, now };

    if(frame->dst.IsGroup())
    {
        Flood(port, vid, frame);
        return;
    }

    Port* outPort = nullptr;
    auto it = macTable.find({vid, frame->dst});
    if(it != macTable.end())
        outPort = it->second.port;

    if(outPort == nullptr) Flood(port, vid, frame);
    else if(outPort != port) Emit(outPort, vid, frame);
}

void Switch::Emit(Port *out, uint16_t vid, FramePtr frame)
{
    if(stpEnabled && out->stpState != StpPortState::Forwarding)
    {
        out->CountDrop(DropReason::Stp);
        return;
    }

    if(out->tagged)
    {
        if(frame->HasVlan() && frame->VlanId() == vid)
            out->Send(frame);
        else
            out->Send(std::make_shared<const EthernetFrame>(
                frame->WithVlan(vid, frame->vlanPcp, frame->vlanDei)));
        return;
    }

    if(out->vlan != vid)
    {
        out->CountDrop(DropReason::Vlan);
        return;
    }

    if(frame->HasVlan())
        out->Send(std::make_shared<const EthernetFrame>(frame->WithoutVlan()));
    else
        out->Send(frame);
}

void Switch::Flood(Port *except, uint16_t vlan, FramePtr frame)
{
    for(Port* p : portList)
        if(p != except) Emit(p, vlan, frame);
}

void Switch::AgeOut(uint64_t now)
{
    AgeOutEntries(macTable, now, kAgingTimeout);
}

Mac Switch::ComputeBridgeMac() const
{
    Mac m = Mac::Broadcast();
    bool any = false;
    for(Port* p : portList)
    {
        if(!any || p->mac < m) { m = p->mac; any = true; }
    }
    return any ? m : Mac::Zero();
}

uint16_t Switch::StpPortId(Port *port) const
{
    for(std::size_t i = 0; i < portList.size(); ++i)
        if(portList[i] == port) return uint16_t(i + 1);
    return 0;
}

void Switch::SetStpEnabled(bool on)
{
    if(on == stpEnabled)
    {
        if(on) SendBpdus();
        return;
    }

    stpEnabled = on;

    if(on)
    {
        if(!stpBridgeMacSet)
        {
            stpBridgeMac = ComputeBridgeMac();
            stpBridgeMacSet = true;
        }
        for(Port* p : portList)
        {
            p->stpState = StpPortState::Blocking;
            p->stpRole = StpPortRole::None;
        }
        stpRootPriority = stpBridgePriority;
        stpRootMac = stpBridgeMac;
        stpRootCost = 0;
        stpRootPort = -1;
        RecomputeStp();
        SendBpdus();
        ScheduleHello();
    }
    else
    {
        for(Port* p : portList)
        {
            p->stpState = StpPortState::Forwarding;
            p->stpRole = StpPortRole::None;
        }
    }
}

void Switch::SetBridgePriority(uint16_t prio)
{
    stpBridgePriority = prio;
    if(stpEnabled)
    {
        RecomputeStp();
        SendBpdus();
    }
}

void Switch::SetStpRapid(bool rapid)
{
    rstp = rapid;
    if(stpEnabled)
    {
        RecomputeStp();
        SendBpdus();
    }
}

void Switch::ScheduleHello()
{
    if(!scheduler || !stpEnabled) return;
    scheduler->ScheduleAfter(kHello, std::make_unique<StpHelloEvent>(this));
}

void Switch::OnStpHello()
{
    if(!stpEnabled) return;

    uint64_t now = clock ? clock->Now() : 0;
    bool changed = false;

    for(Port *p : portList)
    {
        if(p->stpHasBest && now - p->stpBestAt > kMaxAge)
        {
            p->stpHasBest = false;
            changed = true;
        }
    }

    if(changed) RecomputeStp();
    SendBpdus();
    ScheduleHello();
}

void Switch::HandleBpdu(Port *port, const EthernetFrame &frame)
{
    if(!port) return;

    StpBpdu b;
    if(!StpBpdu::TryFromBytes(frame.payload, b)) return;
    if(stpBridgeMacSet && b.bridgeMac == stpBridgeMac) return;

    StpTuple nw{ b.rootPriority, b.rootMac, b.rootPathCost + port->stpCost,
                 b.bridgePriority, b.bridgeMac, b.portId };

    bool store = true;
    uint64_t now = clock ? clock->Now() : 0;
    if(port->stpHasBest)
    {
        StpTuple old{ port->stpBest.rootPriority, port->stpBest.rootMac,
                      port->stpBest.rootPathCost + port->stpCost,
                      port->stpBest.bridgePriority, port->stpBest.bridgeMac,
                      port->stpBest.portId };
        if(!Less(nw, old))
        {
            if(!Less(old, nw))
                port->stpBestAt = now;
            return;
        }
        store = Less(nw, old);
    }

    if(!store) return;

    port->stpBest = b;
    port->stpHasBest = true;
    port->stpBestAt = now;
    if(stpEnabled) RecomputeStp();
}

void Switch::RecomputeStp()
{
    if(!stpEnabled) return;

    StpTuple self{ stpBridgePriority, stpBridgeMac, 0,
                   stpBridgePriority, stpBridgeMac, 0 };
    StpTuple best = self;
    int bestPort = -1;

    for(std::size_t i = 0; i < portList.size(); ++i)
    {
        Port* p = portList[i];
        if(!p->stpHasBest) continue;
        StpTuple t{ p->stpBest.rootPriority, p->stpBest.rootMac,
                    p->stpBest.rootPathCost + p->stpCost,
                    p->stpBest.bridgePriority, p->stpBest.bridgeMac,
                    p->stpBest.portId };
        if(Less(t, best)) { best = t; bestPort = int(i); }
    }

    bool changed = (best.rootPriority != stpRootPriority) ||
                   (best.rootMac != stpRootMac) ||
                   (best.cost != stpRootCost) ||
                   (bestPort != stpRootPort);

    stpRootPriority = best.rootPriority;
    stpRootMac = best.rootMac;
    stpRootCost = best.cost;
    stpRootPort = bestPort;

    for(std::size_t i = 0; i < portList.size(); ++i)
    {
        Port* p = portList[i];

        bool isRoot = (int(i) == stpRootPort);
        bool designated = false;

        if(isRoot || stpRootPort < 0)
        {
            designated = true;
        }
        else
        {
            StpTuple mine{ stpRootPriority, stpRootMac, stpRootCost,
                           stpBridgePriority, stpBridgeMac, StpPortId(p) };
            designated = true;
            if(p->stpHasBest)
            {
                StpTuple recv{ p->stpBest.rootPriority, p->stpBest.rootMac,
                               p->stpBest.rootPathCost,
                               p->stpBest.bridgePriority, p->stpBest.bridgeMac,
                               p->stpBest.portId };
                designated = Less(mine, recv);
            }
        }

        if(designated)
        {
            p->stpRole = isRoot ? StpPortRole::Root : StpPortRole::Designated;

            if(rstp)
            {
                p->stpState = StpPortState::Forwarding;
                continue;
            }

            if(p->stpState == StpPortState::Forwarding ||
               p->stpState == StpPortState::Listening ||
               p->stpState == StpPortState::Learning)
            {
                continue;
            }

            if(!scheduler)
            {
                p->stpState = StpPortState::Forwarding;
                continue;
            }

            p->stpState = StpPortState::Listening;
            ScheduleStp(i, 1);
        }
        else
        {
            p->stpRole = StpPortRole::Alternate;
            p->stpState = StpPortState::Blocking;
        }
    }

    if(changed) SendBpdus();
}

void Switch::ScheduleStp(std::size_t idx, int phase)
{
    if(!scheduler) return;
    scheduler->ScheduleAfter(kForwardDelay, std::make_unique<StpStateEvent>(this, idx, phase));
}

void Switch::OnStpTimer(std::size_t idx, int phase)
{
    if(idx >= portList.size()) return;

    Port* p = portList[idx];
    bool forwardRole = (p->stpRole == StpPortRole::Root ||
                        p->stpRole == StpPortRole::Designated);

    if(!forwardRole)
    {
        p->stpState = StpPortState::Blocking;
        return;
    }

    if(phase == 1 && p->stpState == StpPortState::Listening)
    {
        p->stpState = StpPortState::Learning;
        ScheduleStp(idx, 2);
    }
    else if(phase == 2 && p->stpState == StpPortState::Learning)
    {
        p->stpState = StpPortState::Forwarding;
    }
}

void Switch::SendBpdus()
{
    for(Port* p : portList)
        SendBpdu(p);
}

void Switch::SendBpdu(Port *port)
{
    if(!port || !port->link) return;

    StpBpdu b;
    b.version = rstp ? StpBpdu::kRstpVersion : StpBpdu::kVersion;
    b.rootPriority = stpRootPriority;
    b.rootMac = stpRootMac;
    b.rootPathCost = stpRootCost;
    b.bridgePriority = stpBridgePriority;
    b.bridgeMac = stpBridgeMac;
    b.portId = StpPortId(port);

    port->Send(std::make_shared<const EthernetFrame>(
        StpBpdu::Multicast(), port->mac, EthernetFrame::kSTP, b.ToBytes()));
}

void Switch::PrintStp() const
{
    std::cout << "root=" << stpRootMac.ToString()
              << " cost=" << stpRootCost
              << " bridge=" << stpBridgeMac.ToString()
              << " mode=" << (rstp ? "rstp" : "stp") << "\n";
    for(std::size_t i = 0; i < portList.size(); ++i)
    {
        Port* p = portList[i];
        std::cout << "  p" << i << " " << StateName(p->stpState) << "\n";
    }
}

void Switch::OnLinkDown(Port *port)
{
    if(!port || !stpEnabled) return;
    macTable.clear();
    port->stpHasBest = false;
    port->stpState = StpPortState::Blocking;
    port->stpRole = StpPortRole::Alternate;
    RecomputeStp();
    SendBpdus();
}

void Switch::OnLinkUp(Port *port)
{
    if(!port || !stpEnabled) return;
    macTable.clear();
    port->stpHasBest = false;
    RecomputeStp();
    SendBpdus();
}
