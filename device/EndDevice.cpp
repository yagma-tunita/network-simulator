#include "EndDevice.hpp"
#include "Port.hpp"
#include "../core/IpPacket.hpp"
#include "../core/IcmpMessage.hpp"
#include "../engine/Clock.hpp"
#include "../engine/Scheduler.hpp"
#include "../engine/Event.hpp"
#include <memory>
#include <iostream>
#include <cstddef>

namespace
{
    struct PingTimeoutEvent : Event
    {
        EndDevice *dev;
        uint16_t seq;

        PingTimeoutEvent(EndDevice *d, uint16_t s) : dev(d), seq(s) {}

        void Execute(Engine &) override { dev->OnPingTimeout(seq); }
        const char *Name() const override { return "ping-timeout"; }
    };
}

void EndDevice::OnFrame(Port *port, FramePtr frame)
{
    if (!port)
        return;

    if ((port->mac != frame->dst) && !frame->IsBroadcast())
        return;

    if (frame->type == EthernetFrame::kARP)
    {
        arp.HandleArp(port, *frame);
        FlushPending();
    }
    else if (frame->type == EthernetFrame::kIPv4)
    {
        HandleIp(port, frame);
    }
}

void EndDevice::HandleIp(Port *port, FramePtr frame)
{
    IpPacket pkt;
    if (!IpPacket::TryFromBytes(frame->payload, pkt))
        return;
    if (!port->hasIp || !(pkt.dstIp == port->ip))
        return;
    if (pkt.protocol != IpPacket::kIcmp)
        return;

    IcmpMessage icmp;
    if (!IcmpMessage::TryFromBytes(pkt.payload, icmp))
        return;

    uint64_t now = clock ? clock->Now() : 0;

    if (icmp.type == IcmpMessage::kEchoRequest)
    {
        IcmpMessage reply = icmp;
        reply.type = IcmpMessage::kEchoReply;
        IpPacket out(port->ip, pkt.srcIp, IpPacket::kIcmp, reply.ToBytes());
        port->Send(std::make_shared<const EthernetFrame>(
            frame->src, port->mac, EthernetFrame::kIPv4, out.ToBytes()));
    }
    else if (icmp.type == IcmpMessage::kEchoReply)
    {
        auto it = outstanding.find(icmp.seq);
        if (it != outstanding.end() && it->second.sent)
        {
            uint64_t rtt = now - it->second.sentAt;
            std::cout << "ping reply from " << pkt.srcIp.ToString()
                      << " seq=" << icmp.seq << " time=" << rtt << "\n";
            outstanding.erase(it);
        }
        else
        {
            std::cout << "ping reply from " << pkt.srcIp.ToString()
                      << " seq=" << icmp.seq << "\n";
            if (it != outstanding.end())
                outstanding.erase(it);
        }
    }
    else if (icmp.type == IcmpMessage::kTimeExceeded ||
             icmp.type == IcmpMessage::kDestUnreachable)
    {
        std::cout << (icmp.type == IcmpMessage::kTimeExceeded
                          ? "icmp time exceeded from "
                          : "icmp unreachable from ")
                  << pkt.srcIp.ToString() << "\n";

        IpPacket orig;
        if (IpPacket::TryFromBytes(icmp.payload, orig) &&
            orig.protocol == IpPacket::kIcmp)
        {
            IcmpMessage oc;
            if (IcmpMessage::TryFromBytes(orig.payload, oc))
                outstanding.erase(oc.seq);
        }
    }
}

void EndDevice::SendArpRequest(Ipv4 targetIp)
{
    Port *chosen = nullptr;
    for (Port *p : portList)
    {
        if (p->hasIp && p->subnet.Contains(targetIp))
        {
            chosen = p;
            break;
        }
    }

    arp.SendArpRequest(targetIp, chosen);
}

bool EndDevice::Lookup(Ipv4 ip, Mac &outMac)
{
    return arp.Lookup(ip, outMac);
}

void EndDevice::SetClock(Clock *c)
{
    Device::SetClock(c);
    arp.SetClock(c);
}

void EndDevice::SendPing(Ipv4 targetIp, uint16_t seq, uint8_t ttl)
{
    Port *egress = nullptr;
    Ipv4 nextHop;

    for (Port *p : portList)
    {
        if (p->hasIp && p->subnet.Contains(targetIp))
        {
            egress = p;
            nextHop = targetIp;
            break;
        }
    }

    if (!egress)
    {
        if (!hasGateway)
            return;
        nextHop = gateway;
        for (Port *p : portList)
        {
            if (p->hasIp && p->subnet.Contains(gateway))
            {
                egress = p;
                break;
            }
        }
    }

    if (!egress)
        return;

    if (seq == 0)
        seq = ++nextPingSeq;

    IcmpMessage req;
    req.type = IcmpMessage::kEchoRequest;
    req.id = 0x1234;
    req.seq = seq;

    IpPacket pkt(egress->ip, targetIp, IpPacket::kIcmp, req.ToBytes());
    pkt.ttl = ttl;

    outstanding[seq] = PingOutstanding{ targetIp, 0, false };

    if (scheduler)
        scheduler->ScheduleAfter(kPingTimeout, std::make_unique<PingTimeoutEvent>(this, seq));

    Mac dstMac;
    if (arp.Lookup(nextHop, dstMac))
    {
        uint64_t now = clock ? clock->Now() : 0;
        outstanding[seq].sentAt = now;
        outstanding[seq].sent = true;
        egress->Send(std::make_shared<const EthernetFrame>(
            dstMac, egress->mac, EthernetFrame::kIPv4, pkt.ToBytes()));
    }
    else
    {
        if (pendingPings.size() < kMaxPending)
            pendingPings.push_back(PendingPing{ egress, nextHop, pkt, seq });
        else
            ++droppedPending;

        arp.SendArpRequest(nextHop, egress);
    }
}

void EndDevice::FlushPending()
{
    uint64_t now = clock ? clock->Now() : 0;

    for (auto it = pendingPings.begin(); it != pendingPings.end(); )
    {
        Mac mac;
        if (arp.Lookup(it->nextHop, mac))
        {
            auto o = outstanding.find(it->seq);
            if (o != outstanding.end())
            {
                o->second.sentAt = now;
                o->second.sent = true;
            }
            it->egress->Send(std::make_shared<const EthernetFrame>(
                mac, it->egress->mac, EthernetFrame::kIPv4, it->pkt.ToBytes()));
            it = pendingPings.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void EndDevice::OnPingTimeout(uint16_t seq)
{
    auto it = outstanding.find(seq);
    if (it == outstanding.end())
        return;

    std::cout << "ping timeout from " << it->second.dst.ToString()
              << " seq=" << seq << "\n";
    outstanding.erase(it);

    for (auto p = pendingPings.begin(); p != pendingPings.end(); )
    {
        if (p->seq == seq)
            p = pendingPings.erase(p);
        else
            ++p;
    }
}
