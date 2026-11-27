#include "Port.hpp"
#include "../link/Link.hpp"
#include "Device.hpp"
#include "../core/IpPacket.hpp"
#include "../engine/Clock.hpp"
#include <utility>
#include <algorithm>

const char *DropReasonName(DropReason reason)
{
    switch(reason)
    {
        case DropReason::LinkDown: return "link-down";
        case DropReason::Loss: return "loss";
        case DropReason::Mtu: return "mtu";
        case DropReason::Acl: return "acl";
        case DropReason::Ttl: return "ttl";
        case DropReason::NoRoute: return "no-route";
        case DropReason::NoEgress: return "no-egress";
        case DropReason::ArpPending: return "arp-pending";
        case DropReason::Fragment: return "fragment";
        case DropReason::Stp: return "stp";
        case DropReason::Vlan: return "vlan";
        case DropReason::Parse: return "parse";
        case DropReason::Resource: return "resource";
        default: return "none";
    }
}

void Port::Send(FramePtr frame)
{
    if(!link) return;
    link->Transmit(this, std::move(frame));
}

void Port::Receive(FramePtr frame)
{
    ++rx;
    if(!owner) return;

    if(frame->type == EthernetFrame::kIPv4)
    {
        IpPacket pkt;
        if(IpPacket::TryFromBytes(frame->payload, pkt) && pkt.IsFragment())
        {
            if(!HandleIpFragment(frame, pkt))
                return;
        }
    }
    owner->OnFrame(this, std::move(frame));
}

bool Port::HandleIpFragment(FramePtr &frame, const IpPacket &pkt)
{
    uint64_t now = owner && owner->clock ? owner->clock->Now() : 0;
    for(auto it = ipFragments.begin(); it != ipFragments.end();)
    {
        if(now > it->second.lastSeen + 300)
            it = ipFragments.erase(it);
        else
            ++it;
    }

    IpFragKey key{ pkt.srcIp.value, pkt.dstIp.value,
                   pkt.identification, pkt.protocol };
    if(ipFragments.find(key) == ipFragments.end() &&
       ipFragments.size() >= kMaxFragBuffers)
    {
        CountDrop(DropReason::Fragment);
        return false;
    }

    IpFragBuffer &buf = ipFragments[key];
    uint32_t offset = uint32_t(pkt.fragmentOffset) * 8;
    uint32_t totalSize = uint32_t(offset + pkt.payload.size());
    if(totalSize > 65535)
    {
        ipFragments.erase(key);
        CountDrop(DropReason::Fragment);
        return false;
    }

    buf.lastSeen = now;
    buf.chunks[offset] = pkt.payload;
    if(!pkt.moreFragments)
    {
        buf.total = totalSize;
        buf.hasLast = true;
    }
    if(!buf.hasLast)
        return false;

    uint32_t filled = 0;
    for(const auto &kv : buf.chunks)
    {
        if(kv.first > filled)
            return false;
        filled = std::max(filled, kv.first + uint32_t(kv.second.size()));
    }
    if(filled < buf.total)
        return false;

    std::vector<uint8_t> data(buf.total);
    for(const auto &kv : buf.chunks)
    {
        if(kv.first >= buf.total)
            continue;
        std::size_t len = std::min<std::size_t>(
            kv.second.size(), buf.total - kv.first);
        std::copy_n(kv.second.begin(), len, data.begin() + kv.first);
    }

    IpPacket full(pkt.srcIp, pkt.dstIp, pkt.protocol, std::move(data));
    full.ttl = pkt.ttl;
    full.ecn = pkt.ecn;
    EthernetFrame out = *frame;
    out.payload = full.ToBytes();
    frame = std::make_shared<const EthernetFrame>(out);
    ipFragments.erase(key);
    return true;
}

void Port::SetIp(Ipv4 newip, uint8_t prefix)
{
    ip = newip;
    subnet = Ipv4Subnet(newip, prefix);
    hasIp = true;
}

void Port::Attach(Link *l){ link = l;}

Port::Port(Mac mac, Device *owner, Ipv4 newip, uint8_t prefix, Link *l)
    :mac(mac), owner(owner)
{
    SetIp(newip, prefix);
    Attach(l);
}
