#include "Link.hpp"
#include "../device/Port.hpp"
#include "../device/Device.hpp"
#include "../device/FrameDelivery.hpp"
#include "../core/IpPacket.hpp"
#include "../engine/Scheduler.hpp"
#include <memory>
#include <utility>
#include <cstddef>

void Link::SetScheduler(Scheduler *s){ scheduler = s;}

void Link::SetDelay(uint64_t d){ delay = d;}

void Link::SetLoss(double pct)
{
    lossPct = pct < 0.0 ? 0.0 : (pct > 100.0 ? 100.0 : pct);
}

void Link::SetDup(double pct)
{
    dupPct = pct < 0.0 ? 0.0 : (pct > 100.0 ? 100.0 : pct);
}

void Link::SetJitter(uint64_t max)
{
    jitter = max;
}

void Link::ClearImpair()
{
    lossPct = 0.0;
    dupPct = 0.0;
    jitter = 0;
}

void Link::SetUp(bool up)
{
    if(enabled == up) return;
    enabled = up;

    Port *ends[2] = { A, B };
    for(Port *p : ends)
    {
        if(!p || !p->owner) continue;
        if(up) p->owner->OnLinkUp(p);
        else   p->owner->OnLinkDown(p);
    }
}

void Link::Transmit(Port *from, FramePtr frame)
{
    if(!enabled)
    {
        from->CountDrop(DropReason::LinkDown);
        return;
    }

    Port *to = Other(from);
    if(to == nullptr) return;

    ++from->tx;

    if(lossPct > 0.0)
    {
        std::uniform_real_distribution<double> dist(0.0, 100.0);
        if(dist(rng) < lossPct)
        {
            from->CountDrop(DropReason::Loss);
            return;
        }
    }

    uint64_t extra = 0;
    if(jitter > 0)
    {
        std::uniform_int_distribution<uint64_t> dist(0, jitter);
        extra = dist(rng);
    }

    auto deliver = [&](const FramePtr &f) {
        if(scheduler != nullptr)
            scheduler->ScheduleAfter(delay + extra,
                std::make_unique<FrameDelivery>(to, f));
        else
            to->Receive(f);
    };

    auto sendFrame = [&](const FramePtr &f) {
        if(scheduler != nullptr)
            scheduler->TapFrame(scheduler->Now(), *f);
        deliver(f);
        if(dupPct > 0.0)
        {
            std::uniform_real_distribution<double> dist(0.0, 100.0);
            if(dist(rng) < dupPct)
                deliver(f);
        }
    };

    if(frame->type == EthernetFrame::kIPv4 && mtu > IpPacket::kHeaderSize)
    {
        IpPacket pkt;
        if(IpPacket::TryFromBytes(frame->payload, pkt) &&
           pkt.dontFragment &&
           frame->payload.size() > mtu)
        {
            from->CountDrop(DropReason::Mtu);
            return;
        }
        if(IpPacket::TryFromBytes(frame->payload, pkt) &&
           !pkt.IsFragment() &&
           frame->payload.size() > mtu)
        {
            std::size_t maxPayload = (std::size_t(mtu) - IpPacket::kHeaderSize) &
                                     ~std::size_t(7);
            if(maxPayload >= 8)
            {
                uint16_t id = ++ipIdCounter;
                if(id == 0)
                    id = ++ipIdCounter;
                std::size_t total = pkt.payload.size();
                for(std::size_t offset = 0; offset < total; offset += maxPayload)
                {
                    std::size_t len = total - offset;
                    if(len > maxPayload)
                        len = maxPayload;
                    std::vector<uint8_t> chunk(
                        pkt.payload.begin() + std::ptrdiff_t(offset),
                        pkt.payload.begin() + std::ptrdiff_t(offset + len));
                    IpPacket frag(pkt.srcIp, pkt.dstIp, pkt.protocol,
                                  std::move(chunk));
                    frag.ttl = pkt.ttl;
                    frag.ecn = pkt.ecn;
                    frag.identification = id;
                    frag.fragmentOffset = uint16_t(offset / 8);
                    frag.moreFragments = offset + len < total;

                    EthernetFrame out = *frame;
                    out.payload = frag.ToBytes();
                    sendFrame(std::make_shared<const EthernetFrame>(out));
                }
                return;
            }
        }
    }

    sendFrame(frame);
}

Port *Link::Other(Port *from) const
{
    if(from == A) return B;
    if(from == B) return A;
    return nullptr;
}

bool Link::IsConnected() const { return (A != nullptr) && (B != nullptr);}

void Link::Connected(Port *x, Port *y)
{
    A = x;
    B = y;
    if(A != nullptr) A->Attach(this);
    if(B != nullptr) B->Attach(this);
}

Link::Link(Port *A, Port *B) :A(A),B(B)
{
    if(A != nullptr) A->Attach(this);
    if(B != nullptr) B->Attach(this);
}
