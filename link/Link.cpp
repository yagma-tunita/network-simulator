#include "Link.hpp"
#include "../device/Port.hpp"
#include "../device/Device.hpp"
#include "../device/FrameDelivery.hpp"
#include "../engine/Scheduler.hpp"
#include <memory>
#include <utility>

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
    if(!enabled) return;

    Port *to = Other(from);
    if(to == nullptr) return;

    ++from->tx;

    if(lossPct > 0.0)
    {
        std::uniform_real_distribution<double> dist(0.0, 100.0);
        if(dist(rng) < lossPct)
        {
            ++from->drop;
            return;
        }
    }

    uint64_t extra = 0;
    if(jitter > 0)
    {
        std::uniform_int_distribution<uint64_t> dist(0, jitter);
        extra = dist(rng);
    }

    if(scheduler != nullptr)
        scheduler->TapFrame(scheduler->Now(), *frame);

    auto deliver = [&]() {
        if(scheduler != nullptr)
            scheduler->ScheduleAfter(delay + extra,
                std::make_unique<FrameDelivery>(to, frame));
        else
            to->Receive(frame);
    };

    deliver();

    if(dupPct > 0.0)
    {
        std::uniform_real_distribution<double> dist(0.0, 100.0);
        if(dist(rng) < dupPct)
            deliver();
    }
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
