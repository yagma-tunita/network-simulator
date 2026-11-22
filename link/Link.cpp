#include "Link.hpp"
#include "../device/Port.hpp"
#include "../device/Device.hpp"
#include "../device/FrameDelivery.hpp"
#include "../engine/Scheduler.hpp"
#include <memory>
#include <utility>

void Link::SetScheduler(Scheduler *s){ scheduler = s;}

void Link::SetDelay(uint64_t d){ delay = d;}

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

    if(scheduler != nullptr)
    {
        scheduler->TapFrame(scheduler->Now(), *frame);
        scheduler->ScheduleAfter(delay, std::make_unique<FrameDelivery>(to, std::move(frame)));
    }
    else
        to->Receive(std::move(frame));
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
