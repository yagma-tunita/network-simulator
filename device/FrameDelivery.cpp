#include "FrameDelivery.hpp"
#include "Port.hpp"
#include <utility>

void FrameDelivery::Execute(Engine &)
{
    if (to == nullptr)
        return;
    to->Receive(frame);
}

const char *FrameDelivery::Name() const
{
    return "frame";
}

FrameDelivery::FrameDelivery(Port *to, FramePtr frame)
    : to(to), frame(std::move(frame))
{}
