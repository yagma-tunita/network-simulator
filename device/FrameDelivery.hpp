#pragma once

#include "../core/EthernetFrame.hpp"
#include "../engine/Event.hpp"

struct Port;

struct FrameDelivery : Event
{
    Port *to = nullptr;
    FramePtr frame;

    void Execute(Engine &) override;
    const char *Name() const override;

    FrameDelivery() = default;
    FrameDelivery(Port *to, FramePtr frame);
};
