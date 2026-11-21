#pragma once

#include "../core/EthernetFrame.hpp"

struct Port;

struct Link
{
    Port *A = nullptr;
    Port *B = nullptr;

    void Transmit(Port *from, const EthernetFrame &frame);
    Port* Other(Port*from) const;
    bool IsConnected() const;
    void Connected(Port *x, Port *y);

    Link() = default;
    Link(Port *A, Port *B);
};
