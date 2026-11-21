#include "Link.hpp"
#include "Port.hpp"

void Link::Transmit(Port *from, const EthernetFrame &frame)
{
    Port *to = Other(from);
    if(to == nullptr) return;
    to->Receive(frame);
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
