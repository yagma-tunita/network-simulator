#include "Device.hpp"

void Device::AddPort(Port *p)
{
    portList.push_back(p);
}

void Device::SetClock(Clock *c)
{
    clock = c;
}

void Device::SetScheduler(Scheduler *s)
{
    scheduler = s;
}
