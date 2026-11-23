#include "Engine.hpp"
#include <utility>

bool Engine::Step()
{
    if(queue.Empty()) return false;

    std::unique_ptr<Event> ev = queue.Pop();
    now = ev->time;
    if(trace) trace(ev->time, ev->Name());
    ev->Execute(*this);
    return true;
}

uint64_t Engine::Now() const { return now; }

void Engine::Run()
{
    stopped = false;
    halted = false;
    while(true)
    {
        if(halted) break;
        if(shouldStop && shouldStop()) { stopped = true; break; }
        if(!Step()) break;
    }
}

void Engine::RunUntil(uint64_t time)
{
    stopped = false;
    halted = false;
    while(!queue.Empty() && (queue.Top()->time <= time))
    {
        if(halted) break;
        if(shouldStop && shouldStop()) { stopped = true; break; }
        Step();
    }
}

void Engine::Reset()
{
    queue.Clear();
    now = 0;
    seq = 0;
}

void Engine::ScheduleAt(uint64_t time, std::unique_ptr<Event> ev)
{
    if(maxEvents > 0 && queue.Size() >= maxEvents)
    {
        halted = true;
        return;
    }

    if(time < now) time = now;

    ev->time = time;
    ev->seq = seq;
    seq++;
    queue.Push(std::move(ev));
}

void Engine::ScheduleAfter(uint64_t delay, std::unique_ptr<Event> ev){ ScheduleAt(now + delay, std::move(ev));}

void Engine::TapFrame(uint64_t time, const EthernetFrame &frame)
{
    if(frameTap) frameTap(time, frame);
}


