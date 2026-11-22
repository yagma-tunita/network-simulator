#include "EventQueue.hpp"
#include <utility>

bool EventCompare::operator()(const std::unique_ptr<Event> &a, const std::unique_ptr<Event> &b) const
{
    if (a->time != b->time)
        return a->time > b->time;
    return a->seq > b->seq;
}

void EventQueue::Push(std::unique_ptr<Event> ev)
{
    pq.push(std::move(ev));
}

std::unique_ptr<Event> EventQueue::Pop()
{
    if(pq.empty()) return nullptr;

    std::unique_ptr<Event> ev = std::move(const_cast<std::unique_ptr<Event>&>(pq.top()));
    pq.pop();
    return ev;
}

const Event *EventQueue::Top() const
{
    if(pq.empty()) return nullptr;
    return pq.top().get();
}

void EventQueue::Clear()
{
    pq = Queue{};
}

bool EventQueue::Empty() const{ return pq.empty();}

std::size_t EventQueue::Size() const{ return pq.size();}
