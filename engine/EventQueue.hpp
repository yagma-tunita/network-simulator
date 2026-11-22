#pragma once

#include <queue>
#include <memory>
#include <vector>
#include <cstddef>
#include "Event.hpp"

struct EventCompare
{
    bool operator()(const std::unique_ptr<Event> &a, const std::unique_ptr<Event> &b) const;
};

struct EventQueue
{
    using Queue = std::priority_queue
        <
            std::unique_ptr<Event>,
            std::vector<std::unique_ptr<Event>>,
            EventCompare
        >;

    Queue pq;

    void Push(std::unique_ptr<Event> ev);
    std::unique_ptr<Event> Pop();
    const Event *Top() const;
    void Clear();
    bool Empty() const;
    std::size_t Size() const;

};
