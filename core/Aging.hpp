#pragma once

#include <cstdint>

template <class Table>
void AgeOutEntries(Table &table, uint64_t now, uint64_t timeout)
{
    auto it = table.begin();
    while(it != table.end())
    {
        if((now - it->second.lastSeen) > timeout)
            it = table.erase(it);
        else
            it++;
    }
}