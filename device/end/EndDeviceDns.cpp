#include "../EndDevice.hpp"
#include "../Port.hpp"
#include "../../link/Link.hpp"
#include "../../core/IpPacket.hpp"
#include "../../core/Ipv6Packet.hpp"
#include "../../core/Ipv6Subnet.hpp"
#include "../../core/IcmpMessage.hpp"
#include "../../core/Icmpv6Message.hpp"
#include "../../core/UdpDatagram.hpp"
#include "../../core/TcpSegment.hpp"
#include "../../engine/Clock.hpp"
#include "../../engine/Scheduler.hpp"
#include "../../engine/Event.hpp"
#include <memory>
#include <iostream>
#include <string>
#include <cstddef>
#include <cctype>
#include <algorithm>
#include <iterator>
#include <utility>

namespace
{
    struct DnsRetryEvent : Event
    {
        EndDevice *dev;
        uint64_t gen;

        DnsRetryEvent(EndDevice *d, uint64_t g) : dev(d), gen(g) {}

        void Execute(Engine &) override { dev->OnDnsTimeout(gen); }
        const char *Name() const override { return "dns-retry"; }
    };

    struct DnsSecondaryEvent : Event
    {
        EndDevice *dev;
        std::string zone;
        uint64_t gen;

        DnsSecondaryEvent(EndDevice *d, std::string z, uint64_t g)
            : dev(d), zone(std::move(z)), gen(g) {}

        void Execute(Engine &) override { dev->OnDnsSecondaryTimer(zone, gen); }
        const char *Name() const override { return "dns-secondary"; }
    };

    std::string LowerName(const std::string &name)
    {
        std::string key;
        key.reserve(name.size());
        for(char c : name)
            key.push_back(char(std::tolower(static_cast<unsigned char>(c))));
        return key;
    }

    bool IsSubdomain(const std::string &name, const std::string &zone)
    {
        if(name == zone)
            return true;
        if(name.size() <= zone.size())
            return false;
        std::size_t off = name.size() - zone.size();
        return name[off - 1] == '.' &&
               name.compare(off, zone.size(), zone) == 0;
    }

    bool SameDnsAnswer(const DnsAnswer &a, const DnsAnswer &b)
    {
        return a.name == b.name && a.type == b.type && a.ttl == b.ttl &&
               a.ip == b.ip && a.ip6 == b.ip6 &&
               a.target == b.target &&
               a.preference == b.preference;
    }

    bool ParseInAddrArpa(const std::string &name, uint32_t &out)
    {
        static const std::string suffix = ".in-addr.arpa";
        if(name.size() <= suffix.size() ||
           name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0)
            return false;

        std::size_t end = name.size() - suffix.size();
        uint32_t parts[4] = {0, 0, 0, 0};
        std::size_t pos = 0;
        int count = 0;
        while(pos < end)
        {
            if(count >= 4)
                return false;
            std::size_t dot = name.find('.', pos);
            if(dot == std::string::npos || dot > end)
                dot = end;
            if(dot == pos || dot - pos > 3)
                return false;
            uint32_t v = 0;
            for(std::size_t i = pos; i < dot; ++i)
            {
                if(!std::isdigit(static_cast<unsigned char>(name[i])))
                    return false;
                v = v * 10 + uint32_t(name[i] - '0');
            }
            if(v > 255)
                return false;
            parts[count++] = v;
            pos = dot + 1;
        }
        if(count != 4)
            return false;
        out = (parts[3] << 24) | (parts[2] << 16) |
              (parts[1] << 8) | parts[0];
        return true;
    }
}

void EndDevice::SetDnsServer(bool on)
{
    dnsServerEnabled = on;
}

void EndDevice::AddDnsRecord(const std::string &name, const Ipv4 &ip)
{
    std::string key;
    key.reserve(name.size());
    for(char c : name)
        key.push_back(char(std::tolower(static_cast<unsigned char>(c))));
    dnsRecords[key].push_back(ip);
    dnsReverse[ip.value] = key;
}

void EndDevice::AddDnsAaaa(const std::string &name, const Ipv6 &ip)
{
    std::string key = LowerName(name);
    dnsAaaa[key].push_back(ip);
}

void EndDevice::AddDnsCname(const std::string &alias, const std::string &target)
{
    std::string a;
    std::string t;
    for(char c : alias)
        a.push_back(char(std::tolower(static_cast<unsigned char>(c))));
    for(char c : target)
        t.push_back(char(std::tolower(static_cast<unsigned char>(c))));
    dnsCnames[a] = t;
}

void EndDevice::AddDnsMx(const std::string &name, uint16_t preference,
                         const std::string &exchange)
{
    std::string key;
    std::string target;
    for(char c : name)
        key.push_back(char(std::tolower(static_cast<unsigned char>(c))));
    for(char c : exchange)
        target.push_back(char(std::tolower(static_cast<unsigned char>(c))));
    dnsMxRecords[key].push_back(DnsMxRecord{ preference, target });
}

void EndDevice::SetDnsRrTtl(const std::string &name, uint16_t type,
                            uint32_t ttl)
{
    std::string key = LowerName(name);
    dnsRrTtl[std::make_pair(key, type)] = ttl;
}

uint32_t EndDevice::DnsRrTtl(const std::string &name, uint16_t type,
                             uint32_t fallback) const
{
    std::string key = LowerName(name);
    auto it = dnsRrTtl.find(std::make_pair(key, type));
    return it == dnsRrTtl.end() ? fallback : it->second;
}

void EndDevice::AddDnsZone(const std::string &zoneName)
{
    std::string zone = LowerName(zoneName);
    auto it = dnsZones.find(zone);
    if(it != dnsZones.end())
        return;

    DnsZone z;
    z.name = zone;
    z.mname = "ns." + zone;
    z.rname = "hostmaster." + zone;
    z.ttl = dnsTtl;
    z.minimum = dnsNegativeTtl;
    dnsZones[zone] = z;
}

void EndDevice::AddDnsSecondary(const std::string &zoneName,
                                const Ipv4 &primary)
{
    std::string zone = LowerName(zoneName);
    AddDnsZone(zone);
    DnsSecondaryState state;
    state.primary = primary;
    uint64_t now = clock ? clock->Now() : 0;
    state.expireAt = now + dnsZones[zone].expire;
    dnsSecondaryZones[zone] = state;
    StartDnsSecondaryTransfer(zone, primary);
}

void EndDevice::SetDnsNotifyTargets(const std::string &zoneName,
                                    const std::vector<Ipv4> &targets)
{
    dnsNotifyTargets[LowerName(zoneName)] = targets;
}

void EndDevice::NotifyDnsZone(const std::string &zoneName)
{
    std::string zone = LowerName(zoneName);
    auto it = dnsNotifyTargets.find(zone);
    if(it != dnsNotifyTargets.end())
        NotifyDnsZone(zone, it->second);
}

void EndDevice::NotifyDnsZone(const std::string &zoneName,
                              const std::vector<Ipv4> &targets)
{
    DnsMessage m;
    m.id = uint16_t(nextDnsId++);
    m.flags = 0;
    m.SetOpcode(4);
    m.questions.push_back(DnsQuestion{
        LowerName(zoneName), DnsMessage::kTypeSoa, 1 });
    std::vector<uint8_t> bytes = m.ToBytes();
    if(bytes.empty())
        return;

    std::string payload(bytes.begin(), bytes.end());
    for(const Ipv4 &target : targets)
        SendUdp(target, 53, payload, 53);
}

void EndDevice::StartDnsSecondaryTransfer(const std::string &zone,
                                          const Ipv4 &primary)
{
    std::string key = LowerName(zone);
    auto sit = dnsSecondaryZones.find(key);
    bool useIxfr = sit != dnsSecondaryZones.end() && sit->second.initialized;
    uint32_t serial = 0;
    auto zit = dnsZones.find(key);
    if(zit != dnsZones.end())
        serial = zit->second.serial;
    StartDnsAxfr(primary, key, true, useIxfr, serial);
}

void EndDevice::ApplyDnsSecondaryTransfer(
    const std::string &zoneName, const std::vector<DnsAnswer> &records)
{
    std::string zone = LowerName(zoneName);
    AddDnsZone(zone);

    for(auto it = dnsRecords.begin(); it != dnsRecords.end();)
    {
        if(IsSubdomain(it->first, zone))
        {
            for(const Ipv4 &ip : it->second)
            {
                auto rit = dnsReverse.find(ip.value);
                if(rit != dnsReverse.end() && rit->second == it->first)
                    dnsReverse.erase(rit);
            }
            it = dnsRecords.erase(it);
        }
        else
            ++it;
    }
    for(auto it = dnsAaaa.begin(); it != dnsAaaa.end();)
        it = IsSubdomain(it->first, zone) ? dnsAaaa.erase(it) : std::next(it);
    for(auto it = dnsCnames.begin(); it != dnsCnames.end();)
        it = IsSubdomain(it->first, zone) ? dnsCnames.erase(it)
                                          : std::next(it);
    for(auto it = dnsMxRecords.begin(); it != dnsMxRecords.end();)
        it = IsSubdomain(it->first, zone) ? dnsMxRecords.erase(it)
                                          : std::next(it);
    for(auto it = dnsNsRecords.begin(); it != dnsNsRecords.end();)
        it = IsSubdomain(it->first, zone) ? dnsNsRecords.erase(it)
                                          : std::next(it);
    for(auto it = dnsRrTtl.begin(); it != dnsRrTtl.end();)
        it = IsSubdomain(it->first.first, zone) ? dnsRrTtl.erase(it)
                                                : std::next(it);

    bool sawSoa = false;
    for(const DnsAnswer &a : records)
    {
        std::string name = LowerName(a.name);
        if(a.type == DnsMessage::kTypeSoa)
        {
            if(sawSoa)
                continue;
            sawSoa = true;
            DnsZone &z = dnsZones[zone];
            z.name = zone;
            z.mname = LowerName(a.mname);
            z.rname = LowerName(a.rname);
            z.ttl = a.ttl;
            z.serial = a.serial;
            z.refresh = a.refresh;
            z.retry = a.retry;
            z.expire = a.expire;
            z.minimum = a.minimum;
            continue;
        }
        if(!IsSubdomain(name, zone))
            continue;
        if(a.type == DnsMessage::kTypeNs)
        {
            std::vector<std::string> &ns = dnsNsRecords[name];
            std::string target = LowerName(a.target);
            bool seen = false;
            for(const std::string &v : ns)
                if(v == target) { seen = true; break; }
            if(!seen)
                ns.push_back(target);
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeNs)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeA)
        {
            dnsRecords[name].push_back(a.ip);
            dnsReverse[a.ip.value] = name;
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeA)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeAaaa)
        {
            dnsAaaa[name].push_back(a.ip6);
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeAaaa)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeCname)
        {
            dnsCnames[name] = LowerName(a.target);
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeCname)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeMx)
        {
            dnsMxRecords[name].push_back(
                DnsMxRecord{ a.preference, LowerName(a.target) });
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeMx)] = a.ttl;
        }
    }

    if(!sawSoa)
    {
        std::cout << "dns: secondary " << zone << " failed\n";
        return;
    }
    auto sit = dnsSecondaryZones.find(zone);
    if(sit != dnsSecondaryZones.end())
    {
        uint64_t now = clock ? clock->Now() : 0;
        sit->second.expired = false;
        sit->second.initialized = true;
        sit->second.expireAt = now + dnsZones[zone].expire;
        ScheduleDnsSecondary(zone, dnsZones[zone].refresh);
    }
    std::cout << "dns: secondary " << zone << " updated serial "
              << dnsZones[zone].serial << "\n";
}

void EndDevice::ApplyDnsSecondaryIxfr(
    const std::string &zoneName, const std::vector<DnsAnswer> &records,
    uint32_t clientSerial)
{
    std::string zone = LowerName(zoneName);
    if(records.empty())
    {
        std::cout << "dns: secondary " << zone << " failed\n";
        return;
    }

    if(records.size() == 1 && records[0].type == DnsMessage::kTypeSoa)
    {
        DnsZone &z = dnsZones[zone];
        z.name = zone;
        z.mname = LowerName(records[0].mname);
        z.rname = LowerName(records[0].rname);
        z.ttl = records[0].ttl;
        z.serial = records[0].serial;
        z.refresh = records[0].refresh;
        z.retry = records[0].retry;
        z.expire = records[0].expire;
        z.minimum = records[0].minimum;
        auto sit = dnsSecondaryZones.find(zone);
        if(sit != dnsSecondaryZones.end())
        {
            uint64_t now = clock ? clock->Now() : 0;
            sit->second.expired = false;
            sit->second.initialized = true;
            sit->second.expireAt = now + z.expire;
            ScheduleDnsSecondary(zone, z.refresh);
        }
        std::cout << "dns: secondary " << zone << " up-to-date serial "
                  << z.serial << "\n";
        return;
    }

    bool incremental = records.size() >= 2 &&
                       records[1].type == DnsMessage::kTypeSoa &&
                       records[1].serial == clientSerial;
    if(!incremental)
    {
        ApplyDnsSecondaryTransfer(zone, records);
        return;
    }

    DnsZone &z = dnsZones[zone];
    z.name = zone;
    z.mname = LowerName(records[0].mname);
    z.rname = LowerName(records[0].rname);
    z.ttl = records[0].ttl;
    z.serial = records[0].serial;
    z.refresh = records[0].refresh;
    z.retry = records[0].retry;
    z.expire = records[0].expire;
    z.minimum = records[0].minimum;

    auto removeRecord = [&](const DnsAnswer &a)
    {
        std::string name = LowerName(a.name);
        if(a.type == DnsMessage::kTypeA)
        {
            auto it = dnsRecords.find(name);
            if(it != dnsRecords.end())
            {
                auto &v = it->second;
                for(auto i = v.begin(); i != v.end();)
                {
                    if(*i == a.ip)
                    {
                        auto rit = dnsReverse.find(a.ip.value);
                        if(rit != dnsReverse.end() && rit->second == name)
                            dnsReverse.erase(rit);
                        i = v.erase(i);
                    }
                    else
                        ++i;
                }
                if(v.empty())
                {
                    dnsRecords.erase(it);
                    dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeA));
                }
            }
        }
        else if(a.type == DnsMessage::kTypeAaaa)
        {
            auto it = dnsAaaa.find(name);
            if(it != dnsAaaa.end())
            {
                auto &v = it->second;
                for(auto i = v.begin(); i != v.end();)
                    i = (*i == a.ip6) ? v.erase(i) : std::next(i);
                if(v.empty())
                {
                    dnsAaaa.erase(it);
                    dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeAaaa));
                }
            }
        }
        else if(a.type == DnsMessage::kTypeCname)
        {
            auto it = dnsCnames.find(name);
            if(it != dnsCnames.end() &&
               it->second == LowerName(a.target))
            {
                dnsCnames.erase(it);
                dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeCname));
            }
        }
        else if(a.type == DnsMessage::kTypeMx)
        {
            auto it = dnsMxRecords.find(name);
            if(it != dnsMxRecords.end())
            {
                auto &v = it->second;
                for(auto i = v.begin(); i != v.end();)
                {
                    if(i->preference == a.preference &&
                       i->exchange == LowerName(a.target))
                        i = v.erase(i);
                    else
                        ++i;
                }
                if(v.empty())
                {
                    dnsMxRecords.erase(it);
                    dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeMx));
                }
            }
        }
        else if(a.type == DnsMessage::kTypeNs)
        {
            auto it = dnsNsRecords.find(name);
            if(it != dnsNsRecords.end())
            {
                auto &v = it->second;
                for(auto i = v.begin(); i != v.end();)
                    i = (*i == LowerName(a.target)) ? v.erase(i)
                                                    : std::next(i);
                if(v.empty())
                {
                    dnsNsRecords.erase(it);
                    dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeNs));
                }
            }
        }
    };

    auto addRecord = [&](const DnsAnswer &a)
    {
        std::string name = LowerName(a.name);
        if(a.type == DnsMessage::kTypeA)
        {
            std::vector<Ipv4> &v = dnsRecords[name];
            bool seen = false;
            for(const Ipv4 &ip : v)
                if(ip == a.ip) { seen = true; break; }
            if(!seen)
            {
                v.push_back(a.ip);
                dnsReverse[a.ip.value] = name;
            }
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeA)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeAaaa)
        {
            std::vector<Ipv6> &v = dnsAaaa[name];
            bool seen = false;
            for(const Ipv6 &ip : v)
                if(ip == a.ip6) { seen = true; break; }
            if(!seen)
                v.push_back(a.ip6);
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeAaaa)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeCname)
        {
            dnsCnames[name] = LowerName(a.target);
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeCname)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeMx)
        {
            dnsMxRecords[name].push_back(
                DnsMxRecord{ a.preference, LowerName(a.target) });
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeMx)] = a.ttl;
        }
        else if(a.type == DnsMessage::kTypeNs)
        {
            std::vector<std::string> &v = dnsNsRecords[name];
            bool seen = false;
            for(const std::string &ns : v)
                if(ns == LowerName(a.target)) { seen = true; break; }
            if(!seen)
                v.push_back(LowerName(a.target));
            dnsRrTtl[std::make_pair(name, DnsMessage::kTypeNs)] = a.ttl;
        }
    };

    std::size_t i = 1;
    bool deleting = false;
    while(i < records.size())
    {
        const DnsAnswer &a = records[i];
        if(a.type == DnsMessage::kTypeSoa)
        {
            if(i + 1 == records.size())
                break;
            deleting = !deleting;
            ++i;
            continue;
        }
        if(deleting)
            removeRecord(a);
        else
            addRecord(a);
        ++i;
    }

    auto sit = dnsSecondaryZones.find(zone);
    if(sit != dnsSecondaryZones.end())
    {
        uint64_t now = clock ? clock->Now() : 0;
        sit->second.expired = false;
        sit->second.initialized = true;
        sit->second.expireAt = now + z.expire;
        ScheduleDnsSecondary(zone, z.refresh);
    }
    std::cout << "dns: secondary " << zone << " updated serial "
              << z.serial << "\n";
}

std::vector<DnsAnswer> EndDevice::SnapshotDnsZone(
    const std::string &zoneName) const
{
    std::vector<DnsAnswer> out;
    std::string zone = LowerName(zoneName);
    auto ttl = [this](const std::string &name, uint16_t type,
                      uint32_t fallback)
    {
        return DnsRrTtl(name, type, fallback);
    };
    uint32_t zoneTtl = dnsTtl;
    auto zit = dnsZones.find(zone);
    if(zit != dnsZones.end())
        zoneTtl = zit->second.ttl;

    for(const auto &kv : dnsRecords)
    {
        if(!IsSubdomain(kv.first, zone))
            continue;
        for(const Ipv4 &ip : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeA;
            a.cls = 1;
            a.ttl = ttl(kv.first, DnsMessage::kTypeA, zoneTtl);
            a.ip = ip;
            out.push_back(a);
        }
    }
    for(const auto &kv : dnsAaaa)
    {
        if(!IsSubdomain(kv.first, zone))
            continue;
        for(const Ipv6 &ip : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeAaaa;
            a.cls = 1;
            a.ttl = ttl(kv.first, DnsMessage::kTypeAaaa, zoneTtl);
            a.ip6 = ip;
            out.push_back(a);
        }
    }
    for(const auto &kv : dnsCnames)
    {
        if(!IsSubdomain(kv.first, zone))
            continue;
        DnsAnswer a;
        a.name = kv.first;
        a.type = DnsMessage::kTypeCname;
        a.cls = 1;
        a.ttl = ttl(kv.first, DnsMessage::kTypeCname, zoneTtl);
        a.target = kv.second;
        out.push_back(a);
    }
    for(const auto &kv : dnsMxRecords)
    {
        if(!IsSubdomain(kv.first, zone))
            continue;
        for(const DnsMxRecord &mx : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeMx;
            a.cls = 1;
            a.ttl = ttl(kv.first, DnsMessage::kTypeMx, zoneTtl);
            a.preference = mx.preference;
            a.target = mx.exchange;
            out.push_back(a);
        }
    }
    for(const auto &kv : dnsNsRecords)
    {
        if(!IsSubdomain(kv.first, zone))
            continue;
        for(const std::string &ns : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeNs;
            a.cls = 1;
            a.ttl = ttl(kv.first, DnsMessage::kTypeNs, zoneTtl);
            a.target = ns;
            out.push_back(a);
        }
    }
    return out;
}

void EndDevice::RecordDnsJournal(
    const std::string &zoneName, uint32_t fromSerial, uint32_t toSerial,
    const std::vector<DnsAnswer> &before,
    const std::vector<DnsAnswer> &after)
{
    std::string zone = LowerName(zoneName);
    DnsJournalEntry entry;
    entry.fromSerial = fromSerial;
    entry.toSerial = toSerial;

    for(const DnsAnswer &old : before)
    {
        bool found = false;
        for(const DnsAnswer &cur : after)
            if(SameDnsAnswer(old, cur)) { found = true; break; }
        if(!found)
            entry.deleted.push_back(old);
    }
    for(const DnsAnswer &cur : after)
    {
        bool found = false;
        for(const DnsAnswer &old : before)
            if(SameDnsAnswer(cur, old)) { found = true; break; }
        if(!found)
            entry.added.push_back(cur);
    }
    if(entry.deleted.empty() && entry.added.empty())
        return;

    std::deque<DnsJournalEntry> &journal = dnsJournal[zone];
    journal.push_back(entry);
    while(journal.size() > 64)
        journal.pop_front();
}

void EndDevice::ScheduleDnsSecondary(const std::string &zoneName,
                                     uint64_t delay)
{
    if(!scheduler)
        return;
    std::string zone = LowerName(zoneName);
    auto sit = dnsSecondaryZones.find(zone);
    if(sit == dnsSecondaryZones.end())
        return;
    if(delay == 0)
        delay = 3600;
    uint64_t gen = ++sit->second.gen;
    uint64_t now = clock ? clock->Now() : 0;
    sit->second.refreshAt = now + delay;
    scheduler->ScheduleAfter(delay,
        std::make_unique<DnsSecondaryEvent>(this, zone, gen));
}

void EndDevice::OnDnsSecondaryTimer(const std::string &zoneName, uint64_t gen)
{
    std::string zone = LowerName(zoneName);
    auto sit = dnsSecondaryZones.find(zone);
    if(sit == dnsSecondaryZones.end() || sit->second.gen != gen ||
       sit->second.expired)
        return;
    if(axfrActive)
    {
        ScheduleDnsSecondary(zone, 1);
        return;
    }
    StartDnsSecondaryTransfer(zone, sit->second.primary);
}

void EndDevice::DnsSecondaryFailed(const std::string &zoneName)
{
    std::string zone = LowerName(zoneName);
    auto sit = dnsSecondaryZones.find(zone);
    if(sit == dnsSecondaryZones.end())
        return;
    uint64_t now = clock ? clock->Now() : 0;
    if(sit->second.expireAt != 0 && now >= sit->second.expireAt)
    {
        if(!sit->second.expired)
        {
            sit->second.expired = true;
            ++sit->second.gen;
            std::cout << "dns: secondary " << zone << " expired\n";
        }
        return;
    }
    auto zit = dnsZones.find(zone);
    uint64_t retry = zit != dnsZones.end() ? zit->second.retry : 60;
    ScheduleDnsSecondary(zone, retry);
}

void EndDevice::SetDnsSoa(const std::string &zoneName,
                         const std::string &mname, const std::string &rname,
                         uint32_t ttl, uint32_t serial, uint32_t refresh,
                         uint32_t retry, uint32_t expire, uint32_t minimum)
{
    std::string zone = LowerName(zoneName);
    AddDnsZone(zone);
    DnsZone &z = dnsZones[zone];
    z.mname = LowerName(mname);
    z.rname = LowerName(rname);
    z.ttl = ttl;
    z.serial = serial;
    z.refresh = refresh;
    z.retry = retry;
    z.expire = expire;
    z.minimum = minimum;
}

void EndDevice::AddDnsNs(const std::string &ownerName,
                         const std::string &nameserver)
{
    std::string owner = LowerName(ownerName);
    std::string ns = LowerName(nameserver);
    std::vector<std::string> &list = dnsNsRecords[owner];
    for(const std::string &existing : list)
        if(existing == ns)
            return;
    list.push_back(ns);
}

void EndDevice::SetDnsAxfrAllow(const std::vector<Ipv4> &allow, bool any)
{
    dnsAxfrAllow = allow;
    dnsAxfrAllowAny = any;
}

bool EndDevice::DnsAxfrAllowed(const Ipv4 &client) const
{
    if(dnsAxfrAllowAny)
        return true;
    for(const Ipv4 &ip : dnsAxfrAllow)
        if(ip == client)
            return true;
    return false;
}

void EndDevice::SetDnsUpdateAllow(const std::vector<Ipv4> &allow, bool any)
{
    dnsUpdateAllow = allow;
    dnsUpdateAllowAny = any;
}

bool EndDevice::DnsUpdateAllowed(const Ipv4 &client) const
{
    if(dnsUpdateAllowAny)
        return true;
    for(const Ipv4 &ip : dnsUpdateAllow)
        if(ip == client)
            return true;
    return false;
}

const EndDevice::DnsTsigKey *EndDevice::FindDnsTsigKey(
    const std::string &name) const
{
    std::string key = LowerName(name);
    auto it = dnsTsigKeys.find(key);
    return it == dnsTsigKeys.end() ? nullptr : &it->second;
}

void EndDevice::AddDnsTsig(const std::string &keyName,
                           const std::string &secret,
                           const std::string &algorithm)
{
    std::string key = LowerName(keyName);
    std::string alg = LowerName(algorithm);
    if(!alg.empty() && alg.back() == '.')
        alg.pop_back();
    if(alg == "md5" || alg == "hmac-md5" || alg == "hmac-md5.sig-alg.reg.int")
        alg = "hmac-md5.sig-alg.reg.int";
    else if(alg == "sha1" || alg == "hmac-sha1")
        alg = "hmac-sha1";
    else
        alg = "hmac-sha256";

    dnsTsigKeys[key] = DnsTsigKey{ secret, alg };
    dnsTsigClient = true;
    dnsTsigClientName = key;
    dnsTsigClientSecret = secret;
    dnsTsigClientAlgorithm = alg;
}

bool EndDevice::HasDnsName(const std::string &name) const
{
    return dnsRecords.find(name) != dnsRecords.end() ||
           dnsAaaa.find(name) != dnsAaaa.end() ||
           dnsCnames.find(name) != dnsCnames.end() ||
           dnsMxRecords.find(name) != dnsMxRecords.end() ||
           dnsNsRecords.find(name) != dnsNsRecords.end();
}

std::string EndDevice::FindDnsWildcard(const std::string &name) const
{
    std::size_t dot = name.find('.');
    while(dot != std::string::npos && dot + 1 < name.size())
    {
        std::string candidate = "*." + name.substr(dot + 1);
        if(HasDnsName(candidate))
            return candidate;
        dot = name.find('.', dot + 1);
    }
    return {};
}

void EndDevice::SetDnsResolvers(const std::vector<Ipv4> &servers)
{
    dnsServers = servers;
}

void EndDevice::SetDnsCacheLimit(std::size_t entries)
{
    dnsCacheMax = entries ? entries : 1;
    while(dnsCache.size() > dnsCacheMax)
    {
        auto back = dnsLru.back();
        dnsCache.erase(back);
        dnsLru.pop_back();
    }
}

uint32_t EndDevice::ClampDnsTtl(uint32_t ttl) const
{
    if(ttl == 0)
        return 0;
    if(ttl < dnsTtlMin)
        return dnsTtlMin;
    if(ttl > dnsTtlMax)
        return dnsTtlMax;
    return ttl;
}

void EndDevice::TouchDnsCache(
    const std::pair<std::string, uint16_t> &key)
{
    auto it = dnsCache.find(key);
    if(it == dnsCache.end())
        return;
    dnsLru.splice(dnsLru.begin(), dnsLru, it->second.lru);
}

void EndDevice::StoreDnsCache(
    const std::pair<std::string, uint16_t> &key,
    const DnsCacheEntry &entry)
{
    auto it = dnsCache.find(key);
    if(it != dnsCache.end())
    {
        it->second.answers = entry.answers;
        it->second.expires = entry.expires;
        it->second.negative = entry.negative;
        it->second.nxdomain = entry.nxdomain;
        TouchDnsCache(key);
        return;
    }

    DnsCacheEntry stored = entry;
    dnsLru.push_front(key);
    stored.lru = dnsLru.begin();
    dnsCache.emplace(key, stored);

    while(dnsCache.size() > dnsCacheMax)
    {
        auto back = dnsLru.back();
        dnsCache.erase(back);
        dnsLru.pop_back();
    }
}

void EndDevice::RemoveDnsCache(
    const std::pair<std::string, uint16_t> &key)
{
    auto it = dnsCache.find(key);
    if(it == dnsCache.end())
        return;
    dnsLru.erase(it->second.lru);
    dnsCache.erase(it);
}

bool EndDevice::PrintDnsAnswers(const std::string &name,
                                const std::vector<DnsAnswer> &answers,
                                bool cached)
{
    bool printed = false;
    for(const DnsAnswer &a : answers)
    {
        if(a.type == DnsMessage::kTypeA)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> " << a.ip.ToString() << "\n";
            printed = true;
        }
        else if(a.type == DnsMessage::kTypeAaaa)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> AAAA " << a.ip6.ToString() << "\n";
            printed = true;
        }
        else if(a.type == DnsMessage::kTypePtr)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> PTR " << a.target << "\n";
            printed = true;
        }
        else if(a.type == DnsMessage::kTypeMx)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> MX " << a.preference
                      << " " << a.target << "\n";
            printed = true;
        }
        else if(a.type == DnsMessage::kTypeNs)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> NS " << a.target << "\n";
            printed = true;
        }
        else if(a.type == DnsMessage::kTypeSoa)
        {
            std::cout << "dns: " << (cached ? "cached " : "")
                      << name << " -> SOA " << a.mname
                      << " " << a.rname << "\n";
            printed = true;
        }
    }
    return printed;
}

void EndDevice::DnsQuery(const std::string &name, uint16_t qtype)
{
    dnsReferralDepth = 0;
    dnsInternalQuery = false;
    StartDnsQuery(name, qtype, dnsServers);
}

void EndDevice::DnsQuery(const Ipv4 &server, const std::string &name,
                         uint16_t qtype)
{
    dnsReferralDepth = 0;
    dnsInternalQuery = false;
    StartDnsQuery(name, qtype, std::vector<Ipv4>{ server });
}

void EndDevice::StartDnsQuery(const std::string &name, uint16_t qtype,
                              const std::vector<Ipv4> &servers)
{
    std::string key;
    key.reserve(name.size());
    for(char c : name)
        key.push_back(char(std::tolower(static_cast<unsigned char>(c))));

    if(servers.empty())
    {
        std::cout << "dns: no resolver configured\n";
        return;
    }

    std::pair<std::string, uint16_t> cacheKey{ key, qtype };
    uint64_t now = clock ? clock->Now() : 0;
    if(!dnsInternalQuery)
    {
        auto cached = dnsCache.find(cacheKey);
        if(cached != dnsCache.end())
        {
            if(cached->second.expires > now)
            {
                TouchDnsCache(cacheKey);
                if(cached->second.negative)
                {
                    std::cout << "dns: cached " << key << " -> "
                              << (cached->second.nxdomain ? "NXDOMAIN"
                                                          : "NODATA")
                              << "\n";
                }
                else
                {
                    PrintDnsAnswers(key, cached->second.answers, true);
                }
                return;
            }
            RemoveDnsCache(cacheKey);
        }
    }

    CancelDnsRetry();
    if(dnsTcpActive)
    {
        dnsTcpActive = false;
        if(dnsTcpConn)
        {
            dnsTcpConn->Abort();
            dnsTcpConn = nullptr;
        }
    }
    dnsClientPort = nextDnsClientPort++;
    dnsQueryId = uint16_t(nextDnsId++);
    dnsQueryName = key;
    dnsQueryType = qtype;
    dnsQueryServers = servers;
    dnsQueryServerIndex = 0;
    dnsQueryAttempt = 1;
    dnsQueryServer = dnsQueryServers[0];
    SendDnsQuery();
}

void EndDevice::SendDnsQuery()
{
    if(dnsClientPort == 0 || dnsQueryServers.empty())
        return;

    DnsMessage q;
    q.id = dnsQueryId;
    q.flags = 0x0100;
    q.questions.push_back(DnsQuestion{ dnsQueryName, dnsQueryType, 1 });
    q.hasOpt = true;
    q.optUdpSize = 1232;

    std::vector<uint8_t> bytes = q.ToBytes();
    if(bytes.empty())
    {
        FailDnsQuery();
        return;
    }

    SendUdp(dnsQueryServer, 53,
            std::string(bytes.begin(), bytes.end()), dnsClientPort);
    if(dnsClientPort != 0)
        ScheduleDnsRetry();
}

void EndDevice::ScheduleDnsRetry(uint64_t delay)
{
    if(!scheduler)
        return;
    CancelDnsRetry();
    if(delay == 0)
        delay = dnsTimeout;
    uint64_t gen = ++dnsTimerGen;
    std::unique_ptr<DnsRetryEvent> ev =
        std::make_unique<DnsRetryEvent>(this, gen);
    dnsRetryEvent = ev.get();
    scheduler->ScheduleAfter(delay, std::move(ev));
}

void EndDevice::CancelDnsRetry()
{
    if(dnsRetryEvent)
    {
        dnsRetryEvent->cancelled = true;
        dnsRetryEvent = nullptr;
    }
    ++dnsTimerGen;
}

void EndDevice::OnDnsTimeout(uint64_t gen)
{
    if(gen != dnsTimerGen)
        return;

    dnsRetryEvent = nullptr;

    if(dnsTcpActive)
    {
        if(dnsTcpConn)
        {
            dnsTcpConn->Abort();
            dnsTcpConn = nullptr;
        }
        FailDnsQuery();
        return;
    }

    if(dnsClientPort == 0)
        return;

    if(dnsQueryAttempt < dnsMaxAttempts)
    {
        ++dnsQueryAttempt;
        SendDnsQuery();
        return;
    }

    if(dnsQueryServerIndex + 1 < dnsQueryServers.size())
    {
        ++dnsQueryServerIndex;
        dnsQueryServer = dnsQueryServers[dnsQueryServerIndex];
        dnsQueryAttempt = 1;
        SendDnsQuery();
        return;
    }

    FailDnsQuery();
}

void EndDevice::FailDnsQuery()
{
    CancelDnsRetry();
    dnsTcpActive = false;
    dnsTcpConn = nullptr;
    if(dnsInternalQuery)
    {
        std::string original = dnsOriginalName;
        dnsInternalQuery = false;
        dnsClientPort = 0;
        std::cout << "dns: " << original << " -> SERVFAIL\n";
        return;
    }
    std::cout << "dns: " << dnsQueryName << " -> timeout\n";
    dnsClientPort = 0;
}

void EndDevice::DnsAxfr(const Ipv4 &server, const std::string &zone)
{
    StartDnsAxfr(server, zone, false);
}

void EndDevice::DnsIxfr(const Ipv4 &server, const std::string &zone,
                        uint32_t serial)
{
    StartDnsIxfr(server, zone, serial);
}

void EndDevice::StartDnsIxfr(const Ipv4 &server, const std::string &zone,
                             uint32_t serial)
{
    if(ixfrActive && ixfrConn)
    {
        ixfrActive = false;
        ixfrConn->Abort();
        ixfrConn = nullptr;
    }

    Port *egress = nullptr;
    Ipv4 nextHop;
    if(!ResolveNextHop(server, egress, nextHop))
    {
        std::cout << "dns: ixfr " << LowerName(zone) << " failed\n";
        return;
    }

    CleanupTcpConns();
    if(tcpConns.size() >= kMaxTcpConns)
    {
        ++tcpDropped;
        std::cout << "dns: ixfr " << LowerName(zone) << " failed\n";
        return;
    }

    ixfrZone = LowerName(zone);
    ixfrSerial = serial;
    ixfrId = uint16_t(nextDnsId++);
    ixfrRequestMac.clear();

    TcpConnection &c = NewTcpConnection();
    TcpConnection *cp = &c;
    c.onConnected = [this, cp]() { SendDnsIxfrQuery(*cp); };
    c.onData = [this, cp](const std::vector<uint8_t> &data) {
        OnDnsIxfrData(*cp, data);
    };
    c.onReset = [this, cp]() {
        if(ixfrActive && ixfrConn == cp)
        {
            ixfrActive = false;
            ixfrConn = nullptr;
            std::cout << "dns: ixfr " << ixfrZone << " failed\n";
        }
    };

    ixfrConn = cp;
    ixfrActive = true;
    std::cout << "dns: ixfr " << ixfrZone << " from " << serial << "\n";
    c.OpenActive(egress->ip, nextIxfrLocalPort++, server, 53);
    IndexTcpConn(c);
}

void EndDevice::SendDnsIxfrQuery(TcpConnection &conn)
{
    if(!ixfrActive || ixfrConn != &conn)
        return;

    DnsMessage q;
    q.id = ixfrId;
    q.flags = 0x0100;
    q.questions.push_back(DnsQuestion{
        ixfrZone, DnsMessage::kTypeIxfr, 1 });
    DnsAnswer soa;
    soa.name = ixfrZone;
    soa.type = DnsMessage::kTypeSoa;
    soa.cls = 1;
    soa.ttl = 0;
    soa.mname = "ns." + ixfrZone;
    soa.rname = "hostmaster." + ixfrZone;
    soa.serial = ixfrSerial;
    q.authority.push_back(soa);
    q.hasOpt = true;
    q.optUdpSize = 1232;

    if(dnsTsigClient)
    {
        q.tsig.present = true;
        q.tsig.keyName = dnsTsigClientName;
        q.tsig.algorithm = dnsTsigClientAlgorithm;
        q.tsig.timeSigned = clock ? clock->Now() : 0;
        q.tsig.fudge = 300;
        q.tsig.originalId = q.id;
        q.tsig.error = 0;
        if(!q.SignTsig(dnsTsigClientSecret))
        {
            FailDnsIxfr();
            return;
        }
        ixfrRequestMac = q.tsig.mac;
    }

    std::vector<uint8_t> bytes = q.ToBytes();
    if(bytes.empty() || bytes.size() > 65535)
    {
        FailDnsIxfr();
        return;
    }

    std::vector<uint8_t> framed;
    framed.reserve(bytes.size() + 2);
    framed.push_back(uint8_t(bytes.size() >> 8));
    framed.push_back(uint8_t(bytes.size() & 0xFF));
    framed.insert(framed.end(), bytes.begin(), bytes.end());
    conn.SendData(framed);
}

void EndDevice::OnDnsIxfrData(TcpConnection &conn,
                              const std::vector<uint8_t> &data)
{
    conn.appRx.insert(conn.appRx.end(), data.begin(), data.end());

    while(conn.appRx.size() >= 2)
    {
        std::size_t len = (std::size_t(conn.appRx[0]) << 8) | conn.appRx[1];
        if(len == 0 || len > 65535)
        {
            FailDnsIxfr();
            return;
        }
        if(conn.appRx.size() < len + 2)
            return;

        std::vector<uint8_t> message(conn.appRx.begin() + 2,
                                     conn.appRx.begin() + 2 + len);
        conn.appRx.erase(conn.appRx.begin(),
                         conn.appRx.begin() + 2 + len);

        DnsMessage m;
        if(!DnsMessage::TryFromBytes(message, m) || !m.IsResponse() ||
           m.id != ixfrId || m.Rcode() != 0)
        {
            FailDnsIxfr();
            return;
        }

        if(!ixfrRequestMac.empty())
        {
            bool ok = m.tsig.present &&
                      m.tsig.keyName == dnsTsigClientName &&
                      m.tsig.algorithm == dnsTsigClientAlgorithm &&
                      m.tsig.originalId == ixfrId;
            if(ok)
            {
                uint64_t now = clock ? clock->Now() : 0;
                uint64_t ts = m.tsig.timeSigned;
                uint64_t diff = ts > now ? ts - now : now - ts;
                ok = diff <= m.tsig.fudge;
            }
            if(ok)
                ok = m.VerifyTsig(dnsTsigClientSecret, &ixfrRequestMac);
            if(!ok)
            {
                FailDnsIxfr();
                return;
            }
        }

        for(const DnsAnswer &a : m.answers)
        {
            if(a.type == DnsMessage::kTypeSoa)
                std::cout << "dns: ixfr SOA " << a.serial << "\n";
            else if(a.type == DnsMessage::kTypeA)
                std::cout << "dns: ixfr A " << a.name << " "
                          << a.ip.ToString() << "\n";
            else if(a.type == DnsMessage::kTypeAaaa)
                std::cout << "dns: ixfr AAAA " << a.name << " "
                          << a.ip6.ToString() << "\n";
            else if(a.type == DnsMessage::kTypeCname)
                std::cout << "dns: ixfr CNAME " << a.name << " "
                          << a.target << "\n";
            else if(a.type == DnsMessage::kTypeMx)
                std::cout << "dns: ixfr MX " << a.name << " "
                          << a.preference << " " << a.target << "\n";
            else if(a.type == DnsMessage::kTypeNs)
                std::cout << "dns: ixfr NS " << a.name << " "
                          << a.target << "\n";
        }

        std::cout << "dns: ixfr " << ixfrZone << " complete\n";
        ixfrActive = false;
        ixfrConn = nullptr;
        ixfrRequestMac.clear();
        conn.Close();
        return;
    }
}

void EndDevice::FailDnsIxfr()
{
    if(!ixfrActive)
        return;
    ixfrActive = false;
    if(ixfrConn)
    {
        ixfrConn->Abort();
        ixfrConn = nullptr;
    }
    ixfrRequestMac.clear();
    std::cout << "dns: ixfr " << ixfrZone << " failed\n";
}

void EndDevice::StartDnsAxfr(const Ipv4 &server, const std::string &zone,
                             bool internal, bool useIxfr,
                             uint32_t clientSerial)
{
    if(axfrActive && axfrConn)
    {
        axfrActive = false;
        axfrConn->Abort();
        axfrConn = nullptr;
    }

    Port *egress = nullptr;
    Ipv4 nextHop;
    if(!ResolveNextHop(server, egress, nextHop))
    {
        if(internal)
        {
            std::cout << "dns: secondary " << LowerName(zone) << " failed\n";
            DnsSecondaryFailed(zone);
        }
        else
            std::cout << "dns: axfr " << LowerName(zone) << " failed\n";
        return;
    }

    CleanupTcpConns();
    if(tcpConns.size() >= kMaxTcpConns)
    {
        ++tcpDropped;
        if(internal)
        {
            std::cout << "dns: secondary " << LowerName(zone) << " failed\n";
            DnsSecondaryFailed(zone);
        }
        else
            std::cout << "dns: axfr " << LowerName(zone) << " failed\n";
        return;
    }

    axfrZone = LowerName(zone);
    axfrInternal = internal;
    axfrUseIxfr = useIxfr;
    axfrClientSerial = clientSerial;
    axfrInternalZone = axfrZone;
    axfrId = uint16_t(nextDnsId++);
    axfrSoaCount = 0;
    axfrRecordCount = 0;
    axfrRequestMac.clear();
    axfrRecords.clear();

    TcpConnection &c = NewTcpConnection();
    TcpConnection *cp = &c;
    c.onConnected = [this, cp]() { SendDnsAxfrQuery(*cp); };
    c.onData = [this, cp](const std::vector<uint8_t> &data) {
        OnDnsAxfrData(*cp, data);
    };
    c.onReset = [this, cp]() {
        if(axfrActive && axfrConn == cp)
        {
            axfrActive = false;
            axfrConn = nullptr;
            if(axfrInternal)
            {
                std::cout << "dns: secondary " << axfrInternalZone
                          << " failed\n";
                DnsSecondaryFailed(axfrInternalZone);
            }
            else
                std::cout << "dns: axfr " << axfrZone << " failed\n";
        }
    };

    axfrConn = cp;
    axfrActive = true;
    if(!internal)
        std::cout << "dns: axfr " << axfrZone << " begin\n";
    c.OpenActive(egress->ip, nextAxfrLocalPort++, server, 53);
    IndexTcpConn(c);
}

void EndDevice::SendDnsAxfrQuery(TcpConnection &conn)
{
    if(!axfrActive || axfrConn != &conn)
        return;

    DnsMessage q;
    q.id = axfrId;
    q.flags = 0x0100;
    q.questions.push_back(DnsQuestion{
        axfrZone,
        axfrUseIxfr ? DnsMessage::kTypeIxfr : DnsMessage::kTypeAxfr, 1 });
    if(axfrUseIxfr)
    {
        DnsAnswer soa;
        soa.name = axfrZone;
        soa.type = DnsMessage::kTypeSoa;
        soa.cls = 1;
        soa.ttl = 0;
        soa.mname = "ns." + axfrZone;
        soa.rname = "hostmaster." + axfrZone;
        soa.serial = axfrClientSerial;
        q.authority.push_back(soa);
    }
    if(dnsTsigClient)
    {
        q.tsig.present = true;
        q.tsig.keyName = dnsTsigClientName;
        q.tsig.algorithm = dnsTsigClientAlgorithm;
        q.tsig.timeSigned = clock ? clock->Now() : 0;
        q.tsig.fudge = 300;
        q.tsig.originalId = q.id;
        q.tsig.error = 0;
        if(!q.SignTsig(dnsTsigClientSecret))
        {
            FailDnsAxfr();
            return;
        }
        axfrRequestMac = q.tsig.mac;
    }

    std::vector<uint8_t> bytes = q.ToBytes();
    if(bytes.empty() || bytes.size() > 65535)
    {
        FailDnsAxfr();
        return;
    }

    std::vector<uint8_t> framed;
    framed.reserve(bytes.size() + 2);
    framed.push_back(uint8_t(bytes.size() >> 8));
    framed.push_back(uint8_t(bytes.size() & 0xFF));
    framed.insert(framed.end(), bytes.begin(), bytes.end());
    conn.SendData(framed);
}

void EndDevice::OnDnsAxfrData(TcpConnection &conn,
                              const std::vector<uint8_t> &data)
{
    conn.appRx.insert(conn.appRx.end(), data.begin(), data.end());

    while(conn.appRx.size() >= 2)
    {
        std::size_t len = (std::size_t(conn.appRx[0]) << 8) | conn.appRx[1];
        if(len == 0 || len > 65535)
        {
            FailDnsAxfr();
            return;
        }
        if(conn.appRx.size() < len + 2)
            return;

        std::vector<uint8_t> message(conn.appRx.begin() + 2,
                                     conn.appRx.begin() + 2 + len);
        conn.appRx.erase(conn.appRx.begin(),
                         conn.appRx.begin() + 2 + len);

        DnsMessage m;
        if(!DnsMessage::TryFromBytes(message, m) || !m.IsResponse() ||
           m.id != axfrId || m.Rcode() != 0)
        {
            FailDnsAxfr();
            return;
        }

        if(!axfrRequestMac.empty())
        {
            bool ok = m.tsig.present &&
                      m.tsig.keyName == dnsTsigClientName &&
                      m.tsig.algorithm == dnsTsigClientAlgorithm &&
                      m.tsig.originalId == axfrId;
            if(ok)
            {
                uint64_t now = clock ? clock->Now() : 0;
                uint64_t ts = m.tsig.timeSigned;
                uint64_t diff = ts > now ? ts - now : now - ts;
                ok = diff <= m.tsig.fudge;
            }
            if(ok)
                ok = m.VerifyTsig(dnsTsigClientSecret, &axfrRequestMac);
            if(!ok)
            {
                FailDnsAxfr();
                return;
            }
        }

        if(axfrUseIxfr)
        {
            ApplyDnsSecondaryIxfr(axfrInternalZone, m.answers,
                                  axfrClientSerial);
            axfrActive = false;
            axfrInternal = false;
            axfrUseIxfr = false;
            axfrConn = nullptr;
            axfrRecords.clear();
            conn.Close();
            return;
        }

        for(const DnsAnswer &a : m.answers)
        {
            if(a.type == DnsMessage::kTypeSoa)
                ++axfrSoaCount;
            ++axfrRecordCount;
            if(axfrInternal)
            {
                axfrRecords.push_back(a);
                continue;
            }
            if(a.type == DnsMessage::kTypeSoa)
                std::cout << "dns: axfr SOA " << a.name << " "
                          << a.mname << " " << a.rname << "\n";
            else if(a.type == DnsMessage::kTypeNs)
                std::cout << "dns: axfr NS " << a.name << " "
                          << a.target << "\n";
            else if(a.type == DnsMessage::kTypeA)
                std::cout << "dns: axfr A " << a.name << " "
                          << a.ip.ToString() << "\n";
            else if(a.type == DnsMessage::kTypeAaaa)
                std::cout << "dns: axfr AAAA " << a.name << " "
                          << a.ip6.ToString() << "\n";
            else if(a.type == DnsMessage::kTypeCname)
                std::cout << "dns: axfr CNAME " << a.name << " "
                          << a.target << "\n";
            else if(a.type == DnsMessage::kTypeMx)
                std::cout << "dns: axfr MX " << a.name << " "
                          << a.preference << " " << a.target << "\n";
        }

        if(axfrSoaCount >= 2)
        {
            if(axfrInternal)
                ApplyDnsSecondaryTransfer(axfrInternalZone, axfrRecords);
            else
                std::cout << "dns: axfr " << axfrZone << " complete "
                          << axfrRecordCount << "\n";
            axfrActive = false;
            axfrInternal = false;
            axfrUseIxfr = false;
            axfrConn = nullptr;
            axfrRecords.clear();
            conn.Close();
            return;
        }
    }
}

void EndDevice::FailDnsAxfr()
{
    if(!axfrActive)
        return;
    axfrActive = false;
    if(axfrConn)
    {
        axfrConn->Abort();
        axfrConn = nullptr;
    }
    if(axfrInternal)
    {
        std::cout << "dns: secondary " << axfrInternalZone << " failed\n";
        DnsSecondaryFailed(axfrInternalZone);
    }
    else
        std::cout << "dns: axfr " << axfrZone << " failed\n";
    axfrInternal = false;
    axfrUseIxfr = false;
    axfrRecords.clear();
}

DnsMessage EndDevice::ProcessDnsUpdate(const DnsMessage &m,
                                       const Ipv4 &client)
{
    const DnsTsigKey *tsigKey = nullptr;
    std::vector<uint8_t> requestMac;
    uint64_t now = clock ? clock->Now() : 0;

    auto finish = [&](uint16_t rcode)
    {
        DnsMessage r;
        r.id = m.id;
        r.flags = 0x8000;
        r.SetOpcode(5);
        r.flags = uint16_t((r.flags & ~0x000Fu) | (rcode & 0x000Fu));
        r.questions = m.questions;
        if(tsigKey)
        {
            r.tsig.present = true;
            r.tsig.keyName = m.tsig.keyName;
            r.tsig.algorithm = tsigKey->algorithm;
            r.tsig.timeSigned = now;
            r.tsig.fudge = 300;
            r.tsig.originalId = m.id;
            r.tsig.error = 0;
            r.SignTsig(tsigKey->secret, &requestMac);
        }
        return r;
    };

    if(m.questions.size() != 1 ||
       m.questions[0].qtype != DnsMessage::kTypeSoa ||
       m.questions[0].qclass != 1)
        return finish(1);

    std::string zoneName = LowerName(m.questions[0].name);
    auto zoneIt = dnsZones.find(zoneName);
    if(zoneIt == dnsZones.end())
        return finish(9);

    if(!DnsUpdateAllowed(client))
        return finish(5);

    if(m.tsig.present)
    {
        tsigKey = FindDnsTsigKey(m.tsig.keyName);
        bool ok = tsigKey != nullptr &&
                  tsigKey->algorithm == m.tsig.algorithm &&
                  m.tsig.originalId == m.id;
        if(ok)
        {
            uint64_t ts = m.tsig.timeSigned;
            uint64_t diff = ts > now ? ts - now : now - ts;
            ok = diff <= m.tsig.fudge;
        }
        if(ok)
            ok = m.VerifyTsig(tsigKey->secret);
        if(!ok)
        {
            tsigKey = nullptr;
            return finish(9);
        }
        requestMac = m.tsig.mac;
    }
    else if(dnsTsigRequired)
    {
        return finish(5);
    }

    const uint16_t clAny = 255;
    const uint16_t clNone = 254;
    const uint16_t typeAny = 255;

    auto rrsetExists = [&](const std::string &name, uint16_t type) -> bool
    {
        if(type == DnsMessage::kTypeA)
            return dnsRecords.find(name) != dnsRecords.end();
        if(type == DnsMessage::kTypeCname)
            return dnsCnames.find(name) != dnsCnames.end();
        if(type == DnsMessage::kTypeMx)
            return dnsMxRecords.find(name) != dnsMxRecords.end();
        if(type == DnsMessage::kTypeNs)
            return dnsNsRecords.find(name) != dnsNsRecords.end();
        return false;
    };

    for(const DnsAnswer &p : m.answers)
    {
        std::string name = LowerName(p.name);
        if(p.cls == clAny)
        {
            if(p.type == typeAny)
            {
                if(!HasDnsName(name))
                    return finish(3);
            }
            else if(!rrsetExists(name, p.type))
                return finish(8);
        }
        else if(p.cls == clNone)
        {
            if(p.type == typeAny)
            {
                if(HasDnsName(name))
                    return finish(7);
            }
            else if(rrsetExists(name, p.type))
                return finish(7);
        }
        else if(p.cls == 1)
        {
            if(p.ttl != 0)
                return finish(1);
            if(!HasDnsName(name))
                return finish(3);
            if(!rrsetExists(name, p.type))
                return finish(8);

            bool valueExists = false;
            if(p.type == DnsMessage::kTypeA)
            {
                auto it = dnsRecords.find(name);
                if(it != dnsRecords.end())
                    for(const Ipv4 &ip : it->second)
                        if(ip == p.ip) { valueExists = true; break; }
            }
            else if(p.type == DnsMessage::kTypeCname)
            {
                auto it = dnsCnames.find(name);
                if(it != dnsCnames.end() &&
                   it->second == LowerName(p.target))
                    valueExists = true;
            }
            else if(p.type == DnsMessage::kTypeMx)
            {
                auto it = dnsMxRecords.find(name);
                if(it != dnsMxRecords.end())
                    for(const DnsMxRecord &mx : it->second)
                        if(mx.preference == p.preference &&
                           mx.exchange == LowerName(p.target))
                        {
                            valueExists = true;
                            break;
                        }
            }
            else
                return finish(4);
            if(!valueExists)
                return finish(8);
        }
        else
            return finish(4);
    }

    for(const DnsAnswer &u : m.authority)
    {
        std::string name = LowerName(u.name);
        if(!IsSubdomain(name, zoneName))
            return finish(5);
        if(u.cls == clAny)
        {
            if(u.type != typeAny && u.type != DnsMessage::kTypeA &&
               u.type != DnsMessage::kTypeCname &&
               u.type != DnsMessage::kTypeMx)
                return finish(4);
        }
        else if(u.cls == clNone)
        {
            if(u.type != DnsMessage::kTypeA)
                return finish(4);
        }
        else if(u.cls == 1)
        {
            if(u.type != DnsMessage::kTypeA &&
               u.type != DnsMessage::kTypeCname &&
               u.type != DnsMessage::kTypeMx)
                return finish(4);
        }
        else
            return finish(1);
    }

    std::vector<DnsAnswer> before = SnapshotDnsZone(zoneName);
    uint32_t oldSerial = zoneIt->second.serial;

    auto dropReverse = [&](const std::string &name, const Ipv4 &ip)
    {
        auto rit = dnsReverse.find(ip.value);
        if(rit != dnsReverse.end() && rit->second == name)
            dnsReverse.erase(rit);
    };

    for(const DnsAnswer &u : m.authority)
    {
        std::string name = LowerName(u.name);
        if(u.cls == clAny)
        {
            if(u.type == typeAny || u.type == DnsMessage::kTypeA)
            {
                auto it = dnsRecords.find(name);
                if(it != dnsRecords.end())
                {
                    for(const Ipv4 &ip : it->second)
                        dropReverse(name, ip);
                    dnsRecords.erase(it);
                }
                dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeA));
            }
            if(u.type == typeAny || u.type == DnsMessage::kTypeCname)
            {
                dnsCnames.erase(name);
                dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeCname));
            }
            if(u.type == typeAny || u.type == DnsMessage::kTypeMx)
            {
                dnsMxRecords.erase(name);
                dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeMx));
            }
        }
        else if(u.cls == clNone)
        {
            auto it = dnsRecords.find(name);
            if(it != dnsRecords.end())
            {
                auto &ips = it->second;
                for(auto i = ips.begin(); i != ips.end();)
                {
                    if(*i == u.ip)
                    {
                        dropReverse(name, *i);
                        i = ips.erase(i);
                    }
                    else
                        ++i;
                }
                if(ips.empty())
                {
                    dnsRecords.erase(it);
                    dnsRrTtl.erase(std::make_pair(name, DnsMessage::kTypeA));
                }
            }
        }
        else if(u.cls == 1)
        {
            if(u.type == DnsMessage::kTypeA)
            {
                std::vector<Ipv4> &ips = dnsRecords[name];
                bool seen = false;
                for(const Ipv4 &ip : ips)
                    if(ip == u.ip) { seen = true; break; }
                if(!seen)
                {
                    ips.push_back(u.ip);
                    dnsReverse[u.ip.value] = name;
                }
                dnsRrTtl[std::make_pair(name, DnsMessage::kTypeA)] = u.ttl;
            }
            else if(u.type == DnsMessage::kTypeCname)
            {
                dnsCnames[name] = LowerName(u.target);
                dnsRrTtl[std::make_pair(name, DnsMessage::kTypeCname)] = u.ttl;
            }
            else if(u.type == DnsMessage::kTypeMx)
            {
                dnsMxRecords[name].push_back(
                    DnsMxRecord{ u.preference, LowerName(u.target) });
                dnsRrTtl[std::make_pair(name, DnsMessage::kTypeMx)] = u.ttl;
            }
        }
    }

    std::vector<DnsAnswer> after = SnapshotDnsZone(zoneName);
    bool changed = before.size() != after.size() ||
                   !std::equal(before.begin(), before.end(), after.begin(),
                               SameDnsAnswer);
    if(changed && !m.authority.empty())
    {
        uint32_t nextSerial = oldSerial + 1;
        if(nextSerial == 0)
            nextSerial = 1;
        RecordDnsJournal(zoneName, oldSerial, nextSerial, before, after);
        zoneIt->second.serial = nextSerial;
        NotifyDnsZone(zoneName);
    }

    return finish(0);
}

void EndDevice::DnsUpdateAdd(const Ipv4 &server, const std::string &zone,
                             const std::string &name, const Ipv4 &ip,
                             uint32_t ttl)
{
    DnsAnswer a;
    a.name = LowerName(name);
    a.type = DnsMessage::kTypeA;
    a.cls = 1;
    a.ttl = ttl;
    a.ip = ip;
    SendDnsUpdate(server, zone, std::vector<DnsAnswer>{ a });
}

void EndDevice::DnsUpdateDelete(const Ipv4 &server, const std::string &zone,
                                const std::string &name, uint16_t qtype)
{
    DnsAnswer a;
    a.name = LowerName(name);
    a.type = qtype;
    a.cls = 255;
    a.ttl = 0;
    a.noRdata = true;
    SendDnsUpdate(server, zone, std::vector<DnsAnswer>{ a });
}

void EndDevice::DnsUpdateCheck(const Ipv4 &server, const std::string &zone,
                               const std::string &name, const Ipv4 &ip)
{
    DnsAnswer p;
    p.name = LowerName(name);
    p.type = DnsMessage::kTypeA;
    p.cls = 1;
    p.ttl = 0;
    p.ip = ip;
    SendDnsUpdate(server, zone, {}, std::vector<DnsAnswer>{ p });
}

void EndDevice::SendDnsUpdate(const Ipv4 &server, const std::string &zone,
                              const std::vector<DnsAnswer> &updates,
                              const std::vector<DnsAnswer> &prereqs)
{
    DnsMessage m;
    m.id = uint16_t(nextDnsId++);
    m.flags = 0;
    m.SetOpcode(5);
    m.questions.push_back(DnsQuestion{
        LowerName(zone), DnsMessage::kTypeSoa, 1 });
    m.answers = prereqs;
    m.authority = updates;

    dnsUpdateRequestMac.clear();
    if(dnsTsigClient)
    {
        m.tsig.present = true;
        m.tsig.keyName = dnsTsigClientName;
        m.tsig.algorithm = dnsTsigClientAlgorithm;
        m.tsig.timeSigned = clock ? clock->Now() : 0;
        m.tsig.fudge = 300;
        m.tsig.originalId = m.id;
        m.tsig.error = 0;
        if(!m.SignTsig(dnsTsigClientSecret))
        {
            std::cout << "dns: update " << LowerName(zone) << " failed\n";
            return;
        }
        dnsUpdateRequestMac = m.tsig.mac;
    }

    std::vector<uint8_t> bytes = m.ToBytes();
    if(bytes.empty())
    {
        std::cout << "dns: update " << LowerName(zone) << " failed\n";
        return;
    }

    dnsUpdateActive = true;
    dnsUpdatePort = nextDnsClientPort++;
    dnsUpdateId = m.id;
    dnsUpdateServer = server;
    dnsUpdateZone = LowerName(zone);
    SendUdp(server, 53,
            std::string(bytes.begin(), bytes.end()), dnsUpdatePort);
}

DnsMessage EndDevice::BuildDnsResponse(const DnsMessage &m)
{
    if(!m.questions.empty() &&
       (m.questions[0].qtype == DnsMessage::kTypeAxfr ||
        m.questions[0].qtype == DnsMessage::kTypeIxfr))
    {
        DnsMessage r;
        r.id = m.id;
        r.flags = 0x8185;
        r.questions = m.questions;
        return r;
    }

    if(!dnsZones.empty())
        return BuildZonedDnsResponse(m);

    DnsMessage r;
    r.id = m.id;
    r.flags = 0x8180;
    r.questions = m.questions;
    r.hasOpt = m.hasOpt;
    r.optUdpSize = m.hasOpt ? 1232 : 512;

    std::string key;
    for(char c : m.questions[0].name)
        key.push_back(char(std::tolower(static_cast<unsigned char>(c))));

    std::string name = key;
    bool found = false;
    std::string wildcard;
    for(int depth = 0; depth < 8; ++depth)
    {
        auto cit = dnsCnames.find(name);
        if(cit == dnsCnames.end())
            break;
        DnsAnswer cname;
        cname.name = name;
        cname.type = DnsMessage::kTypeCname;
        cname.cls = 1;
        cname.ttl = DnsRrTtl(name, DnsMessage::kTypeCname, dnsTtl);
        cname.target = cit->second;
        r.answers.push_back(cname);
        name = cit->second;
    }

    if(!HasDnsName(key))
    {
        wildcard = FindDnsWildcard(key);
        if(!wildcard.empty())
        {
            auto cit = dnsCnames.find(wildcard);
            if(cit != dnsCnames.end())
            {
                DnsAnswer cname;
                cname.name = key;
                cname.type = DnsMessage::kTypeCname;
                cname.cls = 1;
                cname.ttl = DnsRrTtl(wildcard, DnsMessage::kTypeCname, dnsTtl);
                cname.target = cit->second;
                r.answers.push_back(cname);
                name = cit->second;
            }
        }
    }

    std::string dataName = name;
    if(name == key && !wildcard.empty() &&
       dnsCnames.find(wildcard) == dnsCnames.end())
        dataName = wildcard;

    uint16_t qtype = m.questions[0].qtype;
    if(qtype == DnsMessage::kTypeA)
    {
        auto it = dnsRecords.find(dataName);
        if(it != dnsRecords.end())
        {
            for(const Ipv4 &ip : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeA;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeA, dnsTtl);
                a.ip = ip;
                r.answers.push_back(a);
            }
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypeAaaa)
    {
        auto it = dnsAaaa.find(dataName);
        if(it != dnsAaaa.end())
        {
            for(const Ipv6 &ip : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeAaaa;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeAaaa, dnsTtl);
                a.ip6 = ip;
                r.answers.push_back(a);
            }
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypePtr)
    {
        uint32_t ip = 0;
        if(ParseInAddrArpa(name, ip))
        {
            auto it = dnsReverse.find(ip);
            if(it != dnsReverse.end())
            {
                DnsAnswer a;
                a.name = name;
                a.type = DnsMessage::kTypePtr;
                a.cls = 1;
                a.ttl = dnsTtl;
                a.target = it->second;
                r.answers.push_back(a);
                found = true;
            }
        }
    }
    else if(qtype == DnsMessage::kTypeMx)
    {
        auto it = dnsMxRecords.find(dataName);
        if(it != dnsMxRecords.end())
        {
            for(const DnsMxRecord &mx : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeMx;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeMx, dnsTtl);
                a.preference = mx.preference;
                a.target = mx.exchange;
                r.answers.push_back(a);
            }
            found = true;
        }
    }

    if(!found)
    {
        bool nameExists = !wildcard.empty() ||
                          dnsRecords.find(name) != dnsRecords.end() ||
                          dnsAaaa.find(name) != dnsAaaa.end() ||
                          dnsMxRecords.find(name) != dnsMxRecords.end() ||
                          dnsCnames.find(name) != dnsCnames.end();
        r.flags = nameExists ? 0x8180 : 0x8183;

        std::string zone = key;
        std::size_t dot = zone.find('.');
        if(dot != std::string::npos && dot + 1 < zone.size())
            zone = zone.substr(dot + 1);

        DnsAnswer soa;
        soa.name = zone;
        soa.type = DnsMessage::kTypeSoa;
        soa.cls = 1;
        soa.ttl = dnsNegativeTtl;
        soa.mname = "ns." + zone;
        soa.rname = "hostmaster." + zone;
        soa.serial = 1;
        soa.refresh = 3600;
        soa.retry = 600;
        soa.expire = 86400;
        soa.minimum = dnsNegativeTtl;
        r.authority.push_back(soa);
    }

    return r;
}

DnsMessage EndDevice::BuildZonedDnsResponse(const DnsMessage &m)
{
    DnsMessage r;
    r.id = m.id;
    r.flags = 0x8180;
    r.questions = m.questions;
    r.hasOpt = m.hasOpt;
    r.optUdpSize = m.hasOpt ? 1232 : 512;

    std::string key = LowerName(m.questions[0].name);
    const DnsZone *zone = nullptr;
    std::size_t bestZone = 0;
    for(const auto &kv : dnsZones)
    {
        if(IsSubdomain(key, kv.first) && kv.first.size() > bestZone)
        {
            zone = &kv.second;
            bestZone = kv.first.size();
        }
    }
    if(!zone)
    {
        r.flags = 0x8185;
        return r;
    }
    auto secondary = dnsSecondaryZones.find(zone->name);
    if(secondary != dnsSecondaryZones.end() && secondary->second.expired)
    {
        r.flags = 0x8182;
        return r;
    }

    std::string delegation;
    std::size_t bestDelegation = 0;
    for(const auto &kv : dnsNsRecords)
    {
        const std::string &owner = kv.first;
        if(owner == zone->name || !IsSubdomain(key, owner) ||
           !IsSubdomain(owner, zone->name))
            continue;
        if(owner.size() > bestDelegation)
        {
            delegation = owner;
            bestDelegation = owner.size();
        }
    }

    auto addSoa = [&](std::vector<DnsAnswer> &out, const std::string &owner)
    {
        DnsAnswer a;
        a.name = owner;
        a.type = DnsMessage::kTypeSoa;
        a.cls = 1;
        a.ttl = zone->ttl;
        a.mname = zone->mname;
        a.rname = zone->rname;
        a.serial = zone->serial;
        a.refresh = zone->refresh;
        a.retry = zone->retry;
        a.expire = zone->expire;
        a.minimum = zone->minimum;
        out.push_back(a);
    };

    auto addGlue = [&](const std::string &ns)
    {
        auto it = dnsRecords.find(ns);
        if(it == dnsRecords.end())
            return;
        for(const Ipv4 &ip : it->second)
        {
            DnsAnswer a;
            a.name = ns;
            a.type = DnsMessage::kTypeA;
            a.cls = 1;
            a.ttl = DnsRrTtl(ns, DnsMessage::kTypeA, zone->ttl);
            a.ip = ip;
            r.additional.push_back(a);
        }
    };

    if(bestDelegation > 0)
    {
        auto it = dnsNsRecords.find(delegation);
        if(it != dnsNsRecords.end())
        {
            for(const std::string &ns : it->second)
            {
                DnsAnswer a;
                a.name = delegation;
                a.type = DnsMessage::kTypeNs;
                a.cls = 1;
                a.ttl = DnsRrTtl(delegation, DnsMessage::kTypeNs, zone->ttl);
                a.target = ns;
                r.authority.push_back(a);
                if(IsSubdomain(ns, delegation))
                    addGlue(ns);
            }
        }
        return r;
    }

    std::string name = key;
    bool found = false;
    std::string wildcard;
    for(int depth = 0; depth < 8; ++depth)
    {
        auto cit = dnsCnames.find(name);
        if(cit == dnsCnames.end())
            break;
        DnsAnswer cname;
        cname.name = name;
        cname.type = DnsMessage::kTypeCname;
        cname.cls = 1;
        cname.ttl = DnsRrTtl(name, DnsMessage::kTypeCname, zone->ttl);
        cname.target = cit->second;
        r.answers.push_back(cname);
        if(!IsSubdomain(cit->second, zone->name))
            break;
        name = cit->second;
    }

    if(!HasDnsName(key))
    {
        wildcard = FindDnsWildcard(key);
        if(!wildcard.empty() && !IsSubdomain(wildcard, zone->name))
            wildcard.clear();
        if(!wildcard.empty())
        {
            auto cit = dnsCnames.find(wildcard);
            if(cit != dnsCnames.end())
            {
                DnsAnswer cname;
                cname.name = key;
                cname.type = DnsMessage::kTypeCname;
                cname.cls = 1;
                cname.ttl = DnsRrTtl(wildcard, DnsMessage::kTypeCname, zone->ttl);
                cname.target = cit->second;
                r.answers.push_back(cname);
                name = cit->second;
            }
        }
    }

    std::string dataName = name;
    if(name == key && !wildcard.empty() &&
       dnsCnames.find(wildcard) == dnsCnames.end())
        dataName = wildcard;

    uint16_t qtype = m.questions[0].qtype;
    if(qtype == DnsMessage::kTypeSoa)
    {
        if(name == zone->name)
        {
            addSoa(r.answers, zone->name);
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypeNs)
    {
        auto it = dnsNsRecords.find(name);
        if(it != dnsNsRecords.end())
        {
            for(const std::string &ns : it->second)
            {
                DnsAnswer a;
                a.name = name;
                a.type = DnsMessage::kTypeNs;
                a.cls = 1;
                a.ttl = DnsRrTtl(name, DnsMessage::kTypeNs, zone->ttl);
                a.target = ns;
                r.answers.push_back(a);
                addGlue(ns);
            }
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypeA)
    {
        auto it = dnsRecords.find(dataName);
        if(it != dnsRecords.end())
        {
            for(const Ipv4 &ip : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeA;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeA, zone->ttl);
                a.ip = ip;
                r.answers.push_back(a);
            }
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypeAaaa)
    {
        auto it = dnsAaaa.find(dataName);
        if(it != dnsAaaa.end())
        {
            for(const Ipv6 &ip : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeAaaa;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeAaaa, zone->ttl);
                a.ip6 = ip;
                r.answers.push_back(a);
            }
            found = true;
        }
    }
    else if(qtype == DnsMessage::kTypePtr)
    {
        uint32_t ip = 0;
        if(ParseInAddrArpa(name, ip))
        {
            auto it = dnsReverse.find(ip);
            if(it != dnsReverse.end())
            {
                DnsAnswer a;
                a.name = name;
                a.type = DnsMessage::kTypePtr;
                a.cls = 1;
                a.ttl = zone->ttl;
                a.target = it->second;
                r.answers.push_back(a);
                found = true;
            }
        }
    }
    else if(qtype == DnsMessage::kTypeMx)
    {
        auto it = dnsMxRecords.find(dataName);
        if(it != dnsMxRecords.end())
        {
            for(const DnsMxRecord &mx : it->second)
            {
                DnsAnswer a;
                a.name = dataName == wildcard ? key : dataName;
                a.type = DnsMessage::kTypeMx;
                a.cls = 1;
                a.ttl = DnsRrTtl(dataName, DnsMessage::kTypeMx, zone->ttl);
                a.preference = mx.preference;
                a.target = mx.exchange;
                r.answers.push_back(a);
            }
            found = true;
        }
    }

    if(!found)
    {
        bool nameExists = !wildcard.empty() ||
                          name == zone->name ||
                          dnsRecords.find(name) != dnsRecords.end() ||
                          dnsAaaa.find(name) != dnsAaaa.end() ||
                          dnsMxRecords.find(name) != dnsMxRecords.end() ||
                          dnsCnames.find(name) != dnsCnames.end() ||
                          dnsNsRecords.find(name) != dnsNsRecords.end();
        r.flags = nameExists ? 0x8180 : 0x8183;
        addSoa(r.authority, zone->name);
    }

    return r;
}

DnsMessage EndDevice::BuildDnsAxfrResponse(const DnsMessage &m)
{
    DnsMessage r;
    r.id = m.id;
    r.flags = 0x8400;
    r.questions = m.questions;
    r.hasOpt = m.hasOpt;
    r.optUdpSize = m.hasOpt ? 1232 : 512;

    std::string zoneName = LowerName(m.questions[0].name);
    auto zit = dnsZones.find(zoneName);
    if(zit == dnsZones.end())
    {
        r.flags = 0x8185;
        return r;
    }
    const DnsZone &zone = zit->second;

    auto append = [&](const DnsAnswer &a) { r.answers.push_back(a); };
    auto addSoa = [&]()
    {
        DnsAnswer soa;
        soa.name = zone.name;
        soa.type = DnsMessage::kTypeSoa;
        soa.cls = 1;
        soa.ttl = zone.ttl;
        soa.mname = zone.mname;
        soa.rname = zone.rname;
        soa.serial = zone.serial;
        soa.refresh = zone.refresh;
        soa.retry = zone.retry;
        soa.expire = zone.expire;
        soa.minimum = zone.minimum;
        append(soa);
    };

    addSoa();
    auto apex = dnsNsRecords.find(zone.name);
    if(apex != dnsNsRecords.end())
    {
        for(const std::string &ns : apex->second)
        {
            DnsAnswer a;
            a.name = zone.name;
            a.type = DnsMessage::kTypeNs;
            a.cls = 1;
            a.ttl = DnsRrTtl(zone.name, DnsMessage::kTypeNs, zone.ttl);
            a.target = ns;
            append(a);
        }
    }

    for(const auto &kv : dnsRecords)
    {
        if(!IsSubdomain(kv.first, zone.name))
            continue;
        for(const Ipv4 &ip : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeA;
            a.cls = 1;
            a.ttl = DnsRrTtl(kv.first, DnsMessage::kTypeA, zone.ttl);
            a.ip = ip;
            append(a);
        }
    }

    for(const auto &kv : dnsAaaa)
    {
        if(!IsSubdomain(kv.first, zone.name))
            continue;
        for(const Ipv6 &ip : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeAaaa;
            a.cls = 1;
            a.ttl = DnsRrTtl(kv.first, DnsMessage::kTypeAaaa, zone.ttl);
            a.ip6 = ip;
            append(a);
        }
    }

    for(const auto &kv : dnsCnames)
    {
        if(!IsSubdomain(kv.first, zone.name))
            continue;
        DnsAnswer a;
        a.name = kv.first;
        a.type = DnsMessage::kTypeCname;
        a.cls = 1;
        a.ttl = DnsRrTtl(kv.first, DnsMessage::kTypeCname, zone.ttl);
        a.target = kv.second;
        append(a);
    }

    for(const auto &kv : dnsMxRecords)
    {
        if(!IsSubdomain(kv.first, zone.name))
            continue;
        for(const DnsMxRecord &mx : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeMx;
            a.cls = 1;
            a.ttl = DnsRrTtl(kv.first, DnsMessage::kTypeMx, zone.ttl);
            a.preference = mx.preference;
            a.target = mx.exchange;
            append(a);
        }
    }

    for(const auto &kv : dnsNsRecords)
    {
        if(kv.first == zone.name || !IsSubdomain(kv.first, zone.name))
            continue;
        for(const std::string &ns : kv.second)
        {
            DnsAnswer a;
            a.name = kv.first;
            a.type = DnsMessage::kTypeNs;
            a.cls = 1;
            a.ttl = DnsRrTtl(kv.first, DnsMessage::kTypeNs, zone.ttl);
            a.target = ns;
            append(a);
        }
    }

    addSoa();
    return r;
}

DnsMessage EndDevice::BuildDnsIxfrResponse(const DnsMessage &m)
{
    DnsMessage r;
    r.id = m.id;
    r.flags = 0x8400;
    r.questions = m.questions;
    r.hasOpt = m.hasOpt;
    r.optUdpSize = m.hasOpt ? 1232 : 512;

    std::string zoneName = LowerName(m.questions[0].name);
    auto zit = dnsZones.find(zoneName);
    if(zit == dnsZones.end())
    {
        r.flags = 0x8185;
        return r;
    }
    const DnsZone &zone = zit->second;
    uint32_t clientSerial = 0;
    for(const DnsAnswer &a : m.authority)
    {
        if(a.type == DnsMessage::kTypeSoa)
        {
            clientSerial = a.serial;
            break;
        }
    }

    auto addSoa = [&](uint32_t serial)
    {
        DnsAnswer soa;
        soa.name = zone.name;
        soa.type = DnsMessage::kTypeSoa;
        soa.cls = 1;
        soa.ttl = zone.ttl;
        soa.mname = zone.mname;
        soa.rname = zone.rname;
        soa.serial = serial;
        soa.refresh = zone.refresh;
        soa.retry = zone.retry;
        soa.expire = zone.expire;
        soa.minimum = zone.minimum;
        r.answers.push_back(soa);
    };

    if(clientSerial >= zone.serial)
    {
        addSoa(zone.serial);
        return r;
    }

    auto jit = dnsJournal.find(zone.name);
    std::vector<const DnsJournalEntry *> chain;
    uint32_t serial = clientSerial;
    while(serial != zone.serial)
    {
        const DnsJournalEntry *found = nullptr;
        if(jit != dnsJournal.end())
        {
            for(const DnsJournalEntry &entry : jit->second)
                if(entry.fromSerial == serial)
                {
                    found = &entry;
                    break;
                }
        }
        if(!found)
            break;
        chain.push_back(found);
        serial = found->toSerial;
        if(chain.size() > 64)
            break;
    }

    if(serial != zone.serial || chain.empty())
        return BuildDnsAxfrResponse(m);

    addSoa(zone.serial);
    for(const DnsJournalEntry *entry : chain)
    {
        addSoa(entry->fromSerial);
        for(const DnsAnswer &a : entry->deleted)
            r.answers.push_back(a);
        addSoa(entry->toSerial);
        for(const DnsAnswer &a : entry->added)
            r.answers.push_back(a);
    }
    addSoa(zone.serial);
    return r;
}

bool EndDevice::TryFollowDnsReferral(const DnsMessage &m)
{
    if(!m.answers.empty() || m.Rcode() != 0)
        return false;

    std::string owner;
    std::vector<std::string> nameservers;
    for(const DnsAnswer &a : m.authority)
    {
        if(a.type == DnsMessage::kTypeNs)
        {
            owner = LowerName(a.name);
            nameservers.push_back(LowerName(a.target));
        }
    }
    if(nameservers.empty())
        return false;

    Ipv4 glue;
    bool haveGlue = false;
    for(const std::string &ns : nameservers)
    {
        for(const DnsAnswer &a : m.additional)
        {
            if(a.type == DnsMessage::kTypeA && LowerName(a.name) == ns)
            {
                glue = a.ip;
                haveGlue = true;
                break;
            }
        }
        if(haveGlue)
            break;
    }

    if(dnsReferralDepth >= 8 || (dnsInternalQuery && !haveGlue))
    {
        std::string failed = dnsInternalQuery ? dnsOriginalName : dnsQueryName;
        std::cout << "dns: " << failed << " -> SERVFAIL\n";
        dnsClientPort = 0;
        dnsInternalQuery = false;
        return true;
    }

    if(!haveGlue)
    {
        ++dnsReferralDepth;
        dnsInternalQuery = true;
        dnsOriginalName = dnsQueryName;
        dnsOriginalType = dnsQueryType;
        dnsReferralOwner = owner;
        std::vector<Ipv4> resolvers = dnsQueryServers;
        if(resolvers.empty())
            resolvers.push_back(dnsQueryServer);
        std::cout << "dns: referral " << owner << " -> resolve NS "
                  << nameservers[0] << "\n";
        StartDnsQuery(nameservers[0], DnsMessage::kTypeA, resolvers);
        return true;
    }

    ++dnsReferralDepth;
    std::cout << "dns: referral " << owner << " -> "
              << glue.ToString() << "\n";
    StartDnsQuery(dnsQueryName, dnsQueryType,
                  std::vector<Ipv4>{ glue });
    return true;
}

void EndDevice::ProcessDnsResponse(const DnsMessage &m)
{
    if(dnsInternalQuery)
    {
        Ipv4 glue;
        bool haveGlue = false;
        for(const DnsAnswer &a : m.answers)
        {
            if(a.type == DnsMessage::kTypeA)
            {
                glue = a.ip;
                haveGlue = true;
                break;
            }
        }

        std::string original = dnsOriginalName;
        uint16_t originalType = dnsOriginalType;
        std::string owner = dnsReferralOwner;
        dnsInternalQuery = false;
        dnsClientPort = 0;

        if(!haveGlue)
        {
            std::cout << "dns: " << original << " -> SERVFAIL\n";
            return;
        }

        std::cout << "dns: referral " << owner << " -> "
                  << glue.ToString() << "\n";
        StartDnsQuery(original, originalType, std::vector<Ipv4>{ glue });
        return;
    }

    uint32_t ttl = 0xFFFFFFFFu;
    bool ttlSeen = false;
    bool hasData = false;
    for(const DnsAnswer &a : m.answers)
    {
        if(a.type == DnsMessage::kTypeA ||
           a.type == DnsMessage::kTypeAaaa ||
           a.type == DnsMessage::kTypeCname ||
           a.type == DnsMessage::kTypePtr ||
           a.type == DnsMessage::kTypeMx ||
           a.type == DnsMessage::kTypeNs ||
           a.type == DnsMessage::kTypeSoa)
        {
            ttl = std::min(ttl, a.ttl);
            ttlSeen = true;
        }
        if(a.type == DnsMessage::kTypeA ||
           a.type == DnsMessage::kTypeAaaa ||
           a.type == DnsMessage::kTypePtr ||
           a.type == DnsMessage::kTypeMx ||
           a.type == DnsMessage::kTypeNs ||
           a.type == DnsMessage::kTypeSoa)
            hasData = true;
    }

    bool printed = PrintDnsAnswers(dnsQueryName, m.answers);
    if(!printed)
    {
        if(m.Rcode() == 3)
            std::cout << "dns: " << dnsQueryName << " -> NXDOMAIN\n";
        else if(m.Rcode() == 0)
            std::cout << "dns: " << dnsQueryName << " -> NODATA\n";
        else
            std::cout << "dns: " << dnsQueryName << " -> SERVFAIL\n";
    }

    auto cacheKey = std::make_pair(dnsQueryName, dnsQueryType);
    if(hasData && ttlSeen && ttl > 0)
    {
        uint64_t now = clock ? clock->Now() : 0;
        DnsCacheEntry entry;
        entry.answers = m.answers;
        entry.expires = now + ClampDnsTtl(ttl);
        entry.negative = false;
        entry.nxdomain = false;
        StoreDnsCache(cacheKey, entry);
    }
    else if(m.Rcode() == 0 || m.Rcode() == 3)
    {
        uint32_t negTtl = 0xFFFFFFFFu;
        bool negSeen = false;
        for(const DnsAnswer &a : m.authority)
        {
            if(a.type == DnsMessage::kTypeSoa)
            {
                negTtl = std::min(negTtl, std::min(a.ttl, a.minimum));
                negSeen = true;
            }
        }
        if(negSeen && negTtl > 0)
        {
            uint64_t now = clock ? clock->Now() : 0;
            DnsCacheEntry entry;
            entry.expires = now + ClampDnsTtl(negTtl);
            entry.negative = true;
            entry.nxdomain = m.Rcode() == 3;
            StoreDnsCache(cacheKey, entry);
        }
        else
        {
            RemoveDnsCache(cacheKey);
        }
    }
    dnsClientPort = 0;
}

void EndDevice::StartDnsTcpQuery()
{
    Port *egress = nullptr;
    Ipv4 nextHop;
    if(!ResolveNextHop(dnsQueryServer, egress, nextHop))
    {
        FailDnsQuery();
        return;
    }

    CleanupTcpConns();
    if(tcpConns.size() >= kMaxTcpConns)
    {
        ++tcpDropped;
        FailDnsQuery();
        return;
    }

    TcpConnection &c = NewTcpConnection();
    TcpConnection *cp = &c;
    c.onConnected = [this, cp]() { SendDnsTcpQuery(*cp); };
    c.onData = [this, cp](const std::vector<uint8_t> &data) {
        OnDnsTcpData(*cp, data);
    };
    c.onReset = [this, cp]() {
        if(dnsTcpActive && dnsTcpConn == cp)
        {
            dnsTcpActive = false;
            dnsTcpConn = nullptr;
            FailDnsQuery();
        }
    };
    dnsTcpConn = cp;
    dnsTcpActive = true;
    c.OpenActive(egress->ip, nextDnsTcpLocalPort++, dnsQueryServer, 53);
    IndexTcpConn(c);
    if(dnsTcpActive)
        ScheduleDnsRetry(std::max<uint64_t>(dnsTimeout * 5, 500));
}

void EndDevice::SendDnsTcpQuery(TcpConnection &conn)
{
    if(!dnsTcpActive || dnsTcpConn != &conn)
        return;

    DnsMessage q;
    q.id = dnsQueryId;
    q.flags = 0x0100;
    q.questions.push_back(DnsQuestion{ dnsQueryName, dnsQueryType, 1 });
    q.hasOpt = true;
    q.optUdpSize = 1232;

    std::vector<uint8_t> bytes = q.ToBytes();
    if(bytes.empty() || bytes.size() > 65535)
    {
        conn.Abort();
        dnsTcpActive = false;
        dnsTcpConn = nullptr;
        FailDnsQuery();
        return;
    }

    std::vector<uint8_t> framed;
    framed.reserve(bytes.size() + 2);
    framed.push_back(uint8_t(bytes.size() >> 8));
    framed.push_back(uint8_t(bytes.size() & 0xFF));
    framed.insert(framed.end(), bytes.begin(), bytes.end());
    conn.SendData(framed);
}

void EndDevice::OnDnsTcpData(TcpConnection &conn,
                             const std::vector<uint8_t> &data)
{
    conn.appRx.insert(conn.appRx.end(), data.begin(), data.end());

    if(conn.localPort == 53)
    {
        while(conn.appRx.size() >= 2)
        {
            std::size_t len = (std::size_t(conn.appRx[0]) << 8) |
                              conn.appRx[1];
            if(len == 0 || len > 65535)
            {
                conn.Abort();
                return;
            }
            if(conn.appRx.size() < len + 2)
                return;
            std::vector<uint8_t> message(conn.appRx.begin() + 2,
                                         conn.appRx.begin() + 2 + len);
            conn.appRx.erase(conn.appRx.begin(),
                             conn.appRx.begin() + 2 + len);
            HandleDnsTcpQuery(conn, message);
        }
        return;
    }

    if(!dnsTcpActive || dnsTcpConn != &conn)
        return;

    while(conn.appRx.size() >= 2)
    {
        std::size_t len = (std::size_t(conn.appRx[0]) << 8) | conn.appRx[1];
        if(len == 0 || len > 65535)
            break;
        if(conn.appRx.size() < len + 2)
            return;

        std::vector<uint8_t> message(conn.appRx.begin() + 2,
                                     conn.appRx.begin() + 2 + len);
        conn.appRx.erase(conn.appRx.begin(),
                         conn.appRx.begin() + 2 + len);

        DnsMessage m;
        if(!DnsMessage::TryFromBytes(message, m))
            continue;
        if(!m.IsResponse() || m.id != dnsQueryId || m.questions.empty())
            continue;

        std::string qname;
        for(char ch : m.questions[0].name)
            qname.push_back(char(std::tolower(static_cast<unsigned char>(ch))));
        if(qname != dnsQueryName || m.questions[0].qtype != dnsQueryType)
            continue;

        CancelDnsRetry();
        dnsTcpActive = false;
        dnsTcpConn = nullptr;
        ProcessDnsResponse(m);
        conn.Close();
        return;
    }
}

void EndDevice::HandleDnsTcpQuery(TcpConnection &conn,
                                  const std::vector<uint8_t> &message)
{
    DnsMessage m;
    if(!DnsMessage::TryFromBytes(message, m))
        return;
    if(m.Opcode() == 5 && !m.IsResponse())
    {
        DnsMessage r = ProcessDnsUpdate(m, conn.remoteIp);
        std::vector<uint8_t> bytes = r.ToBytes();
        if(bytes.empty() || bytes.size() > 65535)
        {
            conn.Abort();
            return;
        }
        std::vector<uint8_t> framed;
        framed.reserve(bytes.size() + 2);
        framed.push_back(uint8_t(bytes.size() >> 8));
        framed.push_back(uint8_t(bytes.size() & 0xFF));
        framed.insert(framed.end(), bytes.begin(), bytes.end());
        conn.SendData(framed);
        conn.Close();
        return;
    }
    if(m.IsResponse() || m.questions.empty())
        return;

    auto refuse = [&]()
    {
        DnsMessage r;
        r.id = m.id;
        r.flags = 0x8185;
        r.questions = m.questions;
        std::vector<uint8_t> bytes = r.ToBytes();
        if(bytes.empty() || bytes.size() > 65535)
        {
            conn.Abort();
            return;
        }
        std::vector<uint8_t> framed;
        framed.reserve(bytes.size() + 2);
        framed.push_back(uint8_t(bytes.size() >> 8));
        framed.push_back(uint8_t(bytes.size() & 0xFF));
        framed.insert(framed.end(), bytes.begin(), bytes.end());
        conn.SendData(framed);
        conn.Close();
    };

    bool axfr = m.questions[0].qtype == DnsMessage::kTypeAxfr;
    bool ixfr = m.questions[0].qtype == DnsMessage::kTypeIxfr;
    bool transfer = axfr || ixfr;
    if(transfer && !DnsAxfrAllowed(conn.remoteIp))
    {
        refuse();
        return;
    }

    std::vector<uint8_t> requestMac;
    const DnsTsigKey *tsigKey = nullptr;
    uint64_t now = clock ? clock->Now() : 0;
    if(m.tsig.present)
    {
        tsigKey = FindDnsTsigKey(m.tsig.keyName);
        bool ok = tsigKey != nullptr && tsigKey->algorithm == m.tsig.algorithm &&
                  m.tsig.originalId == m.id;
        if(ok)
        {
            uint64_t ts = m.tsig.timeSigned;
            uint64_t diff = ts > now ? ts - now : now - ts;
            ok = diff <= m.tsig.fudge;
        }
        if(ok)
            ok = m.VerifyTsig(tsigKey->secret);
        if(!ok)
        {
            refuse();
            return;
        }
        requestMac = m.tsig.mac;
    }
    else if(transfer && dnsTsigRequired)
    {
        refuse();
        return;
    }

    DnsMessage r =
        axfr ? BuildDnsAxfrResponse(m)
             : (ixfr ? BuildDnsIxfrResponse(m) : BuildDnsResponse(m));

    if(axfr && r.Rcode() == 0)
    {
        std::vector<DnsMessage> chunks;
        DnsMessage cur;
        auto resetChunk = [&]()
        {
            cur = DnsMessage();
            cur.id = r.id;
            cur.flags = r.flags;
            cur.questions = r.questions;
            cur.hasOpt = r.hasOpt;
            cur.optUdpSize = r.optUdpSize;
        };
        resetChunk();
        for(const DnsAnswer &a : r.answers)
        {
            cur.answers.push_back(a);
            if(cur.answers.size() % 32 == 0)
            {
                std::vector<uint8_t> probe = cur.ToBytes();
                if(probe.size() > 60000)
                {
                    cur.answers.pop_back();
                    chunks.push_back(cur);
                    resetChunk();
                    cur.answers.push_back(a);
                }
            }
        }
        if(!cur.answers.empty())
            chunks.push_back(cur);

        std::vector<uint8_t> framed;
        for(DnsMessage &chunk : chunks)
        {
            if(!requestMac.empty() && tsigKey)
            {
                chunk.tsig.present = true;
                chunk.tsig.keyName = m.tsig.keyName;
                chunk.tsig.algorithm = tsigKey->algorithm;
                chunk.tsig.timeSigned = now;
                chunk.tsig.fudge = 300;
                chunk.tsig.originalId = m.id;
                chunk.tsig.error = 0;
                if(!chunk.SignTsig(tsigKey->secret, &requestMac))
                {
                    conn.Abort();
                    return;
                }
            }
            std::vector<uint8_t> bytes = chunk.ToBytes();
            if(bytes.empty() || bytes.size() > 65535)
            {
                conn.Abort();
                return;
            }
            framed.push_back(uint8_t(bytes.size() >> 8));
            framed.push_back(uint8_t(bytes.size() & 0xFF));
            framed.insert(framed.end(), bytes.begin(), bytes.end());
        }
        conn.SendData(framed);
        conn.Close();
        return;
    }

    if(!requestMac.empty() && tsigKey)
    {
        r.tsig.present = true;
        r.tsig.keyName = m.tsig.keyName;
        r.tsig.algorithm = tsigKey->algorithm;
        r.tsig.timeSigned = now;
        r.tsig.fudge = 300;
        r.tsig.originalId = m.id;
        r.tsig.error = 0;
        if(!r.SignTsig(tsigKey->secret, &requestMac))
        {
            conn.Abort();
            return;
        }
    }

    std::vector<uint8_t> bytes = r.ToBytes();
    if(bytes.empty() || bytes.size() > 65535)
    {
        conn.Abort();
        return;
    }

    std::vector<uint8_t> framed;
    framed.reserve(bytes.size() + 2);
    framed.push_back(uint8_t(bytes.size() >> 8));
    framed.push_back(uint8_t(bytes.size() & 0xFF));
    framed.insert(framed.end(), bytes.begin(), bytes.end());
    conn.SendData(framed);
    conn.Close();
}

void EndDevice::HandleDns(Port *, const IpPacket &pkt, const UdpDatagram &dgram)
{
    DnsMessage m;
    if(!DnsMessage::TryFromBytes(dgram.payload, m))
        return;

    if(dgram.dstPort == 53 && dnsServerEnabled && m.Opcode() == 4)
    {
        if(m.IsResponse() || m.questions.empty())
            return;

        std::string zone = LowerName(m.questions[0].name);
        auto sit = dnsSecondaryZones.find(zone);
        DnsMessage r;
        r.id = m.id;
        r.flags = 0x8000;
        r.SetOpcode(4);
        r.flags = uint16_t((r.flags & ~0x000Fu) |
                           (sit == dnsSecondaryZones.end() ? 5 : 0));
        r.questions = m.questions;
        std::vector<uint8_t> bytes = r.ToBytes();
        if(!bytes.empty())
            SendUdp(pkt.srcIp, dgram.srcPort,
                    std::string(bytes.begin(), bytes.end()), 53);

        if(sit != dnsSecondaryZones.end())
            StartDnsSecondaryTransfer(zone, sit->second.primary);
        return;
    }

    if(dgram.dstPort == 53 && dnsServerEnabled && m.Opcode() == 5 &&
       !m.IsResponse())
    {
        DnsMessage r = ProcessDnsUpdate(m, pkt.srcIp);
        std::vector<uint8_t> bytes = r.ToBytes();
        if(!bytes.empty())
            SendUdp(pkt.srcIp, dgram.srcPort,
                    std::string(bytes.begin(), bytes.end()), 53);
        return;
    }

    if(dnsUpdateActive && dgram.dstPort == dnsUpdatePort &&
       m.IsResponse() && m.Opcode() == 5)
    {
        if(m.id != dnsUpdateId || !(pkt.srcIp == dnsUpdateServer))
            return;

        bool sigOk = true;
        if(!dnsUpdateRequestMac.empty())
        {
            sigOk = m.tsig.present &&
                    m.tsig.keyName == dnsTsigClientName &&
                    m.tsig.algorithm == dnsTsigClientAlgorithm &&
                    m.tsig.originalId == dnsUpdateId;
            if(sigOk)
            {
                uint64_t now = clock ? clock->Now() : 0;
                uint64_t ts = m.tsig.timeSigned;
                uint64_t diff = ts > now ? ts - now : now - ts;
                sigOk = diff <= m.tsig.fudge;
            }
            if(sigOk)
                sigOk = m.VerifyTsig(dnsTsigClientSecret,
                                     &dnsUpdateRequestMac);
        }

        std::string result = "failed";
        if(!sigOk)
            result = "failed";
        else if(m.Rcode() == 0)
            result = "ok";
        else if(m.Rcode() == 5)
            result = "refused";
        else if(m.Rcode() == 9)
            result = "notauth";
        else if(m.Rcode() == 1)
            result = "formerr";
        else if(m.Rcode() == 3)
            result = "nxdomain";
        else if(m.Rcode() == 4)
            result = "notimp";
        else if(m.Rcode() == 7 || m.Rcode() == 8)
            result = "prereq";

        std::cout << "dns: update " << dnsUpdateZone << " "
                  << result << "\n";
        dnsUpdateActive = false;
        dnsUpdateRequestMac.clear();
        return;
    }

    if(dgram.dstPort == 53 && dnsServerEnabled)
    {
        if(m.IsResponse() || m.questions.empty())
            return;

        DnsMessage r = BuildDnsResponse(m);
        uint16_t limit = 512;
        if(m.hasOpt)
            limit = std::max<uint16_t>(512, std::min<uint16_t>(m.optUdpSize, 4096));

        std::vector<uint8_t> bytes = r.ToBytes();
        if(bytes.size() > limit)
        {
            DnsMessage t;
            t.id = r.id;
            t.flags = r.flags | 0x0200;
            t.questions = r.questions;
            t.hasOpt = r.hasOpt;
            t.optUdpSize = r.optUdpSize;
            bytes = t.ToBytes();
        }
        if(bytes.empty())
            return;
        SendUdp(pkt.srcIp, dgram.srcPort,
                std::string(bytes.begin(), bytes.end()), 53);
        return;
    }

    if(dgram.srcPort == 53 && dnsClientPort != 0 && dgram.dstPort == dnsClientPort)
    {
        if(!m.IsResponse() || m.id != dnsQueryId)
            return;
        if(!(pkt.srcIp == dnsQueryServer) || m.questions.empty())
            return;

        std::string qname;
        for(char c : m.questions[0].name)
            qname.push_back(char(std::tolower(static_cast<unsigned char>(c))));
        if(qname != dnsQueryName || m.questions[0].qtype != dnsQueryType)
            return;

        CancelDnsRetry();

        if(m.flags & 0x0200)
        {
            dnsClientPort = 0;
            std::cout << "dns: truncated; retrying over TCP\n";
            StartDnsTcpQuery();
            return;
        }

        if(TryFollowDnsReferral(m))
            return;

        ProcessDnsResponse(m);
    }
}
