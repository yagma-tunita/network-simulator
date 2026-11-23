#include "Topology.hpp"
#include "../device/Device.hpp"
#include "../device/Port.hpp"
#include "../link/Link.hpp"
#include "../device/EndDevice.hpp"
#include "../device/Switch.hpp"
#include "../device/Router.hpp"
#include "../engine/Engine.hpp"
#include <stdexcept>
#include <algorithm>
#include <utility>
#include <memory>
#include <cstddef>

Topology::Topology() = default;
Topology::~Topology() = default;

template <class T>
static T *CreateDevice(std::map<std::string, std::unique_ptr<Device>> &devices,
                       Engine *engine, const std::string &name)
{
    if (devices.count(name))
        throw std::invalid_argument("Topology: duplicate device '" + name + "'");
    if (devices.size() >= Topology::kMaxDevices)
        throw std::length_error("device limit reached (4096)");

    auto dev = std::make_unique<T>();
    T *raw = dev.get();
    if (engine)
    {
        raw->SetClock(engine);
        raw->SetScheduler(engine);
    }
    devices[name] = std::move(dev);
    return raw;
}

void Topology::SetEngine(Engine *e)
{
    engine = e;
    for (auto &kv : devices)
    {
        kv.second->SetClock(e);
        kv.second->SetScheduler(e);
    }
    for (auto &l : links)
        l->SetScheduler(e);
}

void Topology::Clear()
{
    links.clear();
    ports.clear();
    devices.clear();
}

namespace
{
    void DetachLinksFor(std::vector<std::unique_ptr<Link>> &links, Port *p)
    {
        if(!p) return;
        for(auto it = links.begin(); it != links.end(); )
        {
            Link *l = it->get();
            if(l->A == p || l->B == p)
            {
                Port *other = (l->A == p) ? l->B : l->A;
                if(other) other->link = nullptr;
                p->link = nullptr;
                it = links.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    void ErasePort(std::vector<std::unique_ptr<Port>> &ports, Port *p)
    {
        for(auto it = ports.begin(); it != ports.end(); ++it)
        {
            if(it->get() == p)
            {
                ports.erase(it);
                return;
            }
        }
    }
}

void Topology::RemovePort(const std::string &device, std::size_t idx)
{
    Device *d = FindDevice(device);
    if(idx >= d->portList.size())
        throw std::out_of_range("port index out of range for '" + device + "'");

    Port *p = d->portList[idx];
    DetachLinksFor(links, p);
    d->portList.erase(d->portList.begin() + idx);
    ErasePort(ports, p);

    if(Router *r = dynamic_cast<Router *>(d))
        r->RebuildConnected();
}

void Topology::RemoveDevice(const std::string &name)
{
    Device *d = FindDevice(name);

    std::vector<Port *> owned = d->portList;
    for(Port *p : owned)
    {
        DetachLinksFor(links, p);
        ErasePort(ports, p);
    }
    d->portList.clear();
    devices.erase(name);
}

void Topology::Disconnect(const std::string &device, std::size_t idx)
{
    Port *p = FindPort(device, idx);
    DetachLinksFor(links, p);
}

void Topology::RenameDevice(const std::string &oldName, const std::string &newName)
{
    if(newName.empty())
        throw std::invalid_argument("device name cannot be empty");
    if(devices.count(newName))
        throw std::invalid_argument("device '" + newName + "' already exists");

    auto it = devices.find(oldName);
    if(it == devices.end())
        throw std::invalid_argument("unknown device '" + oldName + "'");

    devices[newName] = std::move(it->second);
    devices.erase(it);
}

void Topology::SetPortIp(const std::string &device, std::size_t idx,
                         const Ipv4 &ip, uint8_t prefix)
{
    Port *p = FindPort(device, idx);
    p->SetIp(ip, prefix);

    Device *d = FindDevice(device);
    if(Router *r = dynamic_cast<Router *>(d))
        r->RebuildConnected();
}

EndDevice *Topology::AddEndDevice(const std::string &name)
{
    return CreateDevice<EndDevice>(devices, engine, name);
}

Switch *Topology::AddSwitch(const std::string &name)
{
    return CreateDevice<Switch>(devices, engine, name);
}

Router *Topology::AddRouter(const std::string &name)
{
    return CreateDevice<Router>(devices, engine, name);
}

Port *Topology::AddPort(const std::string &device, const Mac &mac)
{
    Device *dev = FindDevice(device);
    if (ports.size() >= kMaxPorts)
        throw std::length_error("port limit reached (65536)");
    if (dev->portList.size() >= kMaxPortsPerDevice)
        throw std::length_error("ports-per-device limit reached (1024)");

    auto up = std::make_unique<Port>();
    Port *p = up.get();
    p->mac = mac;
    p->owner = dev;
    ports.push_back(std::move(up));
    dev->AddPort(p);
    return p;
}

Port *Topology::AddPort(const std::string &device, const Mac &mac,
                        const Ipv4 &ip, uint8_t prefix)
{
    Device *dev = FindDevice(device);
    if (ports.size() >= kMaxPorts)
        throw std::length_error("port limit reached (65536)");
    if (dev->portList.size() >= kMaxPortsPerDevice)
        throw std::length_error("ports-per-device limit reached (1024)");

    auto up = std::make_unique<Port>(mac, dev, ip, prefix, nullptr);
    Port *p = up.get();
    ports.push_back(std::move(up));
    dev->AddPort(p);
    return p;
}

Link *Topology::Connect(const std::string &devA, std::size_t idxA,
                        const std::string &devB, std::size_t idxB,
                        uint64_t delay)
{
    Port *a = FindPort(devA, idxA);
    Port *b = FindPort(devB, idxB);
    if (links.size() >= kMaxLinks)
        throw std::length_error("link limit reached (65536)");

    auto up = std::make_unique<Link>(a, b);
    Link *l = up.get();
    l->SetScheduler(engine);
    l->SetDelay(delay);
    links.push_back(std::move(up));
    return l;
}

void Topology::AddRoute(const std::string &router, const Ipv4Subnet &dst, const Ipv4 &nextHop)
{
    Device *d = FindDevice(router);
    Router *r = dynamic_cast<Router *>(d);
    if (!r)
        throw std::invalid_argument("Topology: '" + router + "' is not a router");
    r->AddRoute(dst, nextHop, false);
}

Device *Topology::FindDevice(const std::string &name)
{
    auto it = devices.find(name);
    if (it == devices.end())
        throw std::invalid_argument("Topology: unknown device '" + name + "'");
    return it->second.get();
}

Port *Topology::FindPort(const std::string &device, std::size_t idx)
{
    Device *d = FindDevice(device);
    if (idx >= d->portList.size())
        throw std::out_of_range("Topology: port index out of range for '" + device + "'");
    return d->portList[idx];
}
