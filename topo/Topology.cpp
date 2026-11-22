#include "Topology.hpp"
#include "../device/Device.hpp"
#include "../device/Port.hpp"
#include "../link/Link.hpp"
#include "../device/EndDevice.hpp"
#include "../device/Switch.hpp"
#include "../device/Router.hpp"
#include "../engine/Engine.hpp"
#include <stdexcept>

Topology::Topology() = default;
Topology::~Topology() = default;

template <class T>
static T *CreateDevice(std::map<std::string, std::unique_ptr<Device>> &devices,
                       Engine *engine, const std::string &name)
{
    if (devices.count(name))
        throw std::invalid_argument("Topology: duplicate device '" + name + "'");

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
