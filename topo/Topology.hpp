#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/Mac.hpp"

struct Engine;
struct Device;
struct Port;
struct Link;
struct EndDevice;
struct Switch;
struct Router;

struct Topology
{
    Engine *engine = nullptr;
    std::map<std::string, std::unique_ptr<Device>> devices;
    std::vector<std::unique_ptr<Port>> ports;
    std::vector<std::unique_ptr<Link>> links;

    Topology();
    ~Topology();

    void SetEngine(Engine *e);
    void Clear();

    EndDevice *AddEndDevice(const std::string &name);
    Switch *AddSwitch(const std::string &name);
    Router *AddRouter(const std::string &name);

    Port *AddPort(const std::string &device, const Mac &mac);
    Port *AddPort(const std::string &device, const Mac &mac, const Ipv4 &ip, uint8_t prefix);

    Link *Connect(const std::string &devA, std::size_t idxA,
                  const std::string &devB, std::size_t idxB,
                  uint64_t delay = 1);

    void AddRoute(const std::string &router, const Ipv4Subnet &dst, const Ipv4 &nextHop);

    Device *FindDevice(const std::string &name);
    Port *FindPort(const std::string &device, std::size_t idx);
};
