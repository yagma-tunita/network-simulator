#include "TopoCommand.hpp"
#include "Topology.hpp"
#include "../device/Device.hpp"
#include "../device/EndDevice.hpp"
#include "../device/Switch.hpp"
#include "../device/Port.hpp"
#include "../link/Link.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/Mac.hpp"
#include <sstream>
#include <stdexcept>
#include <utility>
#include <iostream>
#include <cstddef>

std::vector<std::string> Tokenize(const std::string &line)
{
    std::istringstream iss(line);
    std::vector<std::string> tokens;
    std::string w;
    while (iss >> w)
        tokens.push_back(w);
    return tokens;
}

namespace
{
    std::pair<std::string, std::size_t> ParsePortRef(const std::string &s)
    {
        auto pos = s.find(':');
        if (pos == std::string::npos)
            throw std::invalid_argument("expected <device>:<index>, got '" + s + "'");
        std::string name = s.substr(0, pos);
        std::size_t idx = std::stoul(s.substr(pos + 1));
        return { name, idx };
    }

    void ParseIpPrefix(const std::string &s, Ipv4 &ip, uint8_t &prefix)
    {
        auto pos = s.find('/');
        if (pos == std::string::npos)
            throw std::invalid_argument("expected <ip>/<prefix>, got '" + s + "'");

        if (!Ipv4::TryParse(s.substr(0, pos), ip))
            throw std::invalid_argument("bad ip in '" + s + "'");

        std::string right = s.substr(pos + 1);
        if (right.empty())
            throw std::invalid_argument("bad prefix in '" + s + "'");

        unsigned p = 0;
        for (char c : right)
        {
            if (c < '0' || c > '9')
                throw std::invalid_argument("bad prefix in '" + s + "'");
            p = p * 10 + unsigned(c - '0');
            if (p > 32)
                throw std::invalid_argument("prefix out of range in '" + s + "'");
        }
        prefix = uint8_t(p);
    }
}

void ExecuteCommand(Topology &topo, const std::vector<std::string> &t)
{
    if (t.empty())
        return;

    const std::string &cmd = t[0];

    if (cmd == "add-device")
    {
        if (t.size() != 3)
            throw std::invalid_argument("add-device <name> end|switch|router");
        if (t[2] == "end")
            topo.AddEndDevice(t[1]);
        else if (t[2] == "switch")
            topo.AddSwitch(t[1]);
        else if (t[2] == "router")
            topo.AddRouter(t[1]);
        else
            throw std::invalid_argument("unknown device kind '" + t[2] + "'");
    }
    else if (cmd == "add-port")
    {
        if (t.size() != 3 && t.size() != 4)
            throw std::invalid_argument("add-port <device> <mac> [<ip>/<prefix>]");

        Mac mac(t[2]);
        if (t.size() == 3)
        {
            topo.AddPort(t[1], mac);
        }
        else
        {
            Ipv4 ip;
            uint8_t prefix = 0;
            ParseIpPrefix(t[3], ip, prefix);
            topo.AddPort(t[1], mac, ip, prefix);
        }
    }
    else if (cmd == "connect")
    {
        if (t.size() != 3 && t.size() != 4)
            throw std::invalid_argument("connect <dev:idx> <dev:idx> [delay]");

        auto a = ParsePortRef(t[1]);
        auto b = ParsePortRef(t[2]);
        uint64_t delay = (t.size() == 4) ? std::stoull(t[3]) : 1;
        topo.Connect(a.first, a.second, b.first, b.second, delay);
    }
    else if (cmd == "add-route")
    {
        if (t.size() != 4)
            throw std::invalid_argument("add-route <router> <dst/p> <next-hop-ip>");

        Ipv4Subnet dst(t[2]);
        Ipv4 nextHop(t[3]);
        topo.AddRoute(t[1], dst, nextHop);
    }
    else if (cmd == "set-vlan")
    {
        if (t.size() != 3)
            throw std::invalid_argument("set-vlan <dev:idx> <vid>");

        auto ref = ParsePortRef(t[1]);
        unsigned vid = std::stoul(t[2]);
        if (vid > 4094)
            throw std::invalid_argument("vlan id out of range");

        Port *p = topo.FindPort(ref.first, ref.second);
        p->vlan = uint16_t(vid);
        p->tagged = false;
    }
    else if (cmd == "set-trunk")
    {
        if (t.size() != 2 && t.size() != 3)
            throw std::invalid_argument("set-trunk <dev:idx> [native-vid]");

        auto ref = ParsePortRef(t[1]);
        unsigned native = (t.size() == 3) ? std::stoul(t[2]) : 1;
        if (native > 4094)
            throw std::invalid_argument("native vlan id out of range");

        Port *p = topo.FindPort(ref.first, ref.second);
        p->tagged = true;
        p->vlan = uint16_t(native);
    }
    else if (cmd == "arp")
    {
        if (t.size() != 3)
            throw std::invalid_argument("arp <device> <target-ip>");

        Device *d = topo.FindDevice(t[1]);
        EndDevice *e = dynamic_cast<EndDevice *>(d);
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        e->SendArpRequest(Ipv4(t[2]));
    }
    else if (cmd == "set-gateway")
    {
        if (t.size() != 3)
            throw std::invalid_argument("set-gateway <device> <gw-ip>");
        Device *d = topo.FindDevice(t[1]);
        EndDevice *e = dynamic_cast<EndDevice *>(d);
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        e->SetGateway(Ipv4(t[2]));
    }
    else if (cmd == "ping")
    {
        if (t.size() != 3 && t.size() != 4)
            throw std::invalid_argument("ping <device> <target-ip> [ttl]");
        Device *d = topo.FindDevice(t[1]);
        EndDevice *e = dynamic_cast<EndDevice *>(d);
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");

        uint8_t ttl = IpPacket::kDefaultTtl;
        if (t.size() == 4)
        {
            unsigned x = std::stoul(t[3]);
            if (x == 0 || x > 255)
                throw std::invalid_argument("ttl out of range");
            ttl = uint8_t(x);
        }
        e->SendPing(Ipv4(t[2]), 0, ttl);
    }
    else if (cmd == "set-stp")
    {
        if (t.size() != 3)
            throw std::invalid_argument("set-stp <switch> on|off");
        Switch *sw = dynamic_cast<Switch *>(topo.FindDevice(t[1]));
        if (!sw)
            throw std::invalid_argument("'" + t[1] + "' is not a switch");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("set-stp <switch> on|off");
        sw->SetStpEnabled(t[2] == "on");
    }
    else if (cmd == "set-bridge")
    {
        if (t.size() != 3)
            throw std::invalid_argument("set-bridge <switch> <priority>");
        Switch *sw = dynamic_cast<Switch *>(topo.FindDevice(t[1]));
        if (!sw)
            throw std::invalid_argument("'" + t[1] + "' is not a switch");
        unsigned prio = std::stoul(t[2]);
        if (prio > 65535)
            throw std::invalid_argument("bridge priority out of range");
        sw->SetBridgePriority(uint16_t(prio));
    }
    else if (cmd == "set-stp-mode")
    {
        if (t.size() != 3)
            throw std::invalid_argument("set-stp-mode <switch> stp|rstp");
        Switch *sw = dynamic_cast<Switch *>(topo.FindDevice(t[1]));
        if (!sw)
            throw std::invalid_argument("'" + t[1] + "' is not a switch");
        if (t[2] != "stp" && t[2] != "rstp")
            throw std::invalid_argument("set-stp-mode <switch> stp|rstp");
        sw->SetStpRapid(t[2] == "rstp");
    }
    else if (cmd == "stp-status")
    {
        if (t.size() != 2)
            throw std::invalid_argument("stp-status <switch>");
        Switch *sw = dynamic_cast<Switch *>(topo.FindDevice(t[1]));
        if (!sw)
            throw std::invalid_argument("'" + t[1] + "' is not a switch");
        std::cout << t[1] << " ";
        sw->PrintStp();
    }
    else if (cmd == "set-link")
    {
        if (t.size() != 3)
            throw std::invalid_argument("set-link <dev:idx> down|up");
        if (t[2] != "up" && t[2] != "down")
            throw std::invalid_argument("set-link <dev:idx> down|up");

        auto ref = ParsePortRef(t[1]);
        Port *p = topo.FindPort(ref.first, ref.second);
        if (!p->link)
            throw std::invalid_argument("'" + t[1] + "' has no link");
        p->link->SetUp(t[2] == "up");
    }
    else if (cmd == "stats")
    {
        if (t.size() != 2)
            throw std::invalid_argument("stats <device>");
        Device *d = topo.FindDevice(t[1]);
        std::cout << t[1] << "\n";
        for (std::size_t i = 0; i < d->portList.size(); ++i)
        {
            Port *p = d->portList[i];
            std::cout << "  p" << i << " rx=" << p->rx << " tx=" << p->tx
                      << " drop=" << p->drop << "\n";
        }
    }
    else if (cmd == "remove-device")
    {
        if (t.size() != 2)
            throw std::invalid_argument("remove-device <name>");
        topo.RemoveDevice(t[1]);
    }
    else if (cmd == "remove-port")
    {
        if (t.size() != 2)
            throw std::invalid_argument("remove-port <dev:idx>");
        auto ref = ParsePortRef(t[1]);
        topo.RemovePort(ref.first, ref.second);
    }
    else if (cmd == "disconnect")
    {
        if (t.size() != 2)
            throw std::invalid_argument("disconnect <dev:idx>");
        auto ref = ParsePortRef(t[1]);
        topo.Disconnect(ref.first, ref.second);
    }
    else if (cmd == "rename-device")
    {
        if (t.size() != 3)
            throw std::invalid_argument("rename-device <old> <new>");
        topo.RenameDevice(t[1], t[2]);
    }
    else if (cmd == "set-ip")
    {
        if (t.size() != 3)
            throw std::invalid_argument("set-ip <dev:idx> <ip>/<prefix>");
        auto ref = ParsePortRef(t[1]);
        Ipv4 ip;
        uint8_t prefix = 0;
        ParseIpPrefix(t[2], ip, prefix);
        topo.SetPortIp(ref.first, ref.second, ip, prefix);
    }
    else
    {
        throw std::invalid_argument("unknown command '" + cmd + "'");
    }
}
