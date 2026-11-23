#include "TopoCommand.hpp"
#include "Topology.hpp"
#include "Export.hpp"
#include "../device/Device.hpp"
#include "../device/EndDevice.hpp"
#include "../device/Switch.hpp"
#include "../device/Router.hpp"
#include "../device/Port.hpp"
#include "../link/Link.hpp"
#include "../engine/Clock.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/IpPacket.hpp"
#include "../core/Mac.hpp"
#include <sstream>
#include <stdexcept>
#include <utility>
#include <iostream>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <map>

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
    const char *DeviceKind(const Device *d)
    {
        if(dynamic_cast<const Router *>(d)) return "router";
        if(dynamic_cast<const Switch *>(d)) return "switch";
        return "end";
    }

    const char *ProtoName(uint8_t proto)
    {
        if(proto == IpPacket::kTcp) return "tcp";
        if(proto == IpPacket::kUdp) return "udp";
        if(proto == IpPacket::kIcmp) return "icmp";
        return "other";
    }

    const char *OspfIfName(uint8_t s)
    {
        switch(s)
        {
        case Router::OspfIfWaiting: return "Waiting";
        case Router::OspfIfDr: return "DR";
        case Router::OspfIfBdr: return "BDR";
        case Router::OspfIfDrOther: return "DROther";
        default: return "Down";
        }
    }

    const char *OspfNbrName(uint8_t s)
    {
        switch(s)
        {
        case Router::OspfNbrInit: return "Init";
        case Router::OspfNbrTwoWay: return "2-Way";
        case Router::OspfNbrExStart: return "ExStart";
        case Router::OspfNbrExchange: return "Exchange";
        case Router::OspfNbrLoading: return "Loading";
        case Router::OspfNbrFull: return "Full";
        default: return "Down";
        }
    }

    const char *PortState(const Port *p)
    {        const Switch *sw = dynamic_cast<const Switch *>(p->owner);
        if(!sw || !sw->stpEnabled) return "up";
        switch(p->stpState)
        {
        case StpPortState::Disabled:   return "disabled";
        case StpPortState::Blocking:   return "blocking";
        case StpPortState::Listening:  return "listening";
        case StpPortState::Learning:   return "learning";
        case StpPortState::Forwarding: return "forwarding";
        }
        return "up";
    }

    Mac MakeMac(std::uint32_t id)
    {
        Mac m(0x02, 0x00, 0x00, 0x00, 0x00, 0x00);
        m.bytes[2] = uint8_t((id >> 24) & 0xFF);
        m.bytes[3] = uint8_t((id >> 16) & 0xFF);
        m.bytes[4] = uint8_t((id >> 8) & 0xFF);
        m.bytes[5] = uint8_t(id & 0xFF);
        return m;
    }

    void GenerateTree(Topology &topo, unsigned depth, unsigned fanout)
    {
        if(depth == 0 || depth > 8 || fanout < 1 || fanout > 10)
            throw std::invalid_argument("generate: depth 1-8, fanout 1-10");

        long double total = 0.0L, term = 1.0L, leaves = 1.0L;
        for(unsigned i = 0; i <= depth; ++i)
        {
            total += term;
            if(i < depth) term *= fanout;
            leaves = term;
        }
        if(total > 3000.0L)
            throw std::invalid_argument("generate: topology too large");
        if(leaves > 250.0L)
            throw std::invalid_argument("generate: too many leaves for /24");

        std::uint32_t macId = 1;
        unsigned swCount = 1;
        unsigned hostCount = 0;

        topo.AddSwitch("SW1");
        std::vector<std::string> level;
        level.push_back("SW1");

        for(unsigned d = 0; d < depth; ++d)
        {
            std::vector<std::string> next;
            for(const std::string &parent : level)
            {
                for(unsigned f = 0; f < fanout; ++f)
                {
                    std::string child = "SW" + std::to_string(++swCount);
                    std::size_t pIdx = topo.FindDevice(parent)->portList.size();
                    topo.AddSwitch(child);
                    topo.AddPort(parent, MakeMac(macId++));
                    topo.AddPort(child, MakeMac(macId++));
                    topo.Connect(parent, pIdx, child, 0);
                    next.push_back(child);
                }
            }
            level.swap(next);
        }

        for(const std::string &leaf : level)
        {
            std::string host = "H" + std::to_string(++hostCount);
            topo.AddEndDevice(host);
            topo.AddPort(host, MakeMac(macId++),
                         Ipv4(10, 0, 0, uint8_t(1 + hostCount)), 24);
            std::size_t leafIdx = topo.FindDevice(leaf)->portList.size();
            topo.AddPort(leaf, MakeMac(macId++));
            topo.Connect(host, 0, leaf, leafIdx);
        }

        std::cout << "generated tree: " << swCount << " switches, "
                  << hostCount << " hosts\n";
    }

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
        if (t.size() < 3)
            throw std::invalid_argument("set-link <dev:idx> down|up|loss|dup|jitter|clear ...");

        auto ref = ParsePortRef(t[1]);
        Port *p = topo.FindPort(ref.first, ref.second);
        if (!p->link)
            throw std::invalid_argument("'" + t[1] + "' has no link");

        if (t[2] == "up" || t[2] == "down")
        {
            if (t.size() != 3)
                throw std::invalid_argument("set-link <dev:idx> down|up");
            p->link->SetUp(t[2] == "up");
        }
        else if (t[2] == "clear")
        {
            if (t.size() != 3)
                throw std::invalid_argument("set-link <dev:idx> clear");
            p->link->ClearImpair();
        }
        else if (t[2] == "loss" || t[2] == "dup" || t[2] == "jitter")
        {
            if (t.size() != 4)
                throw std::invalid_argument("set-link <dev:idx> loss|dup|jitter <value>");
            if (t[2] == "jitter")
            {
                p->link->SetJitter(uint64_t(std::stoull(t[3])));
            }
            else
            {
                double v = std::stod(t[3]);
                if (v < 0.0 || v > 100.0)
                    throw std::invalid_argument("loss/dup percent must be 0-100");
                if (t[2] == "loss") p->link->SetLoss(v);
                else p->link->SetDup(v);
            }
        }
        else
        {
            throw std::invalid_argument("set-link <dev:idx> down|up|loss|dup|jitter|clear");
        }
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
    else if (cmd == "devices")
    {
        if (t.size() != 1)
            throw std::invalid_argument("devices");
        std::cout << "devices (" << topo.devices.size() << "):\n";
        for (const auto &kv : topo.devices)
        {
            const Device *d = kv.second.get();
            std::cout << "  " << kv.first << "  " << DeviceKind(d)
                      << "  ports=" << d->portList.size() << "\n";
        }
    }
    else if (cmd == "ports")
    {
        if (t.size() != 2)
            throw std::invalid_argument("ports <device>");
        Device *d = topo.FindDevice(t[1]);
        std::cout << t[1] << " ports:\n";
        for (std::size_t i = 0; i < d->portList.size(); ++i)
        {
            Port *p = d->portList[i];
            std::cout << "  p" << i << " mac=" << p->mac.ToString()
                      << " ip=" << (p->hasIp
                            ? p->ip.ToString() + "/" + std::to_string(p->subnet.prefix)
                            : std::string("-"))
                      << " vlan=" << p->vlan << (p->tagged ? " T" : "")
                      << " stp=" << PortState(p)
                      << " rx=" << p->rx << " tx=" << p->tx
                      << " drop=" << p->drop << "\n";
        }
    }
    else if (cmd == "routes")
    {
        if (t.size() != 2)
            throw std::invalid_argument("routes <router>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        std::cout << t[1] << " routes:\n";
        for (const Route &rt : r->routeTable)
            std::cout << "  " << rt.dst.ToString() << " -> "
                      << (rt.direct ? std::string("direct") : rt.nextHop.ToString())
                      << "\n";
    }
    else if (cmd == "arp-table")
    {
        if (t.size() != 2)
            throw std::invalid_argument("arp-table <device>");
        Device *d = topo.FindDevice(t[1]);
        ArpAgent *a = nullptr;
        if (EndDevice *e = dynamic_cast<EndDevice *>(d)) a = &e->arp;
        else if (Router *r = dynamic_cast<Router *>(d)) a = &r->arp;
        if (!a)
            throw std::invalid_argument("'" + t[1] + "' has no ARP table");
        uint64_t now = d->clock ? d->clock->Now() : 0;
        std::cout << t[1] << " arp:\n";
        for (const auto &kv : a->cache)
        {
            uint64_t age = now >= kv.second.lastSeen ? now - kv.second.lastSeen : 0;
            std::cout << "  " << kv.first.ToString() << " -> "
                      << kv.second.mac.ToString() << " age=" << age << "\n";
        }
    }
    else if (cmd == "mac-table")
    {
        if (t.size() != 2)
            throw std::invalid_argument("mac-table <switch>");
        Switch *sw = dynamic_cast<Switch *>(topo.FindDevice(t[1]));
        if (!sw)
            throw std::invalid_argument("'" + t[1] + "' is not a switch");
        uint64_t now = sw->clock ? sw->clock->Now() : 0;
        std::cout << t[1] << " mac-table:\n";
        for (const auto &kv : sw->macTable)
        {
            std::size_t idx = 0;
            for (std::size_t i = 0; i < sw->portList.size(); ++i)
                if (sw->portList[i] == kv.second.port) { idx = i; break; }
            uint64_t age = now >= kv.second.lastSeen ? now - kv.second.lastSeen : 0;
            std::cout << "  vlan=" << kv.first.first << " "
                      << kv.first.second.ToString() << " -> p" << idx
                      << " age=" << age << "\n";
        }
    }
    else if (cmd == "links")
    {
        if (t.size() != 1)
            throw std::invalid_argument("links");
        std::map<const Port *, std::pair<std::string, std::size_t>> pmap;
        for (const auto &kv : topo.devices)
        {
            const Device *d = kv.second.get();
            for (std::size_t i = 0; i < d->portList.size(); ++i)
                pmap[d->portList[i]] = { kv.first, i };
        }
        std::cout << "links (" << topo.links.size() << "):\n";
        for (const auto &lp : topo.links)
        {
            Link *l = lp.get();
            auto a = pmap.find(l->A);
            auto b = pmap.find(l->B);
            if (a == pmap.end() || b == pmap.end()) continue;
            std::cout << "  " << a->second.first << ":" << a->second.second
                      << " <-> " << b->second.first << ":" << b->second.second
                      << (l->enabled ? " up" : " down")
                      << " delay=" << l->delay << "\n";
        }
    }
    else if (cmd == "traceroute")
    {
        if (t.size() != 3 && t.size() != 4)
            throw std::invalid_argument("traceroute <device> <target-ip> [max-hops]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned maxHops = 30;
        if (t.size() == 4)
        {
            maxHops = std::stoul(t[3]);
            if (maxHops == 0 || maxHops > 255)
                throw std::invalid_argument("max-hops out of range");
        }
        e->Traceroute(Ipv4(t[2]), uint8_t(maxHops));
    }
    else if (cmd == "export")
    {
        if (t.size() != 3)
            throw std::invalid_argument("export dot|svg <file>");
        std::string err;
        bool ok = false;
        if (t[1] == "dot") ok = ExportDot(topo, t[2], err);
        else if (t[1] == "svg") ok = ExportSvg(topo, t[2], err);
        else throw std::invalid_argument("export dot|svg <file>");
        if (!ok)
            throw std::runtime_error(err);
        std::cout << "exported " << t[1] << " to " << t[2] << "\n";
    }
    else if (cmd == "udp-echo")
    {
        if (t.size() != 3 && t.size() != 4)
            throw std::invalid_argument("udp-echo <device> on|off [port]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("udp-echo <device> on|off [port]");
        unsigned port = 7;
        if (t.size() == 4)
        {
            port = std::stoul(t[3]);
            if (port == 0 || port > 65535)
                throw std::invalid_argument("udp echo port out of range");
        }
        e->SetUdpEcho(t[2] == "on", uint16_t(port));
    }
    else if (cmd == "udp-send")
    {
        if (t.size() < 4)
            throw std::invalid_argument("udp-send <device> <ip> <dport> <text...>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned dport = std::stoul(t[3]);
        if (dport == 0 || dport > 65535)
            throw std::invalid_argument("udp port out of range");
        std::string text;
        for (std::size_t i = 4; i < t.size(); ++i)
        {
            if (i > 4) text += " ";
            text += t[i];
        }
        e->SendUdp(Ipv4(t[2]), uint16_t(dport), text);
    }
    else if (cmd == "map")
    {
        if (t.size() != 1)
            throw std::invalid_argument("map");
        std::map<const Port *, std::pair<std::string, std::size_t>> pmap;
        for (const auto &kv : topo.devices)
            for (std::size_t i = 0; i < kv.second->portList.size(); ++i)
                pmap[kv.second->portList[i]] = { kv.first, i };

        std::cout << "map:\n";
        for (const auto &kv : topo.devices)
        {
            const Device *d = kv.second.get();
            std::cout << "  " << kv.first << " [" << DeviceKind(d) << "] ("
                      << d->portList.size() << " ports)\n";
            for (std::size_t i = 0; i < d->portList.size(); ++i)
            {
                Port *p = d->portList[i];
                if (!p->link)
                {
                    std::cout << "    p" << i << " -- (unconnected)\n";
                    continue;
                }
                Port *o = p->link->Other(p);
                auto it = pmap.find(o);
                if (it != pmap.end())
                    std::cout << "    p" << i << " -- " << it->second.first
                              << ":" << it->second.second << " ["
                              << DeviceKind(topo.FindDevice(it->second.first))
                              << "]\n";
            }
        }
    }
    else if (cmd == "generate")
    {
        if (t.size() != 4 || t[1] != "tree")
            throw std::invalid_argument("generate tree <depth> <fanout>");
        unsigned depth = std::stoul(t[2]);
        unsigned fanout = std::stoul(t[3]);
        GenerateTree(topo, depth, fanout);
    }
    else if (cmd == "tcp-lite-echo")
    {
        if (t.size() != 3 && t.size() != 4)
            throw std::invalid_argument("tcp-lite-echo <device> on|off [port]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("tcp-lite-echo <device> on|off [port]");
        unsigned port = 0;
        if (t.size() == 4)
        {
            port = std::stoul(t[3]);
            if (port == 0 || port > 65535)
                throw std::invalid_argument("tcp echo port out of range");
        }
        if (t[2] == "on" && port == 0)
            throw std::invalid_argument("tcp-echo on requires a port");
        e->SetTcpEcho(t[2] == "on", uint16_t(port));
    }
    else if (cmd == "tcp-lite-echo-client")
    {
        if (t.size() < 5)
            throw std::invalid_argument("tcp-lite-echo-client <device> <ip> <port> <text...>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned port = std::stoul(t[3]);
        if (port == 0 || port > 65535)
            throw std::invalid_argument("tcp port out of range");
        std::string text;
        for (std::size_t i = 4; i < t.size(); ++i)
        {
            if (i > 4) text += " ";
            text += t[i];
        }
        e->TcpEchoClient(Ipv4(t[2]), uint16_t(port), text);
    }
    else if (cmd == "tcp-listen")
    {
        if (t.size() != 3 && t.size() != 4)
            throw std::invalid_argument("tcp-listen <device> on|off [port]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("tcp-listen <device> on|off [port]");
        unsigned port = 0;
        if (t.size() == 4)
        {
            port = std::stoul(t[3]);
            if (port == 0 || port > 65535)
                throw std::invalid_argument("tcp listen port out of range");
        }
        if (t[2] == "on" && port == 0)
            throw std::invalid_argument("tcp-listen on requires a port");
        e->SetTcpListen(t[2] == "on", uint16_t(port));
    }
    else if (cmd == "tcp-connect")
    {
        if (t.size() < 4)
            throw std::invalid_argument("tcp-connect <device> <ip> <port> [text...]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned port = std::stoul(t[3]);
        if (port == 0 || port > 65535)
            throw std::invalid_argument("tcp port out of range");
        std::string text;
        for (std::size_t i = 4; i < t.size(); ++i)
        {
            if (i > 4) text += " ";
            text += t[i];
        }
        e->TcpConnect(Ipv4(t[2]), uint16_t(port), text);
    }
    else if (cmd == "dhcp-server")
    {
        if (t.size() != 3 && t.size() != 7 && t.size() != 8)
            throw std::invalid_argument("dhcp-server <device> on <start> <end> <prefix> <gateway> [dns] | off");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] == "off")
        {
            if (t.size() != 3)
                throw std::invalid_argument("dhcp-server <device> off");
            e->SetDhcpServer(false, Ipv4::Any(), Ipv4::Any(), 0, Ipv4::Any(), Ipv4::Any());
            return;
        }
        if (t[2] != "on" || t.size() < 7)
            throw std::invalid_argument("dhcp-server <device> on <start> <end> <prefix> <gateway> [dns]");

        Ipv4 start(t[3]);
        Ipv4 end(t[4]);
        unsigned prefix = std::stoul(t[5]);
        if (prefix > 32)
            throw std::invalid_argument("dhcp prefix out of range");
        Ipv4 gw(t[6]);
        Ipv4 dns = (t.size() == 8) ? Ipv4(t[7]) : Ipv4::Any();
        if (end.value < start.value)
            throw std::invalid_argument("dhcp pool end is before start");
        e->SetDhcpServer(true, start, end, uint8_t(prefix), gw, dns);
    }
    else if (cmd == "dhcp-client")
    {
        if (t.size() != 2 && t.size() != 3)
            throw std::invalid_argument("dhcp-client <device> [port-index]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        std::size_t idx = 0;
        if (t.size() == 3)
            idx = std::stoul(t[2]);
        if (idx >= e->portList.size())
            throw std::invalid_argument("dhcp-client port index out of range");
        e->StartDhcpClient(e->portList[idx]);
    }
    else if (cmd == "dns-server")
    {
        if (t.size() != 3)
            throw std::invalid_argument("dns-server <device> on|off");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("dns-server <device> on|off");
        e->SetDnsServer(t[2] == "on");
    }
    else if (cmd == "dns-record")
    {
        if (t.size() != 4)
            throw std::invalid_argument("dns-record <device> <name> <ip>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        e->AddDnsRecord(t[2], Ipv4(t[3]));
    }
    else if (cmd == "dns-query")
    {
        if (t.size() != 3 && t.size() != 4)
            throw std::invalid_argument("dns-query <device> [server-ip] <name>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t.size() == 4)
            e->DnsQuery(Ipv4(t[2]), t[3]);
        else
        {
            if (!e->hasDnsServer)
                throw std::invalid_argument("dns-query: no DNS server configured (use dhcp or pass one)");
            e->DnsQuery(e->dnsServerIp, t[2]);
        }
    }
    else if (cmd == "nat")
    {
        if (t.size() != 3 && t.size() != 5)
            throw std::invalid_argument("nat <router> on <inside-dev:idx> <outside-dev:idx> | off");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");

        if (t[2] == "off")
        {
            if (t.size() != 3)
                throw std::invalid_argument("nat <router> off");
            r->SetNat(false, nullptr, nullptr);
            return;
        }
        if (t[2] != "on" || t.size() != 5)
            throw std::invalid_argument("nat <router> on <inside-dev:idx> <outside-dev:idx>");

        auto in = ParsePortRef(t[3]);
        auto out = ParsePortRef(t[4]);
        if (in.first != t[1] || out.first != t[1])
            throw std::invalid_argument("nat ports must belong to the router");
        if (in.second >= r->portList.size() || out.second >= r->portList.size())
            throw std::invalid_argument("nat port index out of range");

        Port *pi = r->portList[in.second];
        Port *po = r->portList[out.second];
        if (pi == po)
            throw std::invalid_argument("nat inside and outside ports must differ");
        if (!pi->hasIp || !po->hasIp)
            throw std::invalid_argument("nat ports need an IP address");

        r->SetNat(true, pi, po);
    }
    else if (cmd == "nat-port")
    {
        if (t.size() != 6)
            throw std::invalid_argument("nat-port <router> tcp|udp <public-port> <inside-ip> <inside-port>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");

        uint8_t proto = 0;
        if (t[2] == "tcp") proto = IpPacket::kTcp;
        else if (t[2] == "udp") proto = IpPacket::kUdp;
        else throw std::invalid_argument("nat-port protocol must be tcp or udp");

        unsigned publicPort = std::stoul(t[3]);
        if (publicPort == 0 || publicPort > 65535)
            throw std::invalid_argument("nat public port out of range");
        unsigned insidePort = std::stoul(t[5]);
        if (insidePort == 0 || insidePort > 65535)
            throw std::invalid_argument("nat inside port out of range");

        r->AddNatForward(proto, uint16_t(publicPort), Ipv4(t[4]), uint16_t(insidePort));
    }
    else if (cmd == "nat-table")
    {
        if (t.size() != 2)
            throw std::invalid_argument("nat-table <router>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");

        std::cout << "nat " << t[1] << ": "
                  << (r->natEnabled ? "on" : "off");
        if (r->natEnabled)
            std::cout << " inside=" << r->natInside->ip.ToString()
                      << " outside=" << r->natOutside->ip.ToString();
        std::cout << "\n";

        for (const auto &tr : r->natTable)
            std::cout << "  " << ProtoName(tr.proto) << " "
                      << tr.insideIp.ToString() << ":" << tr.insidePort
                      << " -> " << tr.outsideIp.ToString() << ":" << tr.outsidePort
                      << "\n";
        for (const auto &f : r->natForwards)
            std::cout << "  forward " << ProtoName(f.proto) << " "
                      << f.publicPort << " -> "
                      << f.insideIp.ToString() << ":" << f.insidePort << "\n";
    }
    else if (cmd == "rip")
    {
        if (t.size() != 3)
            throw std::invalid_argument("rip <router> on|off");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("rip <router> on|off");
        r->SetRip(t[2] == "on");
    }
    else if (cmd == "rip-status")
    {
        if (t.size() != 2)
            throw std::invalid_argument("rip-status <router>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");

        std::cout << "rip " << t[1] << ": "
                  << (r->ripEnabled ? "on" : "off") << "\n";
        for (const Route &rt : r->routeTable)
        {
            if (rt.direct)
                std::cout << "  connected " << rt.dst.ToString() << "\n";
            else if (rt.dynamic)
                std::cout << "  rip " << rt.dst.ToString() << " via "
                          << rt.nextHop.ToString() << " metric "
                          << rt.metric << "\n";
            else
                std::cout << "  static " << rt.dst.ToString() << " via "
                          << rt.nextHop.ToString() << "\n";
        }
    }
    else if (cmd == "ospf")
    {
        if (t.size() != 3)
            throw std::invalid_argument("ospf <router> on|off");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("ospf <router> on|off");
        r->SetOspf(t[2] == "on");
    }
    else if (cmd == "ospf-status")
    {
        if (t.size() != 2)
            throw std::invalid_argument("ospf-status <router>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");

        std::cout << "ospf " << t[1] << ": "
                  << (r->ospfEnabled ? "on" : "off");
        if (r->ospfEnabled)
            std::cout << " id=" << Ipv4(r->ospfRouterId).ToString()
                      << " area=" << r->ospfAreaId.ToString()
                      << " lsdb=" << r->ospfLsdb.size();
        std::cout << "\n";

        for (const auto &ifc : r->ospfIfaces)
        {
            std::cout << "  iface " << ifc.port->ip.ToString()
                      << " state=" << OspfIfName(ifc.state)
                      << " dr=" << ifc.dr.ToString()
                      << " bdr=" << ifc.bdr.ToString() << "\n";
            for (const auto &kv : ifc.neighbors)
                std::cout << "    neighbor " << Ipv4(kv.first).ToString()
                          << " state=" << OspfNbrName(kv.second.state)
                          << " pri=" << int(kv.second.priority) << "\n";
        }

        for (const Route &rt : r->routeTable)
            if (rt.ospf)
                std::cout << "  route " << rt.dst.ToString() << " via "
                          << rt.nextHop.ToString() << " metric "
                          << rt.metric << "\n";
    }
    else if (cmd == "ospf-auth")
    {
        if (t.size() != 3 && t.size() != 4)
            throw std::invalid_argument("ospf-auth <router> none|simple <password>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        if (t[2] == "none")
        {
            r->ospfAuthType = OspfPacket::AuthNone;
            for (std::size_t i = 0; i < 8; ++i)
                r->ospfPassword[i] = 0;
            return;
        }
        if (t[2] != "simple" || t.size() != 4)
            throw std::invalid_argument("ospf-auth <router> none|simple <password>");
        if (t[3].size() > 8)
            throw std::invalid_argument("ospf simple password must be at most 8 bytes");
        r->ospfAuthType = OspfPacket::AuthSimple;
        for (std::size_t i = 0; i < 8; ++i)
            r->ospfPassword[i] = i < t[3].size() ? uint8_t(t[3][i]) : 0;
    }
    else if (cmd == "acl")
    {
        if (t.size() != 7)
            throw std::invalid_argument("acl <router> in|out allow|deny <src/p> <dst/p> <proto|any>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        bool inbound;
        if (t[2] == "in") inbound = true;
        else if (t[2] == "out") inbound = false;
        else throw std::invalid_argument("acl direction must be in or out");
        bool permit;
        if (t[3] == "allow") permit = true;
        else if (t[3] == "deny") permit = false;
        else throw std::invalid_argument("acl action must be allow or deny");

        Ipv4Subnet src(t[4]);
        Ipv4Subnet dst(t[5]);
        uint8_t proto = 0;
        if (t[6] == "any") proto = 0;
        else if (t[6] == "icmp") proto = IpPacket::kIcmp;
        else if (t[6] == "tcp") proto = IpPacket::kTcp;
        else if (t[6] == "udp") proto = IpPacket::kUdp;
        else throw std::invalid_argument("acl proto must be any, icmp, tcp, or udp");

        r->AddAcl(inbound, permit, src, dst, proto);
        std::cout << "acl added\n";
    }
    else
    {
        throw std::invalid_argument("unknown command '" + cmd + "'");
    }
}
