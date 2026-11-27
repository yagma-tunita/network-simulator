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
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <cctype>

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

    const char *TcpStateName(int s)
    {
        switch(s)
        {
        case TcpConnection::Listening: return "Listening";
        case TcpConnection::SynSent: return "SynSent";
        case TcpConnection::SynRcvd: return "SynRcvd";
        case TcpConnection::Established: return "Established";
        case TcpConnection::FinWait1: return "FinWait1";
        case TcpConnection::FinWait2: return "FinWait2";
        case TcpConnection::CloseWait: return "CloseWait";
        case TcpConnection::Closing: return "Closing";
        case TcpConnection::LastAck: return "LastAck";
        case TcpConnection::TimeWait: return "TimeWait";
        default: return "Closed";
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
    else if (cmd == "add-route6")
    {
        if (t.size() != 4)
            throw std::invalid_argument("add-route6 <router> <dst6/prefix> <next-hop-ip6>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        Ipv6Subnet dst;
        Ipv6 nextHop;
        if (!Ipv6Subnet::TryParse(t[2], dst))
            throw std::invalid_argument("invalid IPv6 destination");
        if (!Ipv6::TryParse(t[3], nextHop))
            throw std::invalid_argument("invalid IPv6 next hop");
        r->AddRoute6(dst, nextHop, false);
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
    else if (cmd == "set-gateway6")
    {
        if (t.size() != 3)
            throw std::invalid_argument("set-gateway6 <device> <gw-ipv6>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        Ipv6 gw;
        if (!Ipv6::TryParse(t[2], gw))
            throw std::invalid_argument("invalid IPv6 gateway");
        e->SetGateway6(gw);
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
    else if (cmd == "ping6")
    {
        if (t.size() != 3)
            throw std::invalid_argument("ping6 <device> <ipv6>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        Ipv6 target;
        if (!Ipv6::TryParse(t[2], target))
            throw std::invalid_argument("invalid IPv6 address");
        e->Ping6(target);
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
    else if (cmd == "span")
    {
        if (t.size() == 3 && t[2] == "off")
        {
            Switch *sw = dynamic_cast<Switch *>(topo.FindDevice(t[1]));
            if (!sw)
                throw std::invalid_argument("'" + t[1] + "' is not a switch");
            sw->SetSpan(nullptr, nullptr);
            return;
        }
        if (t.size() != 4)
            throw std::invalid_argument("span <switch> <src-dev:idx> <dst-dev:idx> | off");
        Switch *sw = dynamic_cast<Switch *>(topo.FindDevice(t[1]));
        if (!sw)
            throw std::invalid_argument("'" + t[1] + "' is not a switch");
        auto src = ParsePortRef(t[2]);
        auto dst = ParsePortRef(t[3]);
        if (src.first != t[1] || dst.first != t[1])
            throw std::invalid_argument("span ports must belong to the switch");
        if (src.second >= sw->portList.size() ||
            dst.second >= sw->portList.size())
            throw std::invalid_argument("span port index out of range");
        if (src.second == dst.second)
            throw std::invalid_argument("span source and destination must differ");
        sw->SetSpan(sw->portList[src.second], sw->portList[dst.second]);
        std::cout << "span configured\n";
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
            throw std::invalid_argument("set-link <dev:idx> down|up|loss|dup|jitter|mtu|clear ...");

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
        else if (t[2] == "loss" || t[2] == "dup" || t[2] == "jitter" ||
                 t[2] == "mtu")
        {
            if (t.size() != 4)
                throw std::invalid_argument("set-link <dev:idx> loss|dup|jitter|mtu <value>");
            if (t[2] == "mtu")
            {
                unsigned mtu = std::stoul(t[3]);
                if (mtu < 576 || mtu > 1500)
                    throw std::invalid_argument("link mtu must be 576..1500");
                p->link->SetMtu(uint16_t(mtu));
                return;
            }
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
            throw std::invalid_argument("set-link <dev:idx> down|up|loss|dup|jitter|mtu|clear");
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
    else if (cmd == "drop-stats")
    {
        if (t.size() != 2)
            throw std::invalid_argument("drop-stats <device>");
        Device *d = topo.FindDevice(t[1]);
        if (!d)
            throw std::invalid_argument("unknown device '" + t[1] + "'");
        std::cout << t[1] << "\n";
        for (std::size_t i = 0; i < d->portList.size(); ++i)
        {
            Port *p = d->portList[i];
            std::cout << "  p" << i << " total=" << p->drop;
            for (std::size_t r = 1; r < DropReasonCount; ++r)
            {
                if (p->dropByReason[r] == 0)
                    continue;
                std::cout << " " << DropReasonName(static_cast<DropReason>(r))
                          << "=" << p->dropByReason[r];
            }
            std::cout << "\n";
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
    else if (cmd == "set-ip6")
    {
        if (t.size() != 3)
            throw std::invalid_argument("set-ip6 <dev:idx> <ipv6>");
        auto ref = ParsePortRef(t[1]);
        Port *p = topo.FindPort(ref.first, ref.second);
        if (!p)
            throw std::invalid_argument("'" + t[1] + "' is not a port");
        std::string text = t[2];
        std::size_t slash = text.find('/');
        Ipv6 ip;
        unsigned prefix = 64;
        if (slash == std::string::npos)
        {
            if (!Ipv6::TryParse(text, ip))
                throw std::invalid_argument("invalid IPv6 address");
        }
        else
        {
            if (!Ipv6::TryParse(text.substr(0, slash), ip))
                throw std::invalid_argument("invalid IPv6 address");
            std::string ps = text.substr(slash + 1);
            if (ps.empty() || ps.size() > 3)
                throw std::invalid_argument("invalid IPv6 prefix");
            prefix = 0;
            for (char c : ps)
            {
                if (c < '0' || c > '9')
                    throw std::invalid_argument("invalid IPv6 prefix");
                prefix = prefix * 10 + unsigned(c - '0');
            }
            if (prefix > 128)
                throw std::invalid_argument("invalid IPv6 prefix");
        }
        p->hasIp6 = true;
        p->ip6 = ip;
        p->prefix6 = uint8_t(prefix);
        Router *r = dynamic_cast<Router *>(topo.FindDevice(ref.first));
        if (r)
            r->RebuildConnected6();
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
                      << " ip6=" << (p->hasIp6
                            ? p->ip6.ToString() + "/" + std::to_string(p->prefix6)
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
    else if (cmd == "routes6")
    {
        if (t.size() != 2)
            throw std::invalid_argument("routes6 <router>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        std::cout << t[1] << " routes6:\n";
        for (const Ipv6Route &rt : r->route6)
            std::cout << "  " << rt.dst.ToString() << " -> "
                      << (rt.direct ? std::string("direct") : rt.nextHop.ToString())
                      << "\n";
    }
    else if (cmd == "nd6-table")
    {
        if (t.size() != 2)
            throw std::invalid_argument("nd6-table <device>");
        Device *d = topo.FindDevice(t[1]);
        if (!d)
            throw std::invalid_argument("unknown device '" + t[1] + "'");
        std::cout << t[1] << " nd6:\n";
        EndDevice *e = dynamic_cast<EndDevice *>(d);
        if (e)
        {
            for (const auto &kv : e->ndCache)
                std::cout << "  " << kv.first.ToString() << " -> "
                          << kv.second.ToString() << "\n";
        }
        else
        {
            Router *r = dynamic_cast<Router *>(d);
            if (r)
                for (const auto &kv : r->nd6Cache)
                    std::cout << "  " << kv.first.ToString() << " -> "
                              << kv.second.ToString() << "\n";
        }
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
        std::vector<std::pair<uint16_t, Mac>> keys;
        keys.reserve(sw->macTable.size());
        for (const auto &kv : sw->macTable)
            keys.push_back(kv.first);
        std::sort(keys.begin(), keys.end(),
                  [](const std::pair<uint16_t, Mac> &a,
                     const std::pair<uint16_t, Mac> &b)
                  {
                      if (a.first != b.first) return a.first < b.first;
                      return a.second < b.second;
                  });
        for (const auto &key : keys)
        {
            const auto entry = sw->macTable.find(key);
            if (entry == sw->macTable.end())
                continue;
            std::size_t idx = 0;
            for (std::size_t i = 0; i < sw->portList.size(); ++i)
                if (sw->portList[i] == entry->second.port) { idx = i; break; }
            uint64_t age = now >= entry->second.lastSeen ? now - entry->second.lastSeen : 0;
            std::cout << "  vlan=" << key.first << " "
                      << key.second.ToString() << " -> p" << idx
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
    else if (cmd == "traceroute6")
    {
        if (t.size() != 3 && t.size() != 4)
            throw std::invalid_argument("traceroute6 <device> <ipv6> [max-hops]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        Ipv6 target;
        if (!Ipv6::TryParse(t[2], target))
            throw std::invalid_argument("invalid IPv6 address");
        unsigned maxHops = 30;
        if (t.size() == 4)
        {
            maxHops = std::stoul(t[3]);
            if (maxHops == 0 || maxHops > 255)
                throw std::invalid_argument("max-hops out of range");
        }
        e->Traceroute6(target, uint8_t(maxHops));
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
            throw std::invalid_argument("udp-send <device> <ip> <dport> [df] <text...>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned dport = std::stoul(t[3]);
        if (dport == 0 || dport > 65535)
            throw std::invalid_argument("udp port out of range");
        bool df = t.size() > 4 && t[4] == "df";
        std::size_t first = df ? 5 : 4;
        std::string text;
        for (std::size_t i = first; i < t.size(); ++i)
        {
            if (i > first) text += " ";
            text += t[i];
        }
        e->SendUdp(Ipv4(t[2]), uint16_t(dport), text, 0, df);
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
    else if (cmd == "tcp-keepalive")
    {
        if (t.size() != 3 && t.size() != 6)
            throw std::invalid_argument("tcp-keepalive <device> on [idle interval count]|off");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("tcp-keepalive <device> on|off");
        if (t[2] == "off")
        {
            if (t.size() != 3)
                throw std::invalid_argument("tcp-keepalive <device> off");
            e->SetTcpKeepalive(false);
            return;
        }
        uint64_t idle = 300, interval = 75;
        uint8_t count = 3;
        if (t.size() == 6)
        {
            idle = std::stoull(t[3]);
            interval = std::stoull(t[4]);
            unsigned c = std::stoul(t[5]);
            if (idle == 0 || interval == 0 || c == 0 || c > 255)
                throw std::invalid_argument("tcp-keepalive parameters out of range");
            count = uint8_t(c);
        }
        e->SetTcpKeepalive(true, idle, interval, count);
    }
    else if (cmd == "tcp-backlog")
    {
        if (t.size() != 3)
            throw std::invalid_argument("tcp-backlog <device> <1-1024>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned n = std::stoul(t[2]);
        if (n < 1 || n > 1024)
            throw std::invalid_argument("tcp-backlog must be 1..1024");
        e->tcpBacklog = n;
    }
    else if (cmd == "tcp-congestion")
    {
        if (t.size() != 3)
            throw std::invalid_argument("tcp-congestion <device> reno|cubic");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] == "reno")
            e->SetTcpCongestion(TcpConnection::Reno);
        else if (t[2] == "cubic")
            e->SetTcpCongestion(TcpConnection::Cubic);
        else
            throw std::invalid_argument("tcp-congestion must be reno or cubic");
    }
    else if (cmd == "tcp-tlp")
    {
        if (t.size() != 3)
            throw std::invalid_argument("tcp-tlp <device> on|off");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("tcp-tlp <device> on|off");
        e->SetTcpTlp(t[2] == "on");
    }
    else if (cmd == "tcp-prr")
    {
        if (t.size() != 3)
            throw std::invalid_argument("tcp-prr <device> on|off");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("tcp-prr <device> on|off");
        e->SetTcpPrr(t[2] == "on");
    }
    else if (cmd == "tcp-rack")
    {
        if (t.size() != 3)
            throw std::invalid_argument("tcp-rack <device> on|off");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("tcp-rack <device> on|off");
        e->SetTcpRack(t[2] == "on");
    }
    else if (cmd == "tcp-pacing")
    {
        if (t.size() != 3)
            throw std::invalid_argument("tcp-pacing <device> on|off");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("tcp-pacing <device> on|off");
        e->SetTcpPacing(t[2] == "on");
    }
    else if (cmd == "tcp-port-range")
    {
        if (t.size() != 4)
            throw std::invalid_argument("tcp-port-range <device> <min> <max>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned minimum = std::stoul(t[2]);
        unsigned maximum = std::stoul(t[3]);
        if (minimum < 1024 || maximum > 65535 || minimum > maximum)
            throw std::invalid_argument("tcp port range must satisfy 1024 <= min <= max <= 65535");
        e->SetTcpPortRange(uint16_t(minimum), uint16_t(maximum));
    }
    else if (cmd == "tcp-status")
    {
        if (t.size() != 2)
            throw std::invalid_argument("tcp-status <device>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");

        e->CleanupTcpConns();
        std::cout << "tcp " << t[1] << ": conns=" << e->tcpConns.size()
                  << " accepted=" << e->tcpAccepted
                  << " dropped=" << e->tcpDropped
                  << " resets=" << e->tcpResetsSent
                  << " backlog=" << e->tcpBacklog
                  << " cookies=" << e->tcpCookiesAccepted
                  << "/" << e->tcpCookiesSent
                  << " keepalive=" << (e->tcpKeepalive ? "on" : "off")
                  << "\n";
        for (const TcpConnection &c : e->tcpConns)
            std::cout << "  conn " << c.localPort
                      << " -> " << c.remoteIp.ToString() << ":" << c.remotePort
                      << " state=" << TcpStateName(c.state)
                      << " rto=" << c.rto
                      << " mss=" << c.mss
                      << " pmtu=" << c.pathMtu
                      << " cwnd=" << c.cwnd
                      << " wnd=" << c.sndWnd
                      << " unacked=" << c.unacked.size()
                      << " retrans=" << c.totalRetransmits
                      << " dsack=" << c.dsacks
                      << " ecn=" << (c.ecnEnabled ? "on" : "off")
                      << " ce=" << c.ecnCePackets << "\n";
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
    else if (cmd == "tcp-send")
    {
        if (t.size() < 2)
            throw std::invalid_argument("tcp-send <device> <text...>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        std::string text;
        for (std::size_t i = 2; i < t.size(); ++i)
        {
            if (i > 2) text += " ";
            text += t[i];
        }
        e->TcpSend(text);
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
    else if (cmd == "dhcp-lease-time")
    {
        if (t.size() != 3)
            throw std::invalid_argument("dhcp-lease-time <device> <seconds>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned long sec = std::stoul(t[2]);
        if (sec == 0 || sec > 604800)
            throw std::invalid_argument("dhcp lease time must be 1..604800 seconds");
        e->SetDhcpLeaseTime(uint32_t(sec));
    }
    else if (cmd == "dhcp-release")
    {
        if (t.size() != 2)
            throw std::invalid_argument("dhcp-release <device>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        e->SendDhcpRelease();
    }
    else if (cmd == "dhcp-relay")
    {
        if (t.size() != 4)
            throw std::invalid_argument("dhcp-relay <router> <dev:idx> <server-ip>|off");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        auto ref = ParsePortRef(t[2]);
        if (ref.first != t[1] || ref.second >= r->portList.size())
            throw std::invalid_argument("dhcp-relay port must belong to the router");
        Port *p = r->portList[ref.second];
        if (t[3] == "off")
        {
            r->SetDhcpRelay(p, false, Ipv4::Any());
            return;
        }
        r->SetDhcpRelay(p, true, Ipv4(t[3]));
    }
    else if (cmd == "ecn-mark")
    {
        if (t.size() != 4)
            throw std::invalid_argument("ecn-mark <router> <dev:idx> on|off");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        auto ref = ParsePortRef(t[2]);
        if (ref.first != t[1] || ref.second >= r->portList.size())
            throw std::invalid_argument("ecn-mark port must belong to the router");
        if (t[3] != "on" && t[3] != "off")
            throw std::invalid_argument("ecn-mark <router> <dev:idx> on|off");
        r->SetEcnMark(r->portList[ref.second], t[3] == "on");
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
    else if (cmd == "dns-ttl")
    {
        if (t.size() != 3)
            throw std::invalid_argument("dns-ttl <device> <seconds>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned long sec = std::stoul(t[2]);
        if (sec > 86400)
            throw std::invalid_argument("dns ttl must be 0..86400 seconds");
        e->SetDnsTtl(uint32_t(sec));
    }
    else if (cmd == "dns-negative-ttl")
    {
        if (t.size() != 3)
            throw std::invalid_argument("dns-negative-ttl <device> <seconds>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned long sec = std::stoul(t[2]);
        if (sec > 86400)
            throw std::invalid_argument("dns negative ttl must be 0..86400 seconds");
        e->SetDnsNegativeTtl(uint32_t(sec));
    }
    else if (cmd == "dns-cache-size")
    {
        if (t.size() != 3)
            throw std::invalid_argument("dns-cache-size <device> <entries>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned long entries = std::stoul(t[2]);
        if (entries == 0 || entries > 65536)
            throw std::invalid_argument("dns cache size must be 1..65536");
        e->SetDnsCacheLimit(std::size_t(entries));
    }
    else if (cmd == "dns-ttl-bounds")
    {
        if (t.size() != 4)
            throw std::invalid_argument("dns-ttl-bounds <device> <min> <max>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned long minimum = std::stoul(t[2]);
        unsigned long maximum = std::stoul(t[3]);
        if (maximum > 86400 || minimum > maximum)
            throw std::invalid_argument("dns ttl bounds must satisfy 0 <= min <= max <= 86400");
        e->SetDnsTtlBounds(uint32_t(minimum), uint32_t(maximum));
    }
    else if (cmd == "dns-record")
    {
        if (t.size() != 4 && t.size() != 5)
            throw std::invalid_argument("dns-record <device> <name> <ip> [ttl]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        uint32_t ttl = e->dnsTtl;
        if (t.size() == 5)
        {
            unsigned long parsed = std::stoul(t[4]);
            if (parsed > 86400)
                throw std::invalid_argument("dns record ttl out of range");
            ttl = uint32_t(parsed);
        }
        e->AddDnsRecord(t[2], Ipv4(t[3]));
        e->SetDnsRrTtl(t[2], 1, ttl);
    }
    else if (cmd == "dns-aaaa")
    {
        if (t.size() != 4 && t.size() != 5)
            throw std::invalid_argument("dns-aaaa <device> <name> <ipv6> [ttl]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        Ipv6 ip;
        if (!Ipv6::TryParse(t[3], ip))
            throw std::invalid_argument("invalid IPv6 address");
        uint32_t ttl = e->dnsTtl;
        if (t.size() == 5)
        {
            unsigned long parsed = std::stoul(t[4]);
            if (parsed > 86400)
                throw std::invalid_argument("dns AAAA ttl out of range");
            ttl = uint32_t(parsed);
        }
        e->AddDnsAaaa(t[2], ip);
        e->SetDnsRrTtl(t[2], DnsMessage::kTypeAaaa, ttl);
    }
    else if (cmd == "dns-cname")
    {
        if (t.size() != 4 && t.size() != 5)
            throw std::invalid_argument("dns-cname <device> <alias> <target> [ttl]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        uint32_t ttl = e->dnsTtl;
        if (t.size() == 5)
        {
            unsigned long parsed = std::stoul(t[4]);
            if (parsed > 86400)
                throw std::invalid_argument("dns cname ttl out of range");
            ttl = uint32_t(parsed);
        }
        e->AddDnsCname(t[2], t[3]);
        e->SetDnsRrTtl(t[2], 5, ttl);
    }
    else if (cmd == "dns-mx")
    {
        if (t.size() != 5 && t.size() != 6)
            throw std::invalid_argument("dns-mx <device> <name> <preference> <exchange> [ttl]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned long pref = std::stoul(t[3]);
        if (pref > 65535)
            throw std::invalid_argument("dns MX preference out of range");
        uint32_t ttl = e->dnsTtl;
        if (t.size() == 6)
        {
            unsigned long parsed = std::stoul(t[5]);
            if (parsed > 86400)
                throw std::invalid_argument("dns MX ttl out of range");
            ttl = uint32_t(parsed);
        }
        e->AddDnsMx(t[2], uint16_t(pref), t[4]);
        e->SetDnsRrTtl(t[2], 15, ttl);
    }
    else if (cmd == "dns-zone")
    {
        if (t.size() != 3)
            throw std::invalid_argument("dns-zone <device> <zone>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        e->AddDnsZone(t[2]);
    }
    else if (cmd == "dns-secondary")
    {
        if (t.size() != 4)
            throw std::invalid_argument("dns-secondary <device> <zone> <primary-ip>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        e->AddDnsSecondary(t[2], Ipv4(t[3]));
    }
    else if (cmd == "dns-notify-target")
    {
        if (t.size() < 4)
            throw std::invalid_argument("dns-notify-target <device> <zone> <ip> [ip...]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t.size() > 11)
            throw std::invalid_argument("dns-notify-target supports at most 8 addresses");
        std::vector<Ipv4> targets;
        for (std::size_t i = 3; i < t.size(); ++i)
            targets.push_back(Ipv4(t[i]));
        e->SetDnsNotifyTargets(t[2], targets);
    }
    else if (cmd == "dns-notify")
    {
        if (t.size() != 3)
            throw std::invalid_argument("dns-notify <device> <zone>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        e->NotifyDnsZone(t[2]);
    }
    else if (cmd == "dns-ns")
    {
        if (t.size() != 4)
            throw std::invalid_argument("dns-ns <device> <owner> <nameserver>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        e->AddDnsNs(t[2], t[3]);
    }
    else if (cmd == "dns-soa")
    {
        if (t.size() != 5 && t.size() != 11)
            throw std::invalid_argument("dns-soa <device> <zone> <mname> <rname> [ttl serial refresh retry expire minimum]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        uint32_t ttl = e->dnsTtl;
        uint32_t serial = 1;
        uint32_t refresh = 3600;
        uint32_t retry = 600;
        uint32_t expire = 86400;
        uint32_t minimum = e->dnsNegativeTtl;
        if (t.size() == 11)
        {
            ttl = uint32_t(std::stoul(t[5]));
            serial = uint32_t(std::stoul(t[6]));
            refresh = uint32_t(std::stoul(t[7]));
            retry = uint32_t(std::stoul(t[8]));
            expire = uint32_t(std::stoul(t[9]));
            minimum = uint32_t(std::stoul(t[10]));
        }
        e->SetDnsSoa(t[2], t[3], t[4], ttl, serial, refresh, retry,
                     expire, minimum);
    }
    else if (cmd == "dns-query")
    {
        if (t.size() != 3 && t.size() != 4 && t.size() != 5)
            throw std::invalid_argument("dns-query <device> [server-ip] <name> [A|AAAA|NS|SOA|PTR|MX]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");

        uint16_t qtype = DnsMessage::kTypeA;
        auto parseType = [](const std::string &tok, uint16_t &out) -> bool
        {
            std::string ty;
            for(char c : tok)
                ty.push_back(char(std::toupper(static_cast<unsigned char>(c))));
            if (ty == "A" || ty == "1") { out = DnsMessage::kTypeA; return true; }
            if (ty == "NS" || ty == "2") { out = DnsMessage::kTypeNs; return true; }
            if (ty == "SOA" || ty == "6") { out = DnsMessage::kTypeSoa; return true; }
            if (ty == "PTR" || ty == "12") { out = DnsMessage::kTypePtr; return true; }
            if (ty == "MX" || ty == "15") { out = DnsMessage::kTypeMx; return true; }
            if (ty == "AAAA" || ty == "28") { out = DnsMessage::kTypeAaaa; return true; }
            return false;
        };

        std::string name;
        bool explicitServer = false;
        Ipv4 server;
        if (t.size() == 5)
        {
            if (!parseType(t[4], qtype))
                throw std::invalid_argument("dns query type must be A, AAAA, NS, SOA, PTR or MX");
            server = Ipv4(t[2]);
            name = t[3];
            explicitServer = true;
        }
        else if (t.size() == 4)
        {
            Ipv4 maybeServer;
            uint16_t maybeType = DnsMessage::kTypeA;
            if (!Ipv4::TryParse(t[2], maybeServer) && parseType(t[3], maybeType))
            {
                qtype = maybeType;
                name = t[2];
            }
            else
            {
                server = Ipv4(t[2]);
                name = t[3];
                explicitServer = true;
            }
        }
        else
            name = t[2];

        if (explicitServer)
            e->DnsQuery(server, name, qtype);
        else
        {
            if (e->dnsServers.empty())
                throw std::invalid_argument("dns-query: no resolver configured (use dns-resolver, dhcp, or pass a server)");
            e->DnsQuery(name, qtype);
        }
    }
    else if (cmd == "dns-axfr")
    {
        if (t.size() != 4)
            throw std::invalid_argument("dns-axfr <device> <server-ip> <zone>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        e->DnsAxfr(Ipv4(t[2]), t[3]);
    }
    else if (cmd == "dns-ixfr")
    {
        if (t.size() != 5)
            throw std::invalid_argument("dns-ixfr <device> <server-ip> <zone> <serial>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned long serial = std::stoul(t[4]);
        e->DnsIxfr(Ipv4(t[2]), t[3], uint32_t(serial));
    }
    else if (cmd == "dns-axfr-allow")
    {
        if (t.size() < 3)
            throw std::invalid_argument("dns-axfr-allow <device> <ip> [ip...] | any|none");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] == "any" || t[2] == "none")
        {
            if (t.size() != 3)
                throw std::invalid_argument("dns-axfr-allow <device> any|none");
            e->SetDnsAxfrAllow({}, t[2] == "any");
            return;
        }
        if (t.size() > 10)
            throw std::invalid_argument("dns-axfr-allow supports at most 8 addresses");
        std::vector<Ipv4> allow;
        for (std::size_t i = 2; i < t.size(); ++i)
            allow.push_back(Ipv4(t[i]));
        e->SetDnsAxfrAllow(allow, false);
    }
    else if (cmd == "dns-tsig")
    {
        if (t.size() != 4 && t.size() != 5)
            throw std::invalid_argument("dns-tsig <device> <key-name> <secret> [md5|sha1|sha256]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        std::string alg = (t.size() == 5) ? t[4] : "sha256";
        for(char &c : alg)
            c = char(std::tolower(static_cast<unsigned char>(c)));
        if (alg != "md5" && alg != "sha1" && alg != "sha256" &&
            alg != "hmac-md5.sig-alg.reg.int." && alg != "hmac-sha1." &&
            alg != "hmac-sha256.")
            throw std::invalid_argument("dns-tsig algorithm must be md5, sha1 or sha256");
        e->AddDnsTsig(t[2], t[3], alg);
    }
    else if (cmd == "dns-tsig-require")
    {
        if (t.size() != 3)
            throw std::invalid_argument("dns-tsig-require <device> on|off");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("dns-tsig-require <device> on|off");
        e->SetDnsTsigRequired(t[2] == "on");
    }
    else if (cmd == "dns-update-allow")
    {
        if (t.size() < 3)
            throw std::invalid_argument("dns-update-allow <device> <ip> [ip...] | any|none");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] == "any" || t[2] == "none")
        {
            if (t.size() != 3)
                throw std::invalid_argument("dns-update-allow <device> any|none");
            e->SetDnsUpdateAllow({}, t[2] == "any");
            return;
        }
        if (t.size() > 10)
            throw std::invalid_argument("dns-update-allow supports at most 8 addresses");
        std::vector<Ipv4> allow;
        for (std::size_t i = 2; i < t.size(); ++i)
            allow.push_back(Ipv4(t[i]));
        e->SetDnsUpdateAllow(allow, false);
    }
    else if (cmd == "dns-update-add")
    {
        if (t.size() != 6 && t.size() != 7)
            throw std::invalid_argument("dns-update-add <device> <server-ip> <zone> <name> <ip> [ttl]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        uint32_t ttl = 60;
        if (t.size() == 7)
        {
            unsigned long parsed = std::stoul(t[6]);
            if (parsed > 86400)
                throw std::invalid_argument("dns update ttl out of range");
            ttl = uint32_t(parsed);
        }
        e->DnsUpdateAdd(Ipv4(t[2]), t[3], t[4], Ipv4(t[5]), ttl);
    }
    else if (cmd == "dns-update-del")
    {
        if (t.size() != 5 && t.size() != 6)
            throw std::invalid_argument("dns-update-del <device> <server-ip> <zone> <name> [A|ANY]");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        uint16_t type = DnsMessage::kTypeA;
        if (t.size() == 6)
        {
            std::string ty;
            for(char c : t[5])
                ty.push_back(char(std::toupper(static_cast<unsigned char>(c))));
            if (ty == "A")
                type = DnsMessage::kTypeA;
            else if (ty == "ANY")
                type = 255;
            else
                throw std::invalid_argument("dns-update-del type must be A or ANY");
        }
        e->DnsUpdateDelete(Ipv4(t[2]), t[3], t[4], type);
    }
    else if (cmd == "dns-update-check")
    {
        if (t.size() != 6)
            throw std::invalid_argument("dns-update-check <device> <server-ip> <zone> <name> <ip>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        e->DnsUpdateCheck(Ipv4(t[2]), t[3], t[4], Ipv4(t[5]));
    }
    else if (cmd == "dns-resolver")
    {
        if (t.size() < 3)
            throw std::invalid_argument("dns-resolver <device> <ip> [ip...] | off");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        if (t[2] == "off")
        {
            if (t.size() != 3)
                throw std::invalid_argument("dns-resolver <device> off");
            e->SetDnsResolvers({});
            return;
        }
        if (t.size() > 10)
            throw std::invalid_argument("dns-resolver supports at most 8 servers");
        std::vector<Ipv4> servers;
        for (std::size_t i = 2; i < t.size(); ++i)
            servers.push_back(Ipv4(t[i]));
        e->SetDnsResolvers(servers);
    }
    else if (cmd == "dns-retry")
    {
        if (t.size() != 4)
            throw std::invalid_argument("dns-retry <device> <timeout> <attempts>");
        EndDevice *e = dynamic_cast<EndDevice *>(topo.FindDevice(t[1]));
        if (!e)
            throw std::invalid_argument("'" + t[1] + "' is not an end device");
        unsigned long timeout = std::stoul(t[2]);
        unsigned long attempts = std::stoul(t[3]);
        if (timeout == 0 || timeout > 10000)
            throw std::invalid_argument("dns retry timeout must be 1..10000");
        if (attempts == 0 || attempts > 10)
            throw std::invalid_argument("dns retry attempts must be 1..10");
        e->SetDnsRetry(uint32_t(timeout), uint8_t(attempts));
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
    else if (cmd == "ospf-router-id")
    {
        if (t.size() != 3)
            throw std::invalid_argument("ospf-router-id <router> <id>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        Ipv4 id(t[2]);
        if (id.value == 0)
            throw std::invalid_argument("ospf router-id must be nonzero");
        r->ospfRouterIdCfg = id.value;
        if (r->ospfEnabled)
            r->SetOspf(true);
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
        {
            std::map<uint32_t, bool> areas;
            std::size_t lsdb = 0;
            std::size_t neighbors = 0;
            std::size_t extRoutes = 0;
            for (const auto &ifc : r->ospfIfaces)
            {
                areas[ifc.area.value] = true;
                neighbors += ifc.neighbors.size();
            }
            for (const auto &kv : r->ospfLsdb)
            {
                areas[kv.first] = true;
                lsdb += kv.second.size();
            }
            for (const Route &rt : r->routeTable)
                if (rt.external)
                    ++extRoutes;
            std::cout << " id=" << Ipv4(r->ospfRouterId).ToString()
                      << " areas=" << areas.size()
                      << " neighbors=" << neighbors
                      << " lsdb=" << lsdb
                      << " external=" << r->ospfExternalLsdb.size()
                      << " extroutes=" << extRoutes;
        }
        std::cout << "\n";

        for (const auto &ifc : r->ospfIfaces)
        {
            std::cout << "  iface ";
            if (ifc.port)
                std::cout << ifc.port->ip.ToString();
            else
                std::cout << "-";
            std::cout << " area=" << ifc.area.ToString()
                      << " state=" << OspfIfName(ifc.state)
                      << " cost=" << ifc.cost
                      << " passive=" << (ifc.passive ? "on" : "off")
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
        if (t.size() < 3 || t.size() > 5)
            throw std::invalid_argument("ospf-auth <router> none|simple <password>|md5|sha1|sha256 <key-id> <key>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        if (t[2] == "none")
        {
            r->ospfAuthType = OspfPacket::AuthNone;
            for (std::size_t i = 0; i < 8; ++i)
                r->ospfPassword[i] = 0;
            r->ospfKey.clear();
            r->ospfDigestAlg = 0;
            return;
        }
        if (t[2] == "md5" || t[2] == "sha1" || t[2] == "sha256")
        {
            if (t.size() != 5)
                throw std::invalid_argument("ospf-auth <router> md5|sha1|sha256 <key-id> <key>");
            unsigned id = std::stoul(t[3]);
            if (id == 0 || id > 255)
                throw std::invalid_argument("ospf crypto key id must be 1..255");
            uint8_t alg = 0;
            if (t[2] == "sha1") alg = 1;
            else if (t[2] == "sha256") alg = 2;
            if (alg == 0 && t[4].size() != 16)
                throw std::invalid_argument("ospf MD5 key must be exactly 16 bytes");
            if (alg != 0 && (t[4].empty() || t[4].size() > 64))
                throw std::invalid_argument("ospf SHA key must be 1..64 bytes");
            r->ospfAuthType = OspfPacket::AuthMd5;
            r->ospfDigestAlg = alg;
            r->ospfKeyId = uint8_t(id);
            r->ospfKey = t[4];
            r->ospfCryptoSeq = 0;
            return;
        }
        if (t[2] != "simple" || t.size() != 4)
            throw std::invalid_argument("ospf-auth <router> none|simple <password>|md5|sha1|sha256 <key-id> <key>");
        if (t[3].size() > 8)
            throw std::invalid_argument("ospf simple password must be at most 8 bytes");
        r->ospfAuthType = OspfPacket::AuthSimple;
        r->ospfDigestAlg = 0;
        for (std::size_t i = 0; i < 8; ++i)
            r->ospfPassword[i] = i < t[3].size() ? uint8_t(t[3][i]) : 0;
    }
    else if (cmd == "ospf-area")
    {
        if (t.size() != 4)
            throw std::invalid_argument("ospf-area <router> <dev:idx> <area-id>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        auto ref = ParsePortRef(t[2]);
        if (ref.first != t[1] || ref.second >= r->portList.size())
            throw std::invalid_argument("ospf-area port must belong to the router");
        Ipv4 area(t[3]);
        Port *p = r->portList[ref.second];
        r->ospfAreaCfg[p] = area;
        for (auto &ifc : r->ospfIfaces)
        {
            if (ifc.port != p)
                continue;
            ifc.area = area;
            ifc.neighbors.clear();
            ifc.state = Router::OspfIfWaiting;
            ifc.waitUntil = 0;
            ifc.dr = Ipv4::Any();
            ifc.bdr = Ipv4::Any();
            ifc.drIp = Ipv4::Any();
            ifc.bdrIp = Ipv4::Any();
        }
    }
    else if (cmd == "ospf-area-type")
    {
        if (t.size() != 4)
            throw std::invalid_argument("ospf-area-type <router> <area-id> stub|nssa|normal");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        Ipv4 area(t[2]);
        if (t[3] != "stub" && t[3] != "nssa" && t[3] != "normal")
            throw std::invalid_argument("ospf-area-type <router> <area-id> stub|nssa|normal");
        r->ospfStubAreas[area.value] = (t[3] == "stub");
        r->ospfNssaAreas[area.value] = (t[3] == "nssa");
    }
    else if (cmd == "ospf-summary")
    {
        if (t.size() != 4 && t.size() != 5)
            throw std::invalid_argument("ospf-summary <router> <area-id> <prefix> [not-advertise] | clear");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        Ipv4 area(t[2]);
        if (t[3] == "clear")
        {
            if (t.size() != 4)
                throw std::invalid_argument("ospf-summary <router> <area-id> clear");
            r->ClearOspfSummaries(area.value);
            return;
        }
        Ipv4Subnet dst(t[3]);
        bool notAdvertise = false;
        if (t.size() == 5)
        {
            if (t[4] != "not-advertise")
                throw std::invalid_argument("ospf-summary option must be not-advertise");
            notAdvertise = true;
        }
        r->AddOspfSummary(area.value, dst, notAdvertise);
    }
    else if (cmd == "ospf-external")
    {
        if (t.size() != 3 && t.size() != 4)
            throw std::invalid_argument("ospf-external <router> <ip/prefix> [metric]");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        if (t.size() == 3 && t[2] == "clear")
        {
            r->ospfExternals.clear();
            return;
        }
        Ipv4Subnet dst(t[2]);
        unsigned metric = 20;
        if (t.size() == 4)
            metric = std::stoul(t[3]);
        if (metric == 0 || metric > 0xFFFFFFu)
            throw std::invalid_argument("ospf external metric out of range");
        r->AddOspfExternal(dst, metric);
    }
    else if (cmd == "ospf-default-originate")
    {
        if (t.size() < 3 || t.size() > 5)
            throw std::invalid_argument("ospf-default-originate <router> on|off [metric] [type1|type2]");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        bool on;
        if (t[2] == "on") on = true;
        else if (t[2] == "off") on = false;
        else throw std::invalid_argument("ospf-default-originate state must be on or off");
        if (!on && t.size() != 3)
            throw std::invalid_argument("ospf-default-originate <router> off");
        unsigned metric = 20;
        bool type2 = true;
        if (t.size() >= 4)
        {
            metric = std::stoul(t[3]);
            if (metric == 0 || metric > 0xFFFFFFu)
                throw std::invalid_argument("ospf default metric out of range");
        }
        if (t.size() == 5)
        {
            if (t[4] == "type2") type2 = true;
            else if (t[4] == "type1") type2 = false;
            else throw std::invalid_argument("ospf default type must be type1 or type2");
        }
        r->SetOspfDefaultOriginate(on, metric, type2);
    }
    else if (cmd == "ospf-redistribute")
    {
        if (t.size() < 3 || t.size() > 5)
            throw std::invalid_argument("ospf-redistribute <router> connected|static|off [metric] [type1|type2]");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        bool connected = r->ospfRedistConnected;
        bool isStatic = r->ospfRedistStatic;
        if (t[2] == "connected") connected = true;
        else if (t[2] == "static") isStatic = true;
        else if (t[2] == "off") { connected = false; isStatic = false; }
        else throw std::invalid_argument("ospf-redistribute source must be connected, static or off");
        unsigned metric = 20;
        bool type2 = true;
        if (t.size() >= 4)
        {
            metric = std::stoul(t[3]);
            if (metric == 0 || metric > 0xFFFFFFu)
                throw std::invalid_argument("ospf redistribute metric out of range");
        }
        if (t.size() == 5)
        {
            if (t[4] == "type2") type2 = true;
            else if (t[4] == "type1") type2 = false;
            else throw std::invalid_argument("ospf redistribute type must be type1 or type2");
        }
        r->SetOspfRedistribute(connected, isStatic, metric, type2);
    }
    else if (cmd == "ospf-cost")
    {
        if (t.size() != 4)
            throw std::invalid_argument("ospf-cost <router> <dev:idx> <1-65535>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        auto ref = ParsePortRef(t[2]);
        if (ref.first != t[1] || ref.second >= r->portList.size())
            throw std::invalid_argument("ospf-cost port must belong to the router");
        unsigned cost = std::stoul(t[3]);
        if (cost == 0 || cost > 65535)
            throw std::invalid_argument("ospf cost must be 1..65535");
        Port *p = r->portList[ref.second];
        r->ospfCostCfg[p] = uint16_t(cost);
        for (auto &ifc : r->ospfIfaces)
            if (ifc.port == p)
                ifc.cost = uint16_t(cost);
    }
    else if (cmd == "ospf-passive")
    {
        if (t.size() != 4)
            throw std::invalid_argument("ospf-passive <router> <dev:idx> on|off");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        auto ref = ParsePortRef(t[2]);
        if (ref.first != t[1] || ref.second >= r->portList.size())
            throw std::invalid_argument("ospf-passive port must belong to the router");
        if (t[3] != "on" && t[3] != "off")
            throw std::invalid_argument("ospf-passive <router> <dev:idx> on|off");
        bool on = t[3] == "on";
        Port *p = r->portList[ref.second];
        r->ospfPassiveCfg[p] = on;
        for (auto &ifc : r->ospfIfaces)
        {
            if (ifc.port != p)
                continue;
            ifc.passive = on;
            if (on)
            {
                ifc.neighbors.clear();
                ifc.state = Router::OspfIfDrOther;
                ifc.dr = Ipv4::Any();
                ifc.bdr = Ipv4::Any();
                ifc.drIp = Ipv4::Any();
                ifc.bdrIp = Ipv4::Any();
            }
            else
            {
                ifc.state = Router::OspfIfWaiting;
                ifc.waitUntil = 0;
            }
        }
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
    else if (cmd == "acl6")
    {
        if (t.size() != 7)
            throw std::invalid_argument("acl6 <router> in|out allow|deny <src6/p> <dst6/p> <proto|any>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        bool inbound;
        if (t[2] == "in") inbound = true;
        else if (t[2] == "out") inbound = false;
        else throw std::invalid_argument("acl6 direction must be in or out");
        bool permit;
        if (t[3] == "allow") permit = true;
        else if (t[3] == "deny") permit = false;
        else throw std::invalid_argument("acl6 action must be allow or deny");

        Ipv6Subnet src;
        Ipv6Subnet dst;
        if (!Ipv6Subnet::TryParse(t[4], src))
            throw std::invalid_argument("invalid IPv6 source prefix");
        if (!Ipv6Subnet::TryParse(t[5], dst))
            throw std::invalid_argument("invalid IPv6 destination prefix");
        uint8_t proto = 0;
        if (t[6] == "any") proto = 0;
        else if (t[6] == "icmp" || t[6] == "icmpv6")
            proto = Icmpv6Message::kNextHeader;
        else if (t[6] == "tcp") proto = 6;
        else if (t[6] == "udp") proto = 17;
        else throw std::invalid_argument("acl6 proto must be any, icmp/icmpv6, tcp, or udp");

        r->AddAcl6(inbound, permit, src, dst, proto);
        std::cout << "acl6 added\n";
    }
    else if (cmd == "bgp")
    {
        if (t.size() != 3)
            throw std::invalid_argument("bgp <router> on|off");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        if (t[2] != "on" && t[2] != "off")
            throw std::invalid_argument("bgp <router> on|off");
        r->bgpEnabled = t[2] == "on";
        if (r->bgpEnabled) r->BgpStart();
        else r->BgpStop();
    }
    else if (cmd == "bgp-as")
    {
        if (t.size() != 3)
            throw std::invalid_argument("bgp-as <router> <asn>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        unsigned asn = std::stoul(t[2]);
        if (asn == 0 || asn > 65535)
            throw std::invalid_argument("bgp ASN out of range");
        r->bgpLocalAs = uint16_t(asn);
        if (r->bgpEnabled) r->BgpStart();
    }
    else if (cmd == "bgp-router-id")
    {
        if (t.size() != 3)
            throw std::invalid_argument("bgp-router-id <router> <ip>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        r->bgpRouterId = Ipv4(t[2]);
        if (r->bgpEnabled) r->BgpStart();
    }
    else if (cmd == "bgp-neighbor")
    {
        if (t.size() != 4)
            throw std::invalid_argument("bgp-neighbor <router> <ip> <remote-as>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        unsigned asn = std::stoul(t[3]);
        if (asn == 0 || asn > 65535)
            throw std::invalid_argument("bgp remote ASN out of range");
        r->bgpNeighbors[Ipv4(t[2])] = uint16_t(asn);
        if (r->bgpEnabled) r->BgpStart();
    }
    else if (cmd == "bgp-network")
    {
        if (t.size() != 3)
            throw std::invalid_argument("bgp-network <router> <prefix>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        r->bgpNetworks.push_back(Ipv4Subnet(t[2]));
    }
    else if (cmd == "bgp-local-pref")
    {
        if (t.size() != 4)
            throw std::invalid_argument("bgp-local-pref <router> <neighbor> <value>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        unsigned long long value = std::stoull(t[3]);
        if (value > 0xFFFFFFFFull)
            throw std::invalid_argument("bgp local-pref out of range");
        r->bgpLocalPrefIn[Ipv4(t[2])] = uint32_t(value);
        r->BgpReapplyPolicy();
    }
    else if (cmd == "bgp-med")
    {
        if (t.size() != 4)
            throw std::invalid_argument("bgp-med <router> <prefix> <value>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        unsigned long long value = std::stoull(t[3]);
        if (value > 0xFFFFFFFFull)
            throw std::invalid_argument("bgp MED out of range");
        r->bgpMedOut[Ipv4Subnet(t[2])] = uint32_t(value);
    }
    else if (cmd == "bgp-path")
    {
        if (t.size() < 6)
            throw std::invalid_argument("bgp-path <router> <peer> <prefix> <next-hop> <asn...>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        BgpPath p;
        p.peer = Ipv4(t[2]);
        p.prefix = Ipv4Subnet(t[3]);
        p.nextHop = Ipv4(t[4]);
        p.routerId = p.peer;
        for (std::size_t i = 5; i < t.size(); ++i)
        {
            unsigned asn = std::stoul(t[i]);
            if (asn == 0 || asn > 65535)
                throw std::invalid_argument("bgp AS path value out of range");
            p.asPath.push_back(uint16_t(asn));
        }
        p.ebgp = p.asPath.empty() || p.asPath.front() != r->bgpLocalAs;
        r->BgpAddPath(p);
    }
    else if (cmd == "bgp-status")
    {
        if (t.size() != 2)
            throw std::invalid_argument("bgp-status <router>");
        Router *r = dynamic_cast<Router *>(topo.FindDevice(t[1]));
        if (!r)
            throw std::invalid_argument("'" + t[1] + "' is not a router");
        std::cout << "bgp " << t[1] << ": "
                  << (r->bgpEnabled ? "on" : "off")
                  << " as=" << r->bgpLocalAs
                  << " id=" << r->bgpRouterId.ToString()
                  << " neighbors=" << r->bgpNeighbors.size()
                  << " networks=" << r->bgpNetworks.size()
                  << " paths=" << r->bgpPaths.size()
                  << " rib=" << r->bgpRib.size() << "\n";
        for (const auto &kv : r->bgpNeighbors)
            std::cout << "  neighbor " << kv.first.ToString()
                      << " as=" << kv.second << "\n";
        auto stateName = [](uint8_t state) {
            switch(state)
            {
                case 1: return "OpenSent";
                case 2: return "OpenConfirm";
                case 3: return "Established";
                default: return "Idle";
            }
        };
        for (const auto &s : r->bgpSessions)
        {
            if (s.state == 0)
                continue;
            std::cout << "  session " << s.peerIp.ToString()
                      << " state=" << stateName(s.state) << "\n";
        }
        for (const BgpSelected &s : r->bgpRib)
        {
            std::cout << "  rib " << s.prefix.ToString() << " via "
                      << s.peer.ToString() << " aspath=";
            for (std::size_t i = 0; i < s.asPath.size(); ++i)
            {
                if (i) std::cout << " ";
                std::cout << s.asPath[i];
            }
            std::cout << "\n";
        }
    }
    else
    {
        throw std::invalid_argument("unknown command '" + cmd + "'");
    }
}
