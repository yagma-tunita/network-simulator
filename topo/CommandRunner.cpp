#include "CommandRunner.hpp"
#include "TopoCommand.hpp"
#include "Topology.hpp"
#include "JsonConfig.hpp"
#include "../engine/Engine.hpp"
#include "../engine/Pcap.hpp"
#include "../core/EthernetFrame.hpp"
#include "../device/Device.hpp"
#include "../device/Port.hpp"
#include "../device/EndDevice.hpp"
#include "../device/Switch.hpp"
#include "../device/Router.hpp"
#include "../link/Link.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/Mac.hpp"
#include <iostream>
#include <sstream>
#include <map>
#include <utility>
#include <string>
#include <vector>
#include <stdexcept>
#include <chrono>
#include <memory>
#include <cstdint>
#include <cstddef>

namespace
{
    using Tokens = std::vector<std::string>;

    std::string JsonQuote(const std::string &s)
    {
        std::string o = "\"";
        for(char c : s)
        {
            switch(c)
            {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if(static_cast<unsigned char>(c) < 0x20) o += ' ';
                else o += c;
            }
        }
        o += "\"";
        return o;
    }

    const char *KindOf(const Device *d)
    {
        if(dynamic_cast<const Router *>(d)) return "router";
        if(dynamic_cast<const Switch *>(d)) return "switch";
        return "end";
    }

    const char *StateName(const Port *p)
    {
        const Switch *sw = dynamic_cast<const Switch *>(p->owner);
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

    std::string StateJson(Topology &topo, Engine &engine)
    {
        std::map<const Port *, std::pair<std::string, std::size_t>> pmap;
        for(const auto &kv : topo.devices)
        {
            const Device *d = kv.second.get();
            for(std::size_t i = 0; i < d->portList.size(); ++i)
                pmap[d->portList[i]] = { kv.first, i };
        }

        std::ostringstream o;
        o << "{\"time\":" << engine.Now() << ",\"devices\":[";
        bool first = true;
        for(const auto &kv : topo.devices)
        {
            const Device *d = kv.second.get();
            if(!first) o << ",";
            first = false;
            o << "{\"name\":" << JsonQuote(kv.first)
              << ",\"kind\":" << JsonQuote(KindOf(d))
              << ",\"ports\":[";
            for(std::size_t i = 0; i < d->portList.size(); ++i)
            {
                const Port *p = d->portList[i];
                if(i) o << ",";
                o << "{\"index\":" << i
                  << ",\"mac\":" << JsonQuote(p->mac.ToString())
                  << ",\"ip\":" << (p->hasIp
                        ? JsonQuote(p->ip.ToString() + "/" + std::to_string(p->subnet.prefix))
                        : std::string("null"))
                  << ",\"ip6\":" << (p->hasIp6
                        ? JsonQuote(p->ip6.ToString())
                        : std::string("null"))
                  << ",\"prefix6\":" << int(p->prefix6)
                  << ",\"vlan\":" << p->vlan
                  << ",\"tagged\":" << (p->tagged ? "true" : "false")
                  << ",\"state\":" << JsonQuote(StateName(p))
                  << ",\"rx\":" << p->rx << ",\"tx\":" << p->tx
                  << ",\"drop\":" << p->drop << "}";
            }
            o << "]";

            const EndDevice *ed = dynamic_cast<const EndDevice *>(d);
            const Router *rt = dynamic_cast<const Router *>(d);
            if(ed && ed->hasGateway6)
                o << ",\"gateway6\":" << JsonQuote(ed->gateway6.ToString());

            auto emitNd6 = [&](const std::map<Ipv6, Mac> &cache) {
                o << ",\"nd6\":[";
                bool nf = true;
                for(const auto &n : cache)
                {
                    if(!nf) o << ",";
                    nf = false;
                    o << "{\"ip\":" << JsonQuote(n.first.ToString())
                      << ",\"mac\":" << JsonQuote(n.second.ToString()) << "}";
                }
                o << "]";
            };
            if(ed) emitNd6(ed->ndCache);
            else if(rt) emitNd6(rt->nd6Cache);

            if(rt)
            {
                o << ",\"routes6\":[";
                bool rf = true;
                for(const Ipv6Route &r : rt->route6)
                {
                    if(!rf) o << ",";
                    rf = false;
                    o << "{\"dst\":" << JsonQuote(r.dst.ToString())
                      << ",\"next\":" << JsonQuote(r.nextHop.ToString())
                      << ",\"direct\":" << (r.direct ? "true" : "false")
                      << "}";
                }
                o << "]";
            }
            o << "}";
        }
        o << "],\"links\":[";
        first = true;
        for(const auto &lp : topo.links)
        {
            const Link *l = lp.get();
            auto a = pmap.find(l->A);
            auto b = pmap.find(l->B);
            if(a == pmap.end() || b == pmap.end()) continue;
            if(!first) o << ",";
            first = false;
            o << "{\"a\":" << JsonQuote(a->second.first)
              << ",\"aPort\":" << a->second.second
              << ",\"b\":" << JsonQuote(b->second.first)
              << ",\"bPort\":" << b->second.second
              << ",\"up\":" << (l->enabled ? "true" : "false")
              << ",\"delay\":" << l->delay << "}";
        }
        o << "]}";
        return o.str();
    }

    struct NopEvent : Event
    {
        void Execute(Engine &) override {}
        const char *Name() const override { return "nop"; }
    };

    bool IsControl(const std::string &c)
    {
        return c == "run" || c == "wait" || c == "step" || c == "quit" || c == "exit"
            || c == "lookup" || c == "help" || c == "trace" || c == "bench"
            || c == "pcap" || c == "save" || c == "load"
            || c == "new" || c == "demo" || c == "state";
    }

    void PrintCommandHelp(const std::string &c)
    {
        struct HelpItem { const char *name; const char *usage; };
        static const HelpItem items[] = {
            { "add-device", "add-device <name> end|switch|router" },
            { "add-port", "add-port <device> <mac> [<ip>/<prefix>]" },
            { "connect", "connect <dev:idx> <dev:idx> [delay]" },
            { "add-route", "add-route <router> <dst/p> <next-hop-ip>" },
            { "add-route6", "add-route6 <router> <dst6/prefix> <next-hop-ip6>" },
            { "set-vlan", "set-vlan <dev:idx> <vid>" },
            { "set-trunk", "set-trunk <dev:idx> [native-vid]" },
            { "set-stp", "set-stp <switch> on|off" },
            { "set-stp-mode", "set-stp-mode <switch> stp|rstp" },
            { "span", "span <switch> <src-dev:idx> <dst-dev:idx> | off" },
            { "set-bridge", "set-bridge <switch> <priority>" },
            { "stp-status", "stp-status <switch>" },
            { "set-link", "set-link <dev:idx> down|up|loss|dup|jitter|mtu|clear ..." },
            { "stats", "stats <device>" },
            { "drop-stats", "drop-stats <device>" },
            { "devices", "devices" },
            { "links", "links" },
            { "ports", "ports <device>" },
            { "routes", "routes <router>" },
            { "routes6", "routes6 <router>" },
            { "arp-table", "arp-table <device>" },
            { "nd6-table", "nd6-table <device>" },
            { "mac-table", "mac-table <switch>" },
            { "traceroute", "traceroute <device> <target-ip> [max-hops]" },
            { "traceroute6", "traceroute6 <device> <ipv6> [max-hops]" },
            { "export", "export dot|svg <file>" },
            { "udp-echo", "udp-echo <device> on|off [port]" },
            { "udp-send", "udp-send <device> <ip> <dport> [df] <text...>" },
            { "tcp-listen", "tcp-listen <device> on|off [port]" },
            { "tcp-connect", "tcp-connect <device> <ip> <port> [text...]" },
            { "tcp-send", "tcp-send <device> <text...>" },
            { "tcp-keepalive", "tcp-keepalive <device> on [idle interval count]|off" },
            { "tcp-status", "tcp-status <device>" },
            { "tcp-backlog", "tcp-backlog <device> <1-1024>" },
            { "tcp-congestion", "tcp-congestion <device> reno|cubic" },
            { "tcp-tlp", "tcp-tlp <device> on|off" },
            { "tcp-prr", "tcp-prr <device> on|off" },
            { "tcp-rack", "tcp-rack <device> on|off" },
            { "tcp-pacing", "tcp-pacing <device> on|off" },
            { "tcp-port-range", "tcp-port-range <device> <min> <max>" },
            { "dhcp-server", "dhcp-server <device> on <start> <end> <prefix> <gateway> [dns] | off" },
            { "dhcp-client", "dhcp-client <device> [port-index]" },
            { "dhcp-lease-time", "dhcp-lease-time <device> <seconds>" },
            { "dhcp-release", "dhcp-release <device>" },
            { "dhcp-relay", "dhcp-relay <router> <dev:idx> <server-ip>|off" },
            { "ecn-mark", "ecn-mark <router> <dev:idx> on|off" },
            { "dns-server", "dns-server <device> on|off" },
            { "dns-ttl", "dns-ttl <device> <seconds>" },
            { "dns-negative-ttl", "dns-negative-ttl <device> <seconds>" },
            { "dns-cache-size", "dns-cache-size <device> <entries>" },
            { "dns-ttl-bounds", "dns-ttl-bounds <device> <min> <max>" },
            { "dns-record", "dns-record <device> <name> <ip> [ttl]" },
            { "dns-aaaa", "dns-aaaa <device> <name> <ipv6> [ttl]" },
            { "dns-cname", "dns-cname <device> <alias> <target> [ttl]" },
            { "dns-mx", "dns-mx <device> <name> <preference> <exchange> [ttl]" },
            { "dns-zone", "dns-zone <device> <zone>" },
            { "dns-secondary", "dns-secondary <device> <zone> <primary-ip>" },
            { "dns-notify-target", "dns-notify-target <device> <zone> <ip> [ip...]" },
            { "dns-notify", "dns-notify <device> <zone>" },
            { "dns-ns", "dns-ns <device> <owner> <nameserver>" },
            { "dns-soa", "dns-soa <device> <zone> <mname> <rname> [ttl serial refresh retry expire minimum]" },
            { "dns-query", "dns-query <device> [server-ip] <name> [A|AAAA|NS|SOA|PTR|MX]" },
            { "dns-axfr", "dns-axfr <device> <server-ip> <zone>" },
            { "dns-ixfr", "dns-ixfr <device> <server-ip> <zone> <serial>" },
            { "dns-axfr-allow", "dns-axfr-allow <device> <ip> [ip...] | any|none" },
            { "dns-tsig", "dns-tsig <device> <key-name> <secret> [md5|sha1|sha256]" },
            { "dns-tsig-require", "dns-tsig-require <device> on|off" },
            { "dns-update-allow", "dns-update-allow <device> <ip> [ip...] | any|none" },
            { "dns-update-add", "dns-update-add <device> <server-ip> <zone> <name> <ip> [ttl]" },
            { "dns-update-del", "dns-update-del <device> <server-ip> <zone> <name> [A|ANY]" },
            { "dns-update-check", "dns-update-check <device> <server-ip> <zone> <name> <ip>" },
            { "dns-resolver", "dns-resolver <device> <ip> [ip...] | off" },
            { "dns-retry", "dns-retry <device> <timeout> <attempts>" },
            { "nat", "nat <router> on <inside-dev:idx> <outside-dev:idx> | off" },
            { "nat-port", "nat-port <router> tcp|udp <public-port> <inside-ip> <inside-port>" },
            { "nat-table", "nat-table <router>" },
            { "rip", "rip <router> on|off" },
            { "rip-status", "rip-status <router>" },
            { "ospf", "ospf <router> on|off" },
            { "ospf-status", "ospf-status <router>" },
            { "ospf-router-id", "ospf-router-id <router> <id>" },
            { "ospf-auth", "ospf-auth <router> none|simple <password>|md5|sha1|sha256 <key-id> <key>" },
            { "ospf-cost", "ospf-cost <router> <dev:idx> <1-65535>" },
            { "ospf-passive", "ospf-passive <router> <dev:idx> on|off" },
            { "ospf-area", "ospf-area <router> <dev:idx> <area-id>" },
            { "ospf-area-type", "ospf-area-type <router> <area-id> stub|nssa|normal" },
            { "ospf-summary", "ospf-summary <router> <area-id> <prefix> [not-advertise] | clear" },
            { "ospf-external", "ospf-external <router> <ip/prefix> [metric]|clear" },
            { "ospf-default-originate", "ospf-default-originate <router> on|off [metric] [type1|type2]" },
            { "ospf-redistribute", "ospf-redistribute <router> connected|static|off [metric] [type1|type2]" },
            { "tcp-lite-echo", "tcp-lite-echo <device> on|off [port]" },
            { "tcp-lite-echo-client", "tcp-lite-echo-client <device> <ip> <port> <text...>" },
            { "acl", "acl <router> in|out allow|deny <src/p> <dst/p> <proto|any>" },
            { "acl6", "acl6 <router> in|out allow|deny <src6/p> <dst6/p> <proto|any>" },
            { "bgp", "bgp <router> on|off" },
            { "bgp-as", "bgp-as <router> <asn>" },
            { "bgp-router-id", "bgp-router-id <router> <ip>" },
            { "bgp-neighbor", "bgp-neighbor <router> <ip> <remote-as>" },
            { "bgp-network", "bgp-network <router> <prefix>" },
            { "bgp-local-pref", "bgp-local-pref <router> <neighbor> <value>" },
            { "bgp-med", "bgp-med <router> <prefix> <value>" },
            { "bgp-path", "bgp-path <router> <peer> <prefix> <next-hop> <asn...>" },
            { "bgp-status", "bgp-status <router>" },
            { "map", "map" },
            { "generate", "generate tree <depth> <fanout>" },
            { "remove-device", "remove-device <name>" },
            { "remove-port", "remove-port <dev:idx>" },
            { "disconnect", "disconnect <dev:idx>" },
            { "rename-device", "rename-device <old> <new>" },
            { "set-ip", "set-ip <dev:idx> <ip>/<prefix>" },
            { "set-ip6", "set-ip6 <dev:idx> <ipv6>" },
            { "set-gateway", "set-gateway <device> <gw-ip>" },
            { "set-gateway6", "set-gateway6 <device> <gw-ipv6>" },
            { "arp", "arp <device> <target-ip>" },
            { "ping", "ping <device> <target-ip> [ttl]" },
            { "ping6", "ping6 <device> <ipv6>" },
            { "state", "state" },
            { "pcap", "pcap <file> | pcap off" },
            { "save", "save <file.yn>" },
            { "load", "load <file.yn>" },
            { "lookup", "lookup <device> <ip>" },
            { "bench", "bench [n]" },
            { "run", "run [duration]" },
            { "wait", "wait [duration]" },
            { "step", "step [n]" },
            { "trace", "trace on|off" },
            { "new", "new" },
            { "demo", "demo" },
            { "quit", "quit | exit" }
        };

        for(const HelpItem &h : items)
        {
            if(c == h.name)
            {
                std::cout << "usage: " << h.usage << "\n";
                return;
            }
        }
        std::cout << "no help for '" << c << "' (see 'help')\n";
    }

    void RunControl(CommandContext &ctx, const Tokens &t)
    {
        const std::string &c = t[0];

        if (c == "quit" || c == "exit")
        {
            ctx.quit = true;
            return;
        }
        if (c == "help")
        {
            if (t.size() >= 2)
                PrintCommandHelp(t[1]);
            else
                PrintHelp();
            return;
        }
        if (c == "run")
        {
            const uint64_t kMaxRun = 1000000;
            uint64_t d = (t.size() > 1) ? std::stoull(t[1]) : 1000;
            if (d > kMaxRun) d = kMaxRun;
            ctx.engine->RunUntil(ctx.engine->Now() + d);
            if (!ctx.quiet)
            {
                if (ctx.engine->stopped)
                    std::cout << "interrupted; now=" << ctx.engine->Now() << "\n";
                else if (ctx.engine->halted)
                    std::cout << "halted (event limit); now=" << ctx.engine->Now() << "\n";
                else
                    std::cout << "ran; now=" << ctx.engine->Now() << "\n";
            }
            return;
        }
        if (c == "wait")
        {
            const uint64_t kMaxWait = 1000000;
            uint64_t d = (t.size() > 1) ? std::stoull(t[1]) : 1;
            if (d > kMaxWait) d = kMaxWait;
            uint64_t target = ctx.engine->Now() + d;
            ctx.engine->ScheduleAfter(d, std::make_unique<NopEvent>());
            ctx.engine->RunUntil(target);
            if (!ctx.quiet)
                std::cout << "waited; now=" << ctx.engine->Now() << "\n";
            return;
        }
        if (c == "new")
        {
            ctx.engine->Reset();
            ctx.topo->Clear();
            ctx.pcap.reset();
            if (!ctx.quiet) std::cout << "new scene\n";
            return;
        }
        if (c == "demo")
        {
            ctx.engine->Reset();
            ctx.topo->Clear();
            ctx.pcap.reset();
            const char *lines[] = {
                "add-device PC1 end",
                "add-device PC2 end",
                "add-device SW1 switch",
                "add-port PC1 aa:aa:aa:aa:aa:01 192.168.1.1/24",
                "add-port PC2 aa:aa:aa:aa:aa:02 192.168.1.2/24",
                "add-port SW1 11:11:11:11:11:01",
                "add-port SW1 11:11:11:11:11:02",
                "connect PC1:0 SW1:0",
                "connect PC2:0 SW1:1",
                "ping PC1 192.168.1.2",
                "run 200"
            };
            for (const char *line : lines)
                RunScriptLine(ctx, line);
            if (!ctx.quiet) std::cout << "demo complete\n";
            return;
        }
        if (c == "bench")
        {
            const uint64_t kMaxBench = 50000000;
            uint64_t n = (t.size() > 1) ? std::stoull(t[1]) : 1000000;
            if (n > kMaxBench) n = kMaxBench;

            auto t0 = std::chrono::steady_clock::now();
            const uint64_t kChunk = 50000;
            uint64_t done = 0;
            while (done < n)
            {
                uint64_t k = (n - done < kChunk) ? (n - done) : kChunk;
                for (uint64_t i = 0; i < k; i++)
                    ctx.engine->ScheduleAfter(0, std::make_unique<NopEvent>());
                ctx.engine->Run();
                done += k;
            }
            auto t1 = std::chrono::steady_clock::now();

            double sec = std::chrono::duration<double>(t1 - t0).count();
            double rate = (sec > 0.0) ? double(n) / sec : 0.0;
            std::cout << n << " events in " << sec << " s = "
                      << rate << " events/s\n";
            return;
        }
        if (c == "step")
        {
            uint64_t n = (t.size() > 1) ? std::stoull(t[1]) : 1;
            for (uint64_t i = 0; i < n && ctx.engine->Step(); i++) {}
            if (!ctx.quiet) std::cout << "now=" << ctx.engine->Now() << "\n";
            return;
        }
        if (c == "pcap")
        {
            if (t.size() == 2 && t[1] == "off")
            {
                uint64_t n = ctx.pcap ? ctx.pcap->Count() : 0;
                bool over = ctx.pcap && ctx.pcap->overflow;
                ctx.pcap.reset();
                ctx.engine->frameTap = nullptr;
                std::cout << "pcap: " << n << " frames captured"
                          << (over ? " (limit reached)" : "") << "\n";
                return;
            }
            if (t.size() != 2)
                throw std::invalid_argument("pcap <file> | pcap off");

            auto w = std::make_shared<PcapWriter>();
            if (!w->Open(t[1]))
                throw std::invalid_argument("cannot open pcap file '" + t[1] + "'");

            ctx.pcap = w;
            ctx.engine->frameTap = [w](uint64_t tm, const EthernetFrame &f) {
                w->Write(tm, f.ToBytes());
            };
            std::cout << "pcap: recording to " << t[1] << "\n";
            return;
        }
        if (c == "trace")
        {
            if (t.size() == 2 && t[1] == "on")
                ctx.engine->trace = [](uint64_t tm, const char *name) {
                    std::cout << "[t=" << tm << "] " << name << "\n";
                };
            else
                ctx.engine->trace = nullptr;
            if (!ctx.quiet)
                std::cout << "trace " << (ctx.engine->trace ? "on" : "off") << "\n";
            return;
        }
        if (c == "lookup")
        {
            if (t.size() != 3)
                throw std::invalid_argument("lookup <device> <ip>");
            Device *d = ctx.topo->FindDevice(t[1]);
            EndDevice *e = dynamic_cast<EndDevice *>(d);
            if (!e)
                throw std::invalid_argument("'" + t[1] + "' is not an end device");
            Mac mac;
            if (e->Lookup(Ipv4(t[2]), mac))
                std::cout << mac.ToString() << "\n";
            else
                std::cout << "(no entry)\n";
            return;
        }
        if (c == "state")
        {
            std::cout << StateJson(*ctx.topo, *ctx.engine) << "\n";
            return;
        }
        if (c == "save")
        {
            if (t.size() != 2)
                throw std::invalid_argument("save <file.json>");
            std::string err;
            LayoutMap layout;
            if (!SaveTopologyJson(*ctx.topo, t[1], layout, err))
                throw std::invalid_argument(err);
            std::cout << "saved to " << t[1] << "\n";
            return;
        }
        if (c == "load")
        {
            if (t.size() != 2)
                throw std::invalid_argument("load <file.json>");
            std::vector<std::string> cmds;
            std::string err;
            LayoutMap layout;
            if (!ParseConfigJson(t[1], cmds, layout, err))
                throw std::invalid_argument(err);
            for (const std::string &line : cmds)
                RunScriptLine(ctx, line);
            std::cout << "loaded " << cmds.size() << " commands from " << t[1] << "\n";
            return;
        }

        throw std::invalid_argument("unknown control command");
    }
}

std::string StateSnapshot(Topology &topo, Engine &engine)
{
    return StateJson(topo, engine);
}

void PrintHelp()
{
    std::cout <<
        "commands:\n"
        "  add-device <name> end|switch|router\n"
        "  add-port   <device> <mac> [<ip>/<prefix>]\n"
        "  connect    <dev:idx> <dev:idx> [delay]\n"
        "  add-route  <router> <dst/p> <next-hop-ip>\n"
        "  add-route6 <router> <dst6/prefix> <next-hop-ip6>\n"
        "  arp        <device> <target-ip>\n"
        "  ping       <device> <target-ip> [ttl]\n"
        "  ping6      <device> <ipv6>\n"
        "  set-gateway <device> <gw-ip>\n"
        "  set-gateway6 <device> <gw-ipv6>\n"
        "  set-vlan   <dev:idx> <vid>\n"
        "  set-trunk  <dev:idx> [native-vid]\n"
        "  set-stp    <switch> on|off\n"
        "  set-stp-mode <switch> stp|rstp\n"
        "  span       <switch> <src-dev:idx> <dst-dev:idx> | off\n"
        "  set-bridge <switch> <priority>\n"
        "  stp-status <switch>\n"
        "  set-link   <dev:idx> down|up|loss|dup|jitter|mtu|clear ...\n"
        "  stats      <device>\n"
        "  drop-stats <device>\n"
        "  devices | links\n"
        "  ports      <device>\n"
        "  routes     <router>\n"
        "  arp-table  <device>\n"
        "  nd6-table  <device>\n"
        "  mac-table  <switch>\n"
        "  traceroute <device> <target-ip> [max-hops]\n"
        "  traceroute6 <device> <ipv6> [max-hops]\n"
        "  export     dot|svg <file>\n"
        "  udp-echo   <device> on|off [port]\n"
        "  udp-send   <device> <ip> <dport> [df] <text...>\n"
        "  tcp-listen <device> on|off [port]\n"
        "  tcp-connect <device> <ip> <port> [text...]\n"
        "  tcp-send   <device> <text...>\n"
        "  tcp-keepalive <device> on [idle interval count]|off\n"
        "  tcp-status <device>\n"
        "  tcp-backlog <device> <1-1024>\n"
        "  tcp-congestion <device> reno|cubic\n"
        "  tcp-tlp <device> on|off\n"
        "  tcp-prr <device> on|off\n"
        "  tcp-rack <device> on|off\n"
        "  tcp-pacing <device> on|off\n"
        "  tcp-port-range <device> <min> <max>\n"
        "  dhcp-server <device> on <start> <end> <prefix> <gateway> [dns] | off\n"
        "  dhcp-client <device> [port-index]\n"
        "  dhcp-lease-time <device> <seconds>\n"
        "  dhcp-release <device>\n"
        "  dhcp-relay <router> <dev:idx> <server-ip>|off\n"
        "  ecn-mark   <router> <dev:idx> on|off\n"
        "  dns-server <device> on|off\n"
        "  dns-ttl    <device> <seconds>\n"
        "  dns-negative-ttl <device> <seconds>\n"
        "  dns-cache-size <device> <entries>\n"
        "  dns-ttl-bounds <device> <min> <max>\n"
        "  dns-record <device> <name> <ip> [ttl]\n"
        "  dns-aaaa   <device> <name> <ipv6> [ttl]\n"
        "  dns-cname  <device> <alias> <target> [ttl]\n"
        "  dns-mx     <device> <name> <preference> <exchange> [ttl]\n"
        "  dns-zone   <device> <zone>\n"
        "  dns-secondary <device> <zone> <primary-ip>\n"
        "  dns-notify-target <device> <zone> <ip> [ip...]\n"
        "  dns-notify <device> <zone>\n"
        "  dns-ns     <device> <owner> <nameserver>\n"
        "  dns-soa    <device> <zone> <mname> <rname> [ttl serial refresh retry expire minimum]\n"
        "  dns-query  <device> [server-ip] <name> [A|AAAA|NS|SOA|PTR|MX]\n"
        "  dns-axfr   <device> <server-ip> <zone>\n"
        "  dns-ixfr   <device> <server-ip> <zone> <serial>\n"
        "  dns-axfr-allow <device> <ip> [ip...] | any|none\n"
        "  dns-tsig   <device> <key-name> <secret> [md5|sha1|sha256]\n"
        "  dns-tsig-require <device> on|off\n"
        "  dns-update-allow <device> <ip> [ip...] | any|none\n"
        "  dns-update-add <device> <server-ip> <zone> <name> <ip> [ttl]\n"
        "  dns-update-del <device> <server-ip> <zone> <name> [A|ANY]\n"
        "  dns-update-check <device> <server-ip> <zone> <name> <ip>\n"
        "  dns-resolver <device> <ip> [ip...] | off\n"
        "  dns-retry  <device> <timeout> <attempts>\n"
        "  nat        <router> on <inside-dev:idx> <outside-dev:idx> | off\n"
        "  nat-port   <router> tcp|udp <public-port> <inside-ip> <inside-port>\n"
        "  nat-table  <router>\n"
        "  rip        <router> on|off\n"
        "  rip-status <router>\n"
        "  ospf       <router> on|off\n"
        "  ospf-status <router>\n"
        "  ospf-router-id <router> <id>\n"
        "  ospf-auth  <router> none|simple <password>|md5|sha1|sha256 <key-id> <key>\n"
        "  ospf-cost  <router> <dev:idx> <1-65535>\n"
        "  ospf-passive <router> <dev:idx> on|off\n"
        "  ospf-area  <router> <dev:idx> <area-id>\n"
        "  ospf-area-type <router> <area-id> stub|nssa|normal\n"
        "  ospf-summary <router> <area-id> <prefix> [not-advertise] | clear\n"
        "  ospf-external <router> <ip/prefix> [metric]|clear\n"
        "  ospf-default-originate <router> on|off [metric] [type1|type2]\n"
        "  ospf-redistribute <router> connected|static|off [metric] [type1|type2]\n"
        "  tcp-lite-echo   <device> on|off [port]\n"
        "  tcp-lite-echo-client <device> <ip> <port> <text...>\n"
        "  acl        <router> in|out allow|deny <src/p> <dst/p> <proto|any>\n"
        "  acl6       <router> in|out allow|deny <src6/p> <dst6/p> <proto|any>\n"
        "  bgp        <router> on|off\n"
        "  bgp-as     <router> <asn>\n"
        "  bgp-router-id <router> <ip>\n"
        "  bgp-neighbor <router> <ip> <remote-as>\n"
        "  bgp-network <router> <prefix>\n"
        "  bgp-local-pref <router> <neighbor> <value>\n"
        "  bgp-med    <router> <prefix> <value>\n"
        "  bgp-path   <router> <peer> <prefix> <next-hop> <asn...>\n"
        "  bgp-status <router>\n"
        "  map\n"
        "  generate   tree <depth> <fanout>\n"
        "  remove-device <name>\n"
        "  remove-port   <dev:idx>\n"
        "  disconnect    <dev:idx>\n"
        "  rename-device <old> <new>\n"
        "  set-ip     <dev:idx> <ip>/<prefix>\n"
        "  set-ip6    <dev:idx> <ipv6>\n"
        "  state      print a JSON snapshot (automation)\n"
        "  pcap       <file> | pcap off                 # capture frames to pcap\n"
        "  save       <file.yn>                         # export scene (.yn)\n"
        "  load       <file.yn>                         # build scene from .yn\n"
        "  new        reset the scene (clears topology and engine)\n"
        "  demo       build a sample 2-host + switch scene and ping\n"
        "  run [d] | wait [d] | step [n] | trace on|off | lookup <device> <ip> | bench [n] | quit | help\n"
        "  .txt scripts run line-by-line; .yn scenes load; .lua runs a Lua script\n";
}

void RunScriptLine(CommandContext &ctx, const std::string &line)
{
    if (line.empty() || line[0] == '#')
        return;

    Tokens t = Tokenize(line);
    if (t.empty())
        return;

    if (IsControl(t[0]))
        RunControl(ctx, t);
    else
        ExecuteCommand(*ctx.topo, t);
}
