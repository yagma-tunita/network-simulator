#include "../engine/Engine.hpp"
#include "../topo/Topology.hpp"
#include "../topo/CommandRunner.hpp"
#include "../topo/JsonConfig.hpp"
#include "../device/Device.hpp"
#include "../device/Port.hpp"
#include "Version.hpp"
#include "LineEditor.hpp"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstddef>
#include <csignal>
#include <cstdlib>

#ifdef HAVE_LUA
#include "../script/LuaScript.hpp"
#endif

static volatile std::sig_atomic_t g_sigint = 0;

static void OnSigint(int)
{
    g_sigint = 1;
}

static bool EndsWith(const std::string &s, const std::string &suffix)
{
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static std::string JsonString(const std::string &s)
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

struct Reporter
{
    bool json = false;
    std::ofstream log;
    bool hasLog = false;

    void record(const std::string &j)
    {
        if(json) std::cout << j << "\n";
        if(hasLog) log << j << "\n";
    }
};

struct CmdResult
{
    bool ok = true;
    std::string out;
    std::string err;
};

static CmdResult RunCaptured(CommandContext &ctx, const std::string &line)
{
    CmdResult r;
    std::ostringstream oss;
    std::streambuf *old = std::cout.rdbuf(oss.rdbuf());
    try
    {
        RunScriptLine(ctx, line);
    }
    catch(const std::exception &e)
    {
        r.ok = false;
        r.err = e.what();
    }
    std::cout.rdbuf(old);
    r.out = oss.str();
    return r;
}

static std::string CmdJson(int line, const std::string &cmd, const CmdResult &r)
{
    std::ostringstream o;
    o << "{\"line\":" << line
      << ",\"cmd\":" << JsonString(cmd)
      << ",\"ok\":" << (r.ok ? "true" : "false")
      << ",\"output\":" << JsonString(r.out);
    if(!r.ok) o << ",\"error\":" << JsonString(r.err);
    o << "}";
    return o.str();
}

static std::string SummaryJson(Topology &topo, Engine &engine, bool ok, int exitCode)
{
    std::ostringstream o;
    o << "{\"summary\":{\"ok\":" << (ok ? "true" : "false")
      << ",\"exit\":" << exitCode
      << ",\"time\":" << engine.Now()
      << ",\"devices\":" << topo.devices.size()
      << ",\"links\":" << topo.links.size()
      << "},\"state\":" << StateSnapshot(topo, engine) << "}";
    return o.str();
}

static int Fail(Reporter &rep, Topology &topo, Engine &engine, const std::string &msg)
{
    if(rep.json || rep.hasLog)
        rep.record("{\"error\":" + JsonString(msg) + "}");
    if(!rep.json)
        std::cerr << "error: " << msg << "\n";
    rep.record(SummaryJson(topo, engine, false, 1));
    return 1;
}

static void PrintUsage(const char *prog)
{
    std::cout
        << YANAS_NAME << " " << YANAS_VERSION << "\n\n"
        << "Usage:\n"
        << "  " << prog << " [options] [file]\n\n"
        << "Options:\n"
        << "  -h, --help          show this help and exit\n"
        << "      --version       print version and exit\n"
        << "      --features      list build features and exit\n"
        << "  -q, --quiet         suppress status lines\n"
        << "      --keep-going    continue after a script error\n"
        << "      --no-lua        refuse to run .lua scripts\n"
        << "  -i, --interactive   enter the prompt after loading a file\n"
        << "      --json          emit NDJSON records (requires a file)\n"
        << "      --log <file>    also append JSON records to a file\n"
        << "  -f, --file <path>   run a scene/script file\n\n"
        << "Files:\n"
        << "  .yn / .json   load a scene (topology)\n"
        << "  .lua          run a Lua script\n"
        << "  otherwise     run a line-command script (.txt)\n\n"
        << "Examples:\n"
        << "  " << prog << "                     # interactive\n"
        << "  " << prog << " tests/config.yn       # load a scene\n"
        << "  " << prog << " -i tests/config.yn    # load, then prompt\n"
        << "  " << prog << " tests/auto_ping.txt\n"
        << "  " << prog << " tests/lua_ping.lua\n"
        << "  " << prog << " --json tests/auto_ping.txt\n"
        << "  echo demo | " << prog << "\n\n"
        << "Press Ctrl-C to interrupt a running simulation.\n";
}

static void RunInteractive(CommandContext &ctx)
{
    const char *home = std::getenv("HOME");
    std::string hist = (home ? std::string(home) : std::string(".")) + "/.yanas_history";
    LineEditor::LoadHistory(hist);
    LineEditor::SetCompleter([&ctx](const std::string &buffer) {
        static const char *cmds[] = {
            "add-device", "add-port", "connect", "add-route", "add-route6", "set-vlan", "set-trunk", "set-stp", "set-stp-mode", "set-bridge", "stp-status", "span",
            "set-link", "stats", "remove-device", "remove-port", "disconnect",
            "rename-device", "set-ip", "state", "set-gateway", "set-gateway6", "arp", "ping",
            "run", "wait", "step", "trace", "lookup", "bench", "pcap", "save", "load",
            "new", "demo", "help", "quit", "exit", "acl6",
            "bgp", "bgp-as", "bgp-router-id", "bgp-neighbor", "bgp-network", "bgp-local-pref", "bgp-med", "bgp-path", "bgp-status",
            "ping6", "set-ip6",
            "devices", "links", "ports", "routes", "routes6", "arp-table", "nd6-table", "mac-table",
            "traceroute", "traceroute6", "export", "udp-echo", "udp-send", "map", "generate",
            "drop-stats",
            "tcp-listen", "tcp-connect", "tcp-send", "tcp-keepalive", "tcp-status", "tcp-backlog", "tcp-congestion", "tcp-tlp", "tcp-prr", "tcp-rack", "tcp-pacing", "tcp-port-range",
            "dhcp-server", "dhcp-client", "dhcp-lease-time", "dhcp-release", "dhcp-relay", "ecn-mark", "dns-server", "dns-ttl", "dns-negative-ttl", "dns-cache-size", "dns-ttl-bounds", "dns-record", "dns-aaaa", "dns-cname", "dns-mx", "dns-zone", "dns-secondary", "dns-notify-target", "dns-notify", "dns-ns", "dns-soa", "dns-query", "dns-axfr", "dns-ixfr", "dns-axfr-allow", "dns-tsig", "dns-tsig-require", "dns-update-allow", "dns-update-add", "dns-update-del", "dns-update-check", "dns-resolver", "dns-retry",
            "nat", "nat-port", "nat-table",
            "rip", "rip-status",
            "ospf", "ospf-status", "ospf-router-id", "ospf-auth", "ospf-cost", "ospf-passive", "ospf-area", "ospf-area-type", "ospf-summary", "ospf-external", "ospf-default-originate", "ospf-redistribute",
            "tcp-lite-echo", "tcp-lite-echo-client", "acl"
        };
        std::vector<std::string> out;
        std::size_t sp = buffer.find_last_of(' ');
        bool first = (sp == std::string::npos);
        std::string prefix = first ? buffer : buffer.substr(sp + 1);

        if(first)
        {
            for(const char *c : cmds)
            {
                std::string s(c);
                if(s.compare(0, prefix.size(), prefix) == 0) out.push_back(s);
            }
        }
        else if(ctx.topo)
        {
            std::string lead = buffer.substr(0, sp + 1);

            std::size_t firstSp = buffer.find(' ');
            if(firstSp != std::string::npos && buffer.substr(0, firstSp) == "export" &&
               buffer.find(' ', firstSp + 1) == std::string::npos)
            {
                for(const char *s : { "dot", "svg" })
                {
                    std::string cand(s);
                    if(cand.compare(0, prefix.size(), prefix) == 0)
                        out.push_back("export " + cand);
                }
                return out;
            }

            std::size_t colon = prefix.find(':');
            if(colon != std::string::npos)
            {
                std::string dev = prefix.substr(0, colon);
                auto it = ctx.topo->devices.find(dev);
                if(it != ctx.topo->devices.end())
                {
                    std::size_t count = it->second->portList.size();
                    for(std::size_t i = 0; i < count; ++i)
                    {
                        std::string cand = dev + ":" + std::to_string(i);
                        if(cand.compare(0, prefix.size(), prefix) == 0)
                            out.push_back(lead + cand);
                    }
                    return out;
                }
            }

            for(const auto &kv : ctx.topo->devices)
                if(kv.first.compare(0, prefix.size(), prefix) == 0)
                    out.push_back(lead + kv.first);
        }
        return out;
    });

    std::cout << YANAS_NAME << " " << YANAS_VERSION << " - type 'help' (try 'demo')\n";

    std::string line;
    while(!ctx.quit)
    {
        if(!LineEditor::ReadLine("> ", line))
            break;
        if(line.empty())
            continue;
        LineEditor::AddHistory(line);
        try
        {
            RunScriptLine(ctx, line);
        }
        catch(const std::exception &e)
        {
            std::cerr << "error: " << e.what() << "\n";
        }
    }

    LineEditor::SaveHistory(hist);
}

static int RunFile(Engine &engine, CommandContext &ctx, const std::string &file,
                   bool allowLua, bool keepGoing, bool quiet, Reporter &rep)
{
    if(EndsWith(file, ".lua"))
    {
        if(!allowLua)
            return Fail(rep, *ctx.topo, engine, "Lua disabled by --no-lua");
#ifdef HAVE_LUA
        std::string out, err;
        bool ok;
        {
            std::ostringstream oss;
            std::streambuf *old = std::cout.rdbuf(oss.rdbuf());
            ok = RunLuaFile(engine, *ctx.topo, file, err);
            std::cout.rdbuf(old);
            out = oss.str();
        }
        if(rep.json || rep.hasLog)
        {
            std::ostringstream o;
            o << "{\"lua\":" << JsonString(file)
              << ",\"ok\":" << (ok ? "true" : "false")
              << ",\"output\":" << JsonString(out);
            if(!ok) o << ",\"error\":" << JsonString(err);
            o << "}";
            rep.record(o.str());
        }
        if(!rep.json)
        {
            std::cout << out;
            if(!ok) std::cerr << "lua: " << err << "\n";
            if(!quiet && ok) std::cout << "done; now=" << engine.Now() << "\n";
        }
        rep.record(SummaryJson(*ctx.topo, engine, ok, ok ? 0 : 1));
        return ok ? 0 : 1;
#else
        return Fail(rep, *ctx.topo, engine, "Lua support not built");
#endif
    }

    if(EndsWith(file, ".yn") || EndsWith(file, ".json"))
    {
        std::vector<std::string> cmds;
        LayoutMap layout;
        std::string err;
        if(!ParseConfigJson(file, cmds, layout, err))
            return Fail(rep, *ctx.topo, engine, err);
        if(cmds.size() > 100000)
            return Fail(rep, *ctx.topo, engine, "scene has too many commands (limit 100000)");

        int status = 0;
        bool allOk = true;
        for(std::size_t i = 0; i < cmds.size(); ++i)
        {
            CmdResult r = RunCaptured(ctx, cmds[i]);
            if(rep.json || rep.hasLog) rep.record(CmdJson(int(i + 1), cmds[i], r));
            if(!rep.json)
            {
                std::cout << r.out;
                if(!r.ok) std::cerr << file << ":" << (i + 1) << ": error: " << r.err << "\n";
            }
            if(!r.ok) { status = 1; allOk = false; if(!keepGoing) break; }
            if(ctx.quit) break;
        }
        if(!rep.json && !quiet && allOk)
            std::cout << "loaded " << cmds.size() << " commands from " << file
                      << "; now=" << engine.Now() << "\n";
        rep.record(SummaryJson(*ctx.topo, engine, allOk, status));
        return status;
    }

    std::ifstream in(file);
    if(!in)
        return Fail(rep, *ctx.topo, engine, "cannot open '" + file + "'");

    in.seekg(0, std::ios::end);
    std::streamoff fileSize = in.tellg();
    in.seekg(0, std::ios::beg);
    if(fileSize < 0 || fileSize > (16 * 1024 * 1024))
        return Fail(rep, *ctx.topo, engine, "script too large (16 MiB limit)");

    int status = 0;
    bool allOk = true;
    int lineNo = 0;
    std::string line;
    while(std::getline(in, line))
    {
        ++lineNo;
        if(lineNo > 1000000)
        {
            if(rep.json || rep.hasLog)
                rep.record("{\"error\":" + JsonString("too many lines (limit 1000000)") + "}");
            if(!rep.json) std::cerr << file << ": too many lines (limit 1000000)\n";
            status = 1;
            allOk = false;
            break;
        }

        CmdResult r = RunCaptured(ctx, line);
        if(rep.json || rep.hasLog) rep.record(CmdJson(lineNo, line, r));
        if(!rep.json)
        {
            std::cout << r.out;
            if(!r.ok) std::cerr << file << ":" << lineNo << ": error: " << r.err << "\n";
        }
        if(!r.ok) { status = 1; allOk = false; if(!keepGoing) break; }
        if(ctx.quit) break;
    }

    if(!rep.json && !quiet && allOk)
        std::cout << "done; now=" << engine.Now() << "\n";
    rep.record(SummaryJson(*ctx.topo, engine, allOk, status));
    return status;
}

int main(int argc, char **argv)
{
    Engine engine;
    Topology topo;
    topo.SetEngine(&engine);

    std::signal(SIGINT, OnSigint);
    engine.shouldStop = []() -> bool {
        if(g_sigint) { g_sigint = 0; return true; }
        return false;
    };

    CommandContext ctx;
    ctx.engine = &engine;
    ctx.topo = &topo;

    std::string file;
    std::string logPath;
    bool haveFile = false;
    bool quiet = false, keepGoing = false, allowLua = true;
    bool forceInteractive = false, json = false;

    for(int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if(a == "-h" || a == "--help") { PrintUsage(argv[0]); return 0; }
        else if(a == "--version") { std::cout << YANAS_NAME << " " << YANAS_VERSION << "\n"; return 0; }
        else if(a == "--features")
        {
            std::cout << "core";
#ifdef HAVE_LUA
            std::cout << " lua";
#endif
            std::cout << "\n";
            return 0;
        }
        else if(a == "-q" || a == "--quiet") quiet = true;
        else if(a == "--keep-going") keepGoing = true;
        else if(a == "--no-lua") allowLua = false;
        else if(a == "--json") json = true;
        else if(a == "-i" || a == "--interactive") forceInteractive = true;
        else if(a == "--log")
        {
            if(i + 1 >= argc) { std::cerr << "error: --log needs a path\n"; return 2; }
            logPath = argv[++i];
        }
        else if(a == "-f" || a == "--file" || a == "--script" || a == "--scene")
        {
            if(i + 1 >= argc) { std::cerr << "error: " << a << " needs a path\n"; return 2; }
            file = argv[++i];
            haveFile = true;
        }
        else if(!a.empty() && a[0] == '-')
        {
            std::cerr << "error: unknown option '" << a << "'\n";
            PrintUsage(argv[0]);
            return 2;
        }
        else
        {
            file = a;
            haveFile = true;
        }
    }

    if(json && !haveFile)
    {
        std::cerr << "error: --json requires a file\n";
        PrintUsage(argv[0]);
        return 2;
    }
    if(json && forceInteractive)
    {
        std::cerr << "error: --json cannot be combined with -i\n";
        return 2;
    }
    ctx.quiet = quiet;

    Reporter rep;
    rep.json = json;
    if(!logPath.empty())
    {
        rep.log.open(logPath);
        if(!rep.log)
        {
            std::cerr << "error: cannot open log '" << logPath << "'\n";
            return 1;
        }
        rep.hasLog = true;
    }

    if(!haveFile)
    {
        RunInteractive(ctx);
        return 0;
    }

    int status = 0;
    try
    {
        status = RunFile(engine, ctx, file, allowLua, keepGoing, quiet, rep);
    }
    catch(const std::exception &e)
    {
        std::cerr << "fatal: " << e.what() << "\n";
        status = 1;
    }

    if(forceInteractive)
        RunInteractive(ctx);

    return status;
}
