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
#include <cstdio>
#include <cstdint>
#include <thread>
#include <atomic>
#include <mutex>
#include <deque>
#include <chrono>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

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

static int RunLive(Engine &engine, CommandContext &ctx, const std::string &ref,
                   uint64_t scaleMs)
{
    if(!ctx.topo)
        return 1;

    std::size_t colon = ref.find(':');
    if(colon == std::string::npos)
    {
        std::cerr << "live: expected <device>:<index>\n";
        return 2;
    }
    std::string name = ref.substr(0, colon);
    std::size_t idx = std::size_t(std::stoul(ref.substr(colon + 1)));
    Port *port = ctx.topo->FindPort(name, idx);
    if(!port)
    {
        std::cerr << "live: no such port " << ref << "\n";
        return 2;
    }

#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    std::mutex mtx;
    std::deque<std::vector<uint8_t>> inbound;
    std::atomic<bool> eof(false);

    std::thread reader([&]() {
        for(;;)
        {
            uint8_t hdr[4];
            if(std::fread(hdr, 1, 4, stdin) != 4)
            {
                eof = true;
                return;
            }
            uint32_t n = uint32_t(hdr[0]) | (uint32_t(hdr[1]) << 8) |
                         (uint32_t(hdr[2]) << 16) | (uint32_t(hdr[3]) << 24);
            if(n == 0 || n > 65535)
            {
                eof = true;
                return;
            }
            std::vector<uint8_t> frame(n);
            if(std::fread(frame.data(), 1, n, stdin) != n)
            {
                eof = true;
                return;
            }
            std::lock_guard<std::mutex> lock(mtx);
            inbound.push_back(std::move(frame));
        }
    });
    reader.detach();

    port->bridge = [](FramePtr f) {
        std::vector<uint8_t> b = f->ToBytes();
        uint32_t n = uint32_t(b.size());
        uint8_t hdr[4] = { uint8_t(n), uint8_t(n >> 8),
                           uint8_t(n >> 16), uint8_t(n >> 24) };
        std::fwrite(hdr, 1, 4, stdout);
        if(!b.empty())
            std::fwrite(b.data(), 1, b.size(), stdout);
        std::fflush(stdout);
    };

    if(scaleMs == 0)
        scaleMs = 1;
    uint64_t base = engine.now;
    auto start = std::chrono::steady_clock::now();

    while(!g_sigint)
    {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        uint64_t target = base + uint64_t(elapsed) / scaleMs;
        if(target > engine.now)
            engine.now = target;

        while(!engine.queue.Empty() &&
              engine.queue.Top()->time <= engine.now)
            engine.Step();

        std::deque<std::vector<uint8_t>> batch;
        {
            std::lock_guard<std::mutex> lock(mtx);
            batch.swap(inbound);
        }
        for(std::vector<uint8_t> &bytes : batch)
        {
            EthernetFrame frame;
            if(EthernetFrame::TryFromBytes(bytes, frame))
                port->Receive(std::make_shared<const EthernetFrame>(std::move(frame)));
        }

        if(eof && batch.empty())
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    port->bridge = nullptr;
    return 0;
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
        << "      --live <dev:idx> stream frames on stdin/stdout\n"
        << "      --live-scale <ms> wall-clock ms per logical tick (default 1)\n"
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
            "add-device", "add-port", "connect", "add-route", "set-vlan",
            "set-trunk", "set-stp", "set-stp-mode", "set-bridge", "stp-status",
            "set-link", "stats", "remove-device", "remove-port", "disconnect",
            "rename-device", "set-ip", "state", "set-gateway", "arp", "ping",
            "run", "step", "trace", "lookup", "bench", "pcap", "save", "load",
            "new", "demo", "help", "quit", "exit",
            "devices", "links", "ports", "routes", "arp-table", "mac-table",
            "traceroute", "export", "udp-echo", "udp-send", "map", "generate",
            "tcp-listen", "tcp-connect", "tcp-keepalive", "tcp-status", "tcp-backlog",
            "dhcp-server", "dhcp-client", "dns-server", "dns-record", "dns-query",
            "nat", "nat-port", "nat-table",
            "rip", "rip-status",
            "ospf", "ospf-status", "ospf-auth",
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
    bool live = false;
    std::string liveRef;
    uint64_t liveScale = 1;

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
        else if(a == "--live")
        {
            if(i + 1 >= argc) { std::cerr << "error: --live needs <device>:<index>\n"; return 2; }
            liveRef = argv[++i];
            live = true;
        }
        else if(a == "--live-scale")
        {
            if(i + 1 >= argc) { std::cerr << "error: --live-scale needs milliseconds\n"; return 2; }
            liveScale = std::stoull(argv[++i]);
        }
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
    if(live && (!haveFile || json || forceInteractive))
    {
        std::cerr << "error: --live requires a file and cannot be combined with --json/-i\n";
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
    std::streambuf *savedCout = nullptr;
    if(live)
        savedCout = std::cout.rdbuf(std::cerr.rdbuf());
    try
    {
        status = RunFile(engine, ctx, file, allowLua, keepGoing, quiet, rep);
    }
    catch(const std::exception &e)
    {
        std::cerr << "fatal: " << e.what() << "\n";
        status = 1;
    }

    if(status == 0 && live)
        status = RunLive(engine, ctx, liveRef, liveScale);
    if(savedCout)
        std::cout.rdbuf(savedCout);

    if(forceInteractive)
        RunInteractive(ctx);

    return status;
}
