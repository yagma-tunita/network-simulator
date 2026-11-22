#include "../engine/Engine.hpp"
#include "../topo/Topology.hpp"
#include "../topo/CommandRunner.hpp"
#include "../topo/JsonConfig.hpp"
#include "Version.hpp"
#include "webserver.hpp"

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstddef>

#ifdef HAVE_LUA
#include "../script/LuaScript.hpp"
#endif

static bool EndsWith(const std::string &s, const std::string &suffix)
{
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
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
        << "      --serve [port]  serve the loopback JSON API (default 8080)\n"
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
        << "  echo demo | " << prog << "\n";
}

static void RunInteractive(CommandContext &ctx)
{
    std::cout << YANAS_NAME << " " << YANAS_VERSION << " - type 'help' (try 'demo')\n";
    std::string line;
    while (!ctx.quit)
    {
        std::cout << "> " << std::flush;
        if (!std::getline(std::cin, line))
            break;
        try
        {
            RunScriptLine(ctx, line);
        }
        catch (const std::exception &e)
        {
            std::cerr << "error: " << e.what() << "\n";
        }
    }
}

static int RunFile(Engine &engine, CommandContext &ctx,
                   const std::string &file, bool allowLua,
                   bool keepGoing, bool quiet)
{
    if (EndsWith(file, ".lua"))
    {
        if (!allowLua)
        {
            std::cerr << "error: Lua disabled by --no-lua\n";
            return 1;
        }
#ifdef HAVE_LUA
        std::string err;
        if (!RunLuaFile(engine, *ctx.topo, file, err))
        {
            std::cerr << "lua: " << err << "\n";
            return 1;
        }
        if (!quiet) std::cout << "done; now=" << engine.Now() << "\n";
        return 0;
#else
        std::cerr << "error: Lua support not built\n";
        return 1;
#endif
    }

    if (EndsWith(file, ".yn") || EndsWith(file, ".json"))
    {
        std::vector<std::string> cmds;
        LayoutMap layout;
        std::string err;
        if (!ParseConfigJson(file, cmds, layout, err))
        {
            std::cerr << "error: " << err << "\n";
            return 1;
        }

        int status = 0;
        for (std::size_t i = 0; i < cmds.size(); ++i)
        {
            try
            {
                RunScriptLine(ctx, cmds[i]);
            }
            catch (const std::exception &e)
            {
                std::cerr << file << ":" << (i + 1) << ": error: " << e.what() << "\n";
                status = 1;
                if (!keepGoing) break;
            }
        }
        if (!quiet)
            std::cout << "loaded " << cmds.size() << " commands from " << file
                      << "; now=" << engine.Now() << "\n";
        return status;
    }

    std::ifstream in(file);
    if (!in)
    {
        std::cerr << "error: cannot open '" << file << "'\n";
        return 1;
    }

    int status = 0;
    std::string line;
    int lineNo = 0;
    while (std::getline(in, line))
    {
        ++lineNo;
        if (ctx.quit) break;
        try
        {
            RunScriptLine(ctx, line);
        }
        catch (const std::exception &e)
        {
            std::cerr << file << ":" << lineNo << ": error: " << e.what() << "\n";
            status = 1;
            if (!keepGoing) break;
        }
    }

    if (!quiet) std::cout << "done; now=" << engine.Now() << "\n";
    return status;
}

int main(int argc, char **argv)
{
    Engine engine;
    Topology topo;
    topo.SetEngine(&engine);

    CommandContext ctx;
    ctx.engine = &engine;
    ctx.topo = &topo;

    std::string file;
    bool haveFile = false;
    bool quiet = false, keepGoing = false, allowLua = true, forceInteractive = false;

    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "-h" || a == "--help")
        {
            PrintUsage(argv[0]);
            return 0;
        }
        else if (a == "--version")
        {
            std::cout << YANAS_NAME << " " << YANAS_VERSION << "\n";
            return 0;
        }
        else if (a == "--features")
        {
            std::cout << "core";
#ifdef HAVE_LUA
            std::cout << " lua";
#endif
            std::cout << "\n";
            return 0;
        }
        else if (a == "-q" || a == "--quiet")
        {
            quiet = true;
        }
        else if (a == "--keep-going")
        {
            keepGoing = true;
        }
        else if (a == "--no-lua")
        {
            allowLua = false;
        }
        else if (a == "-i" || a == "--interactive")
        {
            forceInteractive = true;
        }
        else if (a == "--serve")
        {
            int port = 8080;
            if (i + 1 < argc && argv[i + 1][0] != '-')
            {
                try
                {
                    port = std::stoi(argv[++i]);
                }
                catch (...)
                {
                    std::cerr << "error: bad port\n";
                    PrintUsage(argv[0]);
                    return 2;
                }
            }
            RunWebServer(engine, topo, port);
            return 0;
        }
        else if (a == "-f" || a == "--file" || a == "--script" || a == "--scene")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "error: " << a << " needs a path\n";
                PrintUsage(argv[0]);
                return 2;
            }
            file = argv[++i];
            haveFile = true;
        }
        else if (!a.empty() && a[0] == '-')
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

    ctx.quiet = quiet;

    if (!haveFile)
    {
        RunInteractive(ctx);
        return 0;
    }

    int status = 0;
    try
    {
        status = RunFile(engine, ctx, file, allowLua, keepGoing, quiet);
    }
    catch (const std::exception &e)
    {
        std::cerr << "fatal: " << e.what() << "\n";
        status = 1;
    }

    if (forceInteractive)
        RunInteractive(ctx);

    return status;
}
