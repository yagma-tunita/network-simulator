#pragma once

#include <string>
#include <memory>

struct Engine;
struct Topology;
struct PcapWriter;

struct CommandContext
{
    Engine *engine = nullptr;
    Topology *topo = nullptr;
    bool quit = false;
    bool quiet = false;
    std::shared_ptr<PcapWriter> pcap;
};

void RunScriptLine(CommandContext &ctx, const std::string &line);
void PrintHelp();
