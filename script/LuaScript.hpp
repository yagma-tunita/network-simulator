#pragma once

#include <string>

struct Engine;
struct Topology;

bool RunLuaFile(Engine &engine, Topology &topo, const std::string &path, std::string &err);
