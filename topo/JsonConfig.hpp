#pragma once

#include <string>
#include <vector>
#include <map>
#include <utility>

struct Topology;

using LayoutMap = std::map<std::string, std::pair<int, int>>;

bool SaveTopologyJson(const Topology &topo, const std::string &path,
                      const LayoutMap &layout, std::string &err);
bool ParseConfigJson(const std::string &path, std::vector<std::string> &cmds,
                     LayoutMap &layout, std::string &err);
