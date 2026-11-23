#pragma once

#include <string>

struct Topology;

bool ExportDot(const Topology &topo, const std::string &path, std::string &err);
bool ExportSvg(const Topology &topo, const std::string &path, std::string &err);
