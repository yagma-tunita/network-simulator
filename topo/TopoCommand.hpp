#pragma once

#include <string>
#include <vector>

struct Topology;

std::vector<std::string> Tokenize(const std::string &line);
void ExecuteCommand(Topology &topo, const std::vector<std::string> &tokens);
