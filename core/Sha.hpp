#pragma once

#include <array>
#include <cstdint>
#include <vector>

std::array<uint8_t, 20> Sha1(const std::vector<uint8_t> &data);
std::array<uint8_t, 32> Sha256(const std::vector<uint8_t> &data);
