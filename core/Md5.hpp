#pragma once

#include <array>
#include <cstdint>
#include <vector>

std::array<uint8_t, 16> Md5(const std::vector<uint8_t> &data);
