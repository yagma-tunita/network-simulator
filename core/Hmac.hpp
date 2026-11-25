#pragma once

#include <cstdint>
#include <vector>

std::vector<uint8_t> HmacMd5(const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &data);
std::vector<uint8_t> HmacSha1(const std::vector<uint8_t> &key,
                              const std::vector<uint8_t> &data);
std::vector<uint8_t> HmacSha256(const std::vector<uint8_t> &key,
                                const std::vector<uint8_t> &data);
