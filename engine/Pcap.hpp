#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

struct PcapWriter
{
    std::FILE *fp = nullptr;
    uint64_t count = 0;

    PcapWriter() = default;
    PcapWriter(const PcapWriter &) = delete;
    PcapWriter &operator=(const PcapWriter &) = delete;
    ~PcapWriter();

    bool Open(const std::string &path);
    void Write(uint64_t t, const std::vector<uint8_t> &bytes);
    void Close();
    uint64_t Count() const { return count; }
};
