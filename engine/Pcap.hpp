#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

struct PcapWriter
{
    static constexpr uint64_t kDefaultMaxFrames = 2000000;
    static constexpr uint64_t kDefaultMaxBytes = 256ull * 1024 * 1024;

    std::FILE *fp = nullptr;
    uint64_t count = 0;
    uint64_t bytes = 0;
    uint64_t maxFrames = kDefaultMaxFrames;
    uint64_t maxBytes = kDefaultMaxBytes;
    bool overflow = false;

    PcapWriter() = default;
    PcapWriter(const PcapWriter &) = delete;
    PcapWriter &operator=(const PcapWriter &) = delete;
    ~PcapWriter();

    bool Open(const std::string &path);
    void Write(uint64_t t, const std::vector<uint8_t> &bytes);
    void Close();
    uint64_t Count() const { return count; }
};
