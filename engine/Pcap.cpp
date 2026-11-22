#include "Pcap.hpp"

namespace
{
    void Put16(std::FILE *fp, uint16_t v)
    {
        uint8_t b[2] = { uint8_t(v), uint8_t(v >> 8) };
        std::fwrite(b, 1, 2, fp);
    }

    void Put32(std::FILE *fp, uint32_t v)
    {
        uint8_t b[4] = { uint8_t(v), uint8_t(v >> 8), uint8_t(v >> 16), uint8_t(v >> 24) };
        std::fwrite(b, 1, 4, fp);
    }
}

PcapWriter::~PcapWriter()
{
    Close();
}

bool PcapWriter::Open(const std::string &path)
{
    Close();
    fp = std::fopen(path.c_str(), "wb");
    if(!fp) return false;

    Put32(fp, 0xA1B2C3D4u);
    Put16(fp, 2);
    Put16(fp, 4);
    Put32(fp, 0);
    Put32(fp, 0);
    Put32(fp, 65535);
    Put32(fp, 1);

    count = 0;
    return true;
}

void PcapWriter::Write(uint64_t t, const std::vector<uint8_t> &bytes)
{
    if(!fp) return;

    Put32(fp, uint32_t(t));
    Put32(fp, 0);
    Put32(fp, uint32_t(bytes.size()));
    Put32(fp, uint32_t(bytes.size()));
    if(!bytes.empty())
        std::fwrite(bytes.data(), 1, bytes.size(), fp);

    ++count;
}

void PcapWriter::Close()
{
    if(fp)
    {
        std::fclose(fp);
        fp = nullptr;
    }
}
