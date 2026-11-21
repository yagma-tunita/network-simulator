#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

#include "Ipv4.hpp"
#include "Mac.hpp"


namespace ByteIO
{
    inline void AppendU8(std::vector<uint8_t> &buf, uint8_t v)
    {
        buf.push_back(v);
    }

    inline void AppendU16(std::vector<uint8_t> &buf, uint16_t v)
    {
        buf.push_back(uint8_t(v >> 8));
        buf.push_back(uint8_t(v));
    }

    inline void AppendIpv4(std::vector<uint8_t> &buf, const Ipv4 &ip)
    {
        buf.push_back(uint8_t(ip.value >> 24));
        buf.push_back(uint8_t(ip.value >> 16));
        buf.push_back(uint8_t(ip.value >> 8));
        buf.push_back(uint8_t(ip.value));
    }

    inline void AppendMac(std::vector<uint8_t> &buf, const Mac &mac)
    {
        for (std::size_t i = 0; i < 6; i++)
            buf.push_back(mac.bytes[i]);
    }

    inline uint8_t ReadU8(const std::vector<uint8_t> &buf, std::size_t off)
    {
        return buf[off];
    }

    inline uint16_t ReadU16(const std::vector<uint8_t> &buf, std::size_t off)
    {
        return uint16_t((uint16_t(buf[off]) << 8) | uint16_t(buf[off + 1]));
    }

    inline Ipv4 ReadIpv4(const std::vector<uint8_t> &buf, std::size_t off)
    {
        uint32_t v = (uint32_t(buf[off])       << 24)
                   | (uint32_t(buf[off + 1])   << 16)
                   | (uint32_t(buf[off + 2])   << 8)
                   |  uint32_t(buf[off + 3]);
        return Ipv4(v);
    }

    inline Mac ReadMac(const std::vector<uint8_t> &buf, std::size_t off)
    {
        Mac mac;
        for (std::size_t i = 0; i < 6; i++)
            mac.bytes[i] = buf[off + i];
        return mac;
    }
}
