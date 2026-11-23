#pragma once

#include "Ipv4.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>

struct OspfLsaHeader
{
    uint16_t age = 0;
    uint8_t options = 0x02;
    uint8_t type = 1;
    Ipv4 id;
    Ipv4 advRouter;
    uint32_t seq = 0x80000001u;
    uint16_t checksum = 0;
    uint16_t length = 20;
};

struct OspfRouterLink
{
    Ipv4 id;
    Ipv4 data;
    uint8_t type = 1;
    uint16_t metric = 1;
};

struct OspfLsa
{
    OspfLsaHeader header;
    uint8_t flags = 0;
    std::vector<OspfRouterLink> links;
    Ipv4 mask;
    std::vector<Ipv4> attached;
};

struct OspfLsrItem
{
    uint32_t type = 0;
    Ipv4 id;
    Ipv4 advRouter;
};

struct OspfPacket
{
    enum Type : uint8_t
    {
        Hello = 1,
        DatabaseDescription = 2,
        LinkStateRequest = 3,
        LinkStateUpdate = 4,
        LinkStateAck = 5
    };

    enum LsaType : uint8_t
    {
        RouterLsa = 1,
        NetworkLsa = 2
    };

    enum AuthType : uint16_t
    {
        AuthNone = 0,
        AuthSimple = 1
    };

    uint8_t version = 2;
    uint8_t type = 0;
    uint16_t length = 0;
    Ipv4 routerId;
    Ipv4 areaId;
    uint16_t checksum = 0;
    uint16_t authType = AuthNone;
    uint8_t auth[8] = {};

    Ipv4 helloMask;
    uint16_t helloInterval = 10;
    uint8_t helloOptions = 0x02;
    uint8_t helloPriority = 1;
    uint32_t deadInterval = 40;
    Ipv4 dr;
    Ipv4 bdr;
    std::vector<Ipv4> neighbors;

    uint16_t ddMtu = 1500;
    uint8_t ddOptions = 0x02;
    uint8_t ddFlags = 0;
    uint32_t ddSeq = 0;
    std::vector<OspfLsaHeader> ddHeaders;

    std::vector<OspfLsrItem> requests;

    std::vector<OspfLsa> lsas;

    std::vector<OspfLsaHeader> acks;

    std::vector<uint8_t> ToBytes() const;
    static bool TryFromBytes(const std::vector<uint8_t> &buf, OspfPacket &out);

    static uint16_t LsaChecksum(const std::vector<uint8_t> &lsa);
    static uint16_t PacketChecksum(const std::vector<uint8_t> &pkt);
    static std::vector<uint8_t> EncodeLsa(const OspfLsa &lsa);
    static bool DecodeLsa(const std::vector<uint8_t> &buf, std::size_t &off,
                          std::size_t limit, OspfLsa &out);
};
