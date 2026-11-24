#include "OspfPacket.hpp"
#include "ByteIO.hpp"
#include "Md5.hpp"
#include "Sha.hpp"
#include <cstddef>
#include <algorithm>

using namespace ByteIO;

namespace
{
    std::size_t CryptoDigestLen(uint8_t alg)
    {
        if(alg == 1) return 20;
        if(alg == 2) return 32;
        return 16;
    }

    std::vector<uint8_t> CryptoDigest(const std::vector<uint8_t> &packet,
                                      const std::string &key, uint8_t alg)
    {
        if(alg == 0)
        {
            std::vector<uint8_t> input = packet;
            for(char c : key)
                input.push_back(uint8_t(c));
            std::array<uint8_t, 16> d = Md5(input);
            return std::vector<uint8_t>(d.begin(), d.end());
        }

        std::size_t L = CryptoDigestLen(alg);
        std::vector<uint8_t> ko;
        if(key.size() > L)
        {
            std::vector<uint8_t> k(key.begin(), key.end());
            if(alg == 1)
            {
                std::array<uint8_t, 20> h = Sha1(k);
                ko.assign(h.begin(), h.end());
            }
            else
            {
                std::array<uint8_t, 32> h = Sha256(k);
                ko.assign(h.begin(), h.end());
            }
        }
        else
        {
            ko.assign(key.begin(), key.end());
            ko.resize(L, 0);
        }

        std::vector<uint8_t> input = packet;
        static const uint8_t apadBytes[4] = { 0x87, 0x8f, 0xe1, 0xf3 };
        for(std::size_t i = 0; i < L; ++i)
            input.push_back(apadBytes[i % 4]);

        std::vector<uint8_t> ipad(64, 0x36);
        std::vector<uint8_t> opad(64, 0x5c);
        for(std::size_t i = 0; i < L; ++i)
        {
            ipad[i] ^= ko[i];
            opad[i] ^= ko[i];
        }

        std::vector<uint8_t> inner = ipad;
        inner.insert(inner.end(), input.begin(), input.end());

        std::vector<uint8_t> hash;
        if(alg == 1)
        {
            std::array<uint8_t, 20> h = Sha1(inner);
            hash.assign(h.begin(), h.end());
        }
        else
        {
            std::array<uint8_t, 32> h = Sha256(inner);
            hash.assign(h.begin(), h.end());
        }

        std::vector<uint8_t> outer = opad;
        outer.insert(outer.end(), hash.begin(), hash.end());
        if(alg == 1)
        {
            std::array<uint8_t, 20> h = Sha1(outer);
            return std::vector<uint8_t>(h.begin(), h.end());
        }
        std::array<uint8_t, 32> h = Sha256(outer);
        return std::vector<uint8_t>(h.begin(), h.end());
    }

    void AppendLsaHeader(std::vector<uint8_t> &buf, const OspfLsaHeader &h)
    {
        AppendU16(buf, h.age);
        AppendU8(buf, h.options);
        AppendU8(buf, h.type);
        AppendIpv4(buf, h.id);
        AppendIpv4(buf, h.advRouter);
        AppendU32(buf, h.seq);
        AppendU16(buf, h.checksum);
        AppendU16(buf, h.length);
    }

    OspfLsaHeader ReadLsaHeader(const std::vector<uint8_t> &buf, std::size_t off)
    {
        OspfLsaHeader h;
        h.age = ReadU16(buf, off);
        h.options = ReadU8(buf, off + 2);
        h.type = ReadU8(buf, off + 3);
        h.id = ReadIpv4(buf, off + 4);
        h.advRouter = ReadIpv4(buf, off + 8);
        h.seq = ReadU32(buf, off + 12);
        h.checksum = ReadU16(buf, off + 16);
        h.length = ReadU16(buf, off + 18);
        return h;
    }
}

uint16_t OspfPacket::LsaChecksum(const std::vector<uint8_t> &lsa)
{
    if(lsa.size() < 20)
        return 0;

    int c0 = 0;
    int c1 = 0;
    for(std::size_t i = 2; i < lsa.size(); ++i)
    {
        c0 = (c0 + lsa[i]) % 255;
        c1 = (c1 + c0) % 255;
    }

    int len = int(lsa.size());
    int x = ((len - 17) * c0 - c1) % 255;
    if(x <= 0)
        x += 255;
    int y = 510 - c0 - x;
    while(y > 255)
        y -= 255;

    return uint16_t((x << 8) | y);
}

uint16_t OspfPacket::PacketChecksum(const std::vector<uint8_t> &pkt)
{
    uint32_t sum = 0;
    std::size_t len = pkt.size();

    for(std::size_t i = 0; i < len; i += 2)
    {
        if(i == 12)
            continue;
        if(i >= 16 && i < 24)
            continue;

        uint16_t w = uint16_t(pkt[i]) << 8;
        if(i + 1 < len)
            w |= pkt[i + 1];
        sum += w;
    }

    while(sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return uint16_t(~sum);
}

std::vector<uint8_t> OspfPacket::EncodeLsa(const OspfLsa &lsa)
{
    std::vector<uint8_t> body;

    if(lsa.header.type == RouterLsa)
    {
        AppendU8(body, lsa.flags);
        AppendU8(body, 0);
        AppendU16(body, uint16_t(lsa.links.size()));
        for(const OspfRouterLink &l : lsa.links)
        {
            AppendIpv4(body, l.id);
            AppendIpv4(body, l.data);
            AppendU8(body, l.type);
            AppendU8(body, 0);
            AppendU16(body, l.metric);
        }
    }
    else if(lsa.header.type == NetworkLsa)
    {
        AppendIpv4(body, lsa.mask);
        for(const Ipv4 &r : lsa.attached)
            AppendIpv4(body, r);
    }
    else if(lsa.header.type == SummaryLsa)
    {
        AppendIpv4(body, lsa.mask);
        AppendU32(body, lsa.metric & 0x00FFFFFFu);
    }
    else if(lsa.header.type == SummaryAsbrLsa)
    {
        AppendU32(body, lsa.metric & 0x00FFFFFFu);
    }
    else if(lsa.header.type == ExternalLsa)
    {
        AppendIpv4(body, lsa.mask);
        AppendIpv4(body, lsa.forwarding);
        AppendU32(body, lsa.metric);
    }
    else if(lsa.header.type == NssaExternalLsa)
    {
        AppendIpv4(body, lsa.mask);
        AppendIpv4(body, lsa.forwarding);
        AppendU32(body, lsa.metric);
    }

    OspfLsaHeader h = lsa.header;
    h.length = uint16_t(20 + body.size());
    h.checksum = 0;

    std::vector<uint8_t> out;
    out.reserve(h.length);
    AppendLsaHeader(out, h);
    out.insert(out.end(), body.begin(), body.end());

    uint16_t c = LsaChecksum(out);
    out[16] = uint8_t(c >> 8);
    out[17] = uint8_t(c);
    return out;
}

bool OspfPacket::DecodeLsa(const std::vector<uint8_t> &buf, std::size_t &off,
                           std::size_t limit, OspfLsa &out)
{
    if(off + 20 > limit)
        return false;

    OspfLsaHeader h = ReadLsaHeader(buf, off);
    if(h.length < 20 || off + h.length > limit)
        return false;

    std::vector<uint8_t> bytes(buf.begin() + off, buf.begin() + off + h.length);
    uint16_t stored = ReadU16(bytes, 16);
    bytes[16] = 0;
    bytes[17] = 0;
    if(LsaChecksum(bytes) != stored)
        return false;

    out = OspfLsa();
    out.header = h;

    if(h.type == RouterLsa)
    {
        if(h.length < 24)
            return false;
        out.flags = bytes[20];
        uint16_t count = ReadU16(bytes, 22);
        if(std::size_t(24) + std::size_t(count) * 12 != h.length)
            return false;
        for(uint16_t i = 0; i < count; ++i)
        {
            std::size_t p = 24 + std::size_t(i) * 12;
            OspfRouterLink l;
            l.id = ReadIpv4(bytes, p);
            l.data = ReadIpv4(bytes, p + 4);
            l.type = ReadU8(bytes, p + 8);
            l.metric = ReadU16(bytes, p + 10);
            out.links.push_back(l);
        }
    }
    else if(h.type == NetworkLsa)
    {
        if(h.length < 24 || (h.length - 24) % 4 != 0)
            return false;
        out.mask = ReadIpv4(bytes, 20);
        for(std::size_t p = 24; p < h.length; p += 4)
            out.attached.push_back(ReadIpv4(bytes, p));
    }
    else if(h.type == SummaryLsa)
    {
        if(h.length < 28)
            return false;
        out.mask = ReadIpv4(bytes, 20);
        out.metric = ReadU32(bytes, 24) & 0x00FFFFFFu;
    }
    else if(h.type == SummaryAsbrLsa)
    {
        if(h.length < 24)
            return false;
        out.metric = ReadU32(bytes, 20) & 0x00FFFFFFu;
    }
    else if(h.type == ExternalLsa)
    {
        if(h.length < 32)
            return false;
        out.mask = ReadIpv4(bytes, 20);
        out.forwarding = ReadIpv4(bytes, 24);
        out.metric = ReadU32(bytes, 28);
    }
    else if(h.type == NssaExternalLsa)
    {
        if(h.length < 32)
            return false;
        out.mask = ReadIpv4(bytes, 20);
        out.forwarding = ReadIpv4(bytes, 24);
        out.metric = ReadU32(bytes, 28);
    }

    off += h.length;
    return true;
}

std::vector<uint8_t> OspfPacket::ToBytes() const
{
    std::vector<uint8_t> payload;

    if(type == Hello)
    {
        AppendIpv4(payload, helloMask);
        AppendU16(payload, helloInterval);
        AppendU8(payload, helloOptions);
        AppendU8(payload, helloPriority);
        AppendU32(payload, deadInterval);
        AppendIpv4(payload, dr);
        AppendIpv4(payload, bdr);
        for(const Ipv4 &n : neighbors)
            AppendIpv4(payload, n);
    }
    else if(type == DatabaseDescription)
    {
        AppendU16(payload, ddMtu);
        AppendU8(payload, ddOptions);
        AppendU8(payload, ddFlags);
        AppendU32(payload, ddSeq);
        for(const OspfLsaHeader &h : ddHeaders)
            AppendLsaHeader(payload, h);
    }
    else if(type == LinkStateRequest)
    {
        for(const OspfLsrItem &r : requests)
        {
            AppendU32(payload, r.type);
            AppendIpv4(payload, r.id);
            AppendIpv4(payload, r.advRouter);
        }
    }
    else if(type == LinkStateUpdate)
    {
        AppendU32(payload, uint32_t(lsas.size()));
        for(const OspfLsa &l : lsas)
        {
            std::vector<uint8_t> b = EncodeLsa(l);
            payload.insert(payload.end(), b.begin(), b.end());
        }
    }
    else if(type == LinkStateAck)
    {
        for(const OspfLsaHeader &h : acks)
            AppendLsaHeader(payload, h);
    }

    std::vector<uint8_t> out;
    out.reserve(24 + payload.size());

    AppendU8(out, version);
    AppendU8(out, type);
    AppendU16(out, uint16_t(24 + payload.size()));
    AppendIpv4(out, routerId);
    AppendIpv4(out, areaId);
    AppendU16(out, 0);
    AppendU16(out, authType);
    for(std::size_t i = 0; i < 8; ++i)
        out.push_back(auth[i]);

    out.insert(out.end(), payload.begin(), payload.end());

    if(authType == AuthMd5)
    {
        if(digestAlg > 2)
            return {};
        if(digestAlg == 0 && md5Key.size() != 16)
            return {};
        if(digestAlg != 0 && md5Key.empty())
            return {};
        std::size_t digestLen = CryptoDigestLen(digestAlg);
        out[12] = 0;
        out[13] = 0;
        out[16] = 0;
        out[17] = 0;
        out[18] = authKeyId;
        out[19] = uint8_t(digestLen);
        out[20] = uint8_t(cryptoSeq >> 24);
        out[21] = uint8_t(cryptoSeq >> 16);
        out[22] = uint8_t(cryptoSeq >> 8);
        out[23] = uint8_t(cryptoSeq);

        std::vector<uint8_t> digest = CryptoDigest(out, md5Key, digestAlg);
        out.insert(out.end(), digest.begin(), digest.end());
        return out;
    }

    uint16_t c = PacketChecksum(out);
    out[12] = uint8_t(c >> 8);
    out[13] = uint8_t(c);

    return out;
}

bool OspfPacket::TryFromBytes(const std::vector<uint8_t> &buf, OspfPacket &out,
                              const std::string &md5Key, uint8_t digestAlg)
{
    if(buf.size() < 24)
        return false;
    if(ReadU8(buf, 0) != 2)
        return false;

    uint16_t len = ReadU16(buf, 2);
    if(len < 24 || len > buf.size())
        return false;

    uint16_t at = ReadU16(buf, 14);
    if(at > AuthMd5)
        return false;

    std::vector<uint8_t> data(buf.begin(), buf.begin() + len);
    uint16_t stored = ReadU16(data, 12);

    if(at == AuthMd5)
    {
        if(digestAlg > 2)
            return false;
        if(digestAlg == 0 && md5Key.size() != 16)
            return false;
        if(digestAlg != 0 && md5Key.empty())
            return false;
        std::size_t digestLen = CryptoDigestLen(digestAlg);
        if(buf.size() < std::size_t(len) + digestLen || data[19] != digestLen)
            return false;
        std::vector<uint8_t> calc = CryptoDigest(data, md5Key, digestAlg);
        for(std::size_t i = 0; i < digestLen; ++i)
            if(calc[i] != buf[len + i])
                return false;
    }
    else if(PacketChecksum(data) != stored)
    {
        return false;
    }

    out = OspfPacket();
    out.version = 2;
    out.type = ReadU8(data, 1);
    out.length = len;
    out.routerId = ReadIpv4(data, 4);
    out.areaId = ReadIpv4(data, 8);
    out.checksum = stored;
    out.authType = at;
    for(std::size_t i = 0; i < 8; ++i)
        out.auth[i] = data[16 + i];
    if(at == AuthMd5)
    {
        out.authKeyId = data[18];
        out.cryptoSeq = ReadU32(data, 20);
        out.md5Key = md5Key;
        out.digestAlg = digestAlg;
    }

    if(out.type == Hello)
    {
        if(len < 44 || (len - 44) % 4 != 0)
            return false;
        out.helloMask = ReadIpv4(data, 24);
        out.helloInterval = ReadU16(data, 28);
        out.helloOptions = ReadU8(data, 30);
        out.helloPriority = ReadU8(data, 31);
        out.deadInterval = ReadU32(data, 32);
        out.dr = ReadIpv4(data, 36);
        out.bdr = ReadIpv4(data, 40);
        for(std::size_t p = 44; p < len; p += 4)
            out.neighbors.push_back(ReadIpv4(data, p));
    }
    else if(out.type == DatabaseDescription)
    {
        if(len < 32 || (len - 32) % 20 != 0)
            return false;
        out.ddMtu = ReadU16(data, 24);
        out.ddOptions = ReadU8(data, 26);
        out.ddFlags = ReadU8(data, 27);
        out.ddSeq = ReadU32(data, 28);
        for(std::size_t p = 32; p < len; p += 20)
            out.ddHeaders.push_back(ReadLsaHeader(data, p));
    }
    else if(out.type == LinkStateRequest)
    {
        if((len - 24) % 12 != 0)
            return false;
        for(std::size_t p = 24; p < len; p += 12)
        {
            OspfLsrItem r;
            r.type = ReadU32(data, p);
            r.id = ReadIpv4(data, p + 4);
            r.advRouter = ReadIpv4(data, p + 8);
            out.requests.push_back(r);
        }
    }
    else if(out.type == LinkStateUpdate)
    {
        if(len < 28)
            return false;
        uint32_t count = ReadU32(data, 24);
        if(count > 4096)
            return false;
        std::size_t off = 28;
        for(uint32_t i = 0; i < count; ++i)
        {
            OspfLsa l;
            if(!DecodeLsa(data, off, len, l))
                return false;
            out.lsas.push_back(l);
        }
        if(off != len)
            return false;
    }
    else if(out.type == LinkStateAck)
    {
        if((len - 24) % 20 != 0)
            return false;
        for(std::size_t p = 24; p < len; p += 20)
            out.acks.push_back(ReadLsaHeader(data, p));
    }
    else
    {
        return false;
    }

    return true;
}
