#include "DnsMessage.hpp"
#include "ByteIO.hpp"
#include "Hmac.hpp"
#include <cstddef>
#include <cctype>
#include <algorithm>

using namespace ByteIO;

namespace
{
    bool AppendName(std::vector<uint8_t> &buf, const std::string &name)
    {
        if (name.empty() || name.size() > 253)
            return false;

        std::size_t start = 0;
        while (start < name.size())
        {
            std::size_t dot = name.find('.', start);
            std::size_t end = (dot == std::string::npos) ? name.size() : dot;
            std::size_t len = end - start;
            if (len == 0 || len > 63)
                return false;

            buf.push_back(uint8_t(len));
            for (std::size_t i = start; i < end; ++i)
                buf.push_back(uint8_t(name[i]));

            if (dot == std::string::npos)
                break;
            start = dot + 1;
        }

        buf.push_back(0);
        return true;
    }

    bool ReadName(const std::vector<uint8_t> &buf, std::size_t &off, std::string &out)
    {
        std::size_t pos = off;
        std::size_t resume = 0;
        bool jumped = false;
        int guard = 0;

        while (true)
        {
            if (pos >= buf.size())
                return false;

            uint8_t len = buf[pos];
            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= buf.size())
                    return false;
                std::size_t ptr = (std::size_t(len & 0x3F) << 8) | buf[pos + 1];
                if (!jumped)
                {
                    resume = pos + 2;
                    jumped = true;
                }
                pos = ptr;
                if (++guard > 64)
                    return false;
                continue;
            }
            if (len == 0)
            {
                ++pos;
                break;
            }
            if (len > 63 || pos + 1 + len > buf.size())
                return false;

            if (!out.empty())
                out.push_back('.');
            out.append(reinterpret_cast<const char *>(&buf[pos + 1]), len);
            pos += 1 + len;

            if (++guard > 128)
                return false;
        }

        off = jumped ? resume : pos;
        return true;
    }

    std::string CanonicalTsigAlgorithm(const std::string &algorithm)
    {
        std::string out;
        out.reserve(algorithm.size() + 1);
        for(char c : algorithm)
            out.push_back(char(std::tolower(static_cast<unsigned char>(c))));
        if(!out.empty() && out.back() != '.')
            out.push_back('.');
        return out;
    }

    std::vector<uint8_t> TsigMacInput(const DnsMessage &msg,
                                      const DnsTsig &tsig,
                                      const std::vector<uint8_t> *requestMac)
    {
        DnsMessage wireMsg = msg;
        wireMsg.tsig.present = false;
        std::vector<uint8_t> wire = wireMsg.ToBytes();
        if(wire.empty())
            return {};

        std::vector<uint8_t> data;
        if(requestMac)
        {
            AppendU16(data, uint16_t(requestMac->size()));
            data.insert(data.end(), requestMac->begin(), requestMac->end());
        }
        data.insert(data.end(), wire.begin(), wire.end());

        if(!AppendName(data, tsig.keyName))
            return {};
        AppendU16(data, 255);
        AppendU32(data, 0);
        if(!AppendName(data, CanonicalTsigAlgorithm(tsig.algorithm)))
            return {};
        for(int shift = 40; shift >= 0; shift -= 8)
            data.push_back(uint8_t((tsig.timeSigned >> shift) & 0xFF));
        AppendU16(data, tsig.fudge);
        AppendU16(data, tsig.error);
        AppendU16(data, uint16_t(tsig.other.size()));
        data.insert(data.end(), tsig.other.begin(), tsig.other.end());
        return data;
    }

    std::vector<uint8_t> TsigHash(const std::string &algorithm,
                                  const std::string &secret,
                                  const std::vector<uint8_t> &data)
    {
        std::string alg = CanonicalTsigAlgorithm(algorithm);
        std::vector<uint8_t> key(secret.begin(), secret.end());
        if(alg == "hmac-md5.sig-alg.reg.int.")
            return HmacMd5(key, data);
        if(alg == "hmac-sha1.")
            return HmacSha1(key, data);
        if(alg == "hmac-sha256.")
            return HmacSha256(key, data);
        return {};
    }
}

std::vector<uint8_t> DnsMessage::ToBytes() const
{
    std::vector<uint8_t> buf;
    buf.reserve(64 + (questions.size() + answers.size() +
                      authority.size() + additional.size()) * 16 +
                      (hasOpt ? 11 : 0));

    AppendU16(buf, id);
    AppendU16(buf, flags);
    AppendU16(buf, uint16_t(questions.size()));
    AppendU16(buf, uint16_t(answers.size()));
    AppendU16(buf, uint16_t(authority.size()));
    AppendU16(buf, uint16_t(additional.size() + (hasOpt ? 1 : 0) +
                            (tsig.present ? 1 : 0)));

    for (const DnsQuestion &q : questions)
    {
        if (!AppendName(buf, q.name))
            return {};
        AppendU16(buf, q.qtype);
        AppendU16(buf, q.qclass);
    }

    auto appendRecords = [&](const std::vector<DnsAnswer> &records) -> bool
    {
        for (const DnsAnswer &a : records)
        {
            if (!AppendName(buf, a.name))
                return false;
            AppendU16(buf, a.type);
            AppendU16(buf, a.cls);
            AppendU32(buf, a.ttl);

            if (a.noRdata)
            {
                AppendU16(buf, 0);
            }
            else if (a.type == DnsMessage::kTypeA)
            {
                AppendU16(buf, 4);
                AppendIpv4(buf, a.ip);
            }
            else if (a.type == DnsMessage::kTypeAaaa)
            {
                AppendU16(buf, 16);
                buf.insert(buf.end(), a.ip6.bytes.begin(), a.ip6.bytes.end());
            }
            else if (a.type == DnsMessage::kTypeCname ||
                     a.type == DnsMessage::kTypePtr ||
                     a.type == DnsMessage::kTypeNs)
            {
                std::vector<uint8_t> rdata;
                if (!AppendName(rdata, a.target))
                    return false;
                AppendU16(buf, uint16_t(rdata.size()));
                buf.insert(buf.end(), rdata.begin(), rdata.end());
            }
            else if (a.type == DnsMessage::kTypeMx)
            {
                std::vector<uint8_t> rdata;
                AppendU16(rdata, a.preference);
                if (!AppendName(rdata, a.target))
                    return false;
                AppendU16(buf, uint16_t(rdata.size()));
                buf.insert(buf.end(), rdata.begin(), rdata.end());
            }
            else if (a.type == DnsMessage::kTypeSoa)
            {
                std::vector<uint8_t> rdata;
                if (!AppendName(rdata, a.mname) ||
                    !AppendName(rdata, a.rname))
                    return false;
                AppendU32(rdata, a.serial);
                AppendU32(rdata, a.refresh);
                AppendU32(rdata, a.retry);
                AppendU32(rdata, a.expire);
                AppendU32(rdata, a.minimum);
                AppendU16(buf, uint16_t(rdata.size()));
                buf.insert(buf.end(), rdata.begin(), rdata.end());
            }
            else
            {
                AppendU16(buf, 0);
            }
        }
        return true;
    };

    if (!appendRecords(answers) || !appendRecords(authority) ||
        !appendRecords(additional))
        return {};

    if (hasOpt)
    {
        buf.push_back(0);
        AppendU16(buf, DnsMessage::kTypeOpt);
        AppendU16(buf, optUdpSize);
        AppendU32(buf, (uint32_t(optVersion) << 16) | optFlags);
        AppendU16(buf, 0);
    }

    if (tsig.present)
    {
        if (!AppendName(buf, tsig.keyName))
            return {};
        AppendU16(buf, DnsMessage::kTypeTsig);
        AppendU16(buf, 255);
        AppendU32(buf, 0);

        std::vector<uint8_t> rdata;
        if (!AppendName(rdata, tsig.algorithm))
            return {};
        for (int shift = 40; shift >= 0; shift -= 8)
            rdata.push_back(uint8_t((tsig.timeSigned >> shift) & 0xFF));
        AppendU16(rdata, tsig.fudge);
        AppendU16(rdata, uint16_t(tsig.mac.size()));
        rdata.insert(rdata.end(), tsig.mac.begin(), tsig.mac.end());
        AppendU16(rdata, tsig.originalId);
        AppendU16(rdata, tsig.error);
        AppendU16(rdata, uint16_t(tsig.other.size()));
        rdata.insert(rdata.end(), tsig.other.begin(), tsig.other.end());
        AppendU16(buf, uint16_t(rdata.size()));
        buf.insert(buf.end(), rdata.begin(), rdata.end());
    }

    return buf;
}

bool DnsMessage::TryFromBytes(const std::vector<uint8_t> &buf, DnsMessage &out)
{
    if (buf.size() < 12)
        return false;

    out = DnsMessage();
    out.id = ReadU16(buf, 0);
    out.flags = ReadU16(buf, 2);
    uint16_t qd = ReadU16(buf, 4);
    uint16_t an = ReadU16(buf, 6);
    uint16_t ns = ReadU16(buf, 8);
    uint16_t ar = ReadU16(buf, 10);

    if (qd > 64 || an > 256 || ns > 64 || ar > 64)
        return false;

    std::size_t off = 12;

    for (uint16_t i = 0; i < qd; ++i)
    {
        DnsQuestion q;
        if (!ReadName(buf, off, q.name))
            return false;
        if (off + 4 > buf.size())
            return false;
        q.qtype = ReadU16(buf, off);
        q.qclass = ReadU16(buf, off + 2);
        off += 4;
        out.questions.push_back(q);
    }

    auto readRecord = [&](DnsAnswer &a) -> bool
    {
        if (!ReadName(buf, off, a.name))
            return false;
        if (off + 10 > buf.size())
            return false;
        a.type = ReadU16(buf, off);
        a.cls = ReadU16(buf, off + 2);
        a.ttl = ReadU32(buf, off + 4);
        uint16_t rdlen = ReadU16(buf, off + 8);
        off += 10;
        if (off + rdlen > buf.size())
            return false;
        std::size_t rdata = off;
        a.noRdata = (rdlen == 0);
        if (a.type == DnsMessage::kTypeA && rdlen == 4)
            a.ip = ReadIpv4(buf, off);
        else if (a.type == DnsMessage::kTypeAaaa && rdlen == 16)
        {
            for(std::size_t i = 0; i < 16; ++i)
                a.ip6.bytes[i] = buf[rdata + i];
        }
        else if (a.type == DnsMessage::kTypeCname ||
                 a.type == DnsMessage::kTypePtr ||
                 a.type == DnsMessage::kTypeNs)
        {
            std::size_t nameOff = rdata;
            if (!ReadName(buf, nameOff, a.target))
                return false;
        }
        else if (a.type == DnsMessage::kTypeMx && rdlen >= 3)
        {
            a.preference = ReadU16(buf, rdata);
            std::size_t nameOff = rdata + 2;
            if (!ReadName(buf, nameOff, a.target))
                return false;
        }
        else if (a.type == DnsMessage::kTypeSoa)
        {
            std::size_t p = rdata;
            if (!ReadName(buf, p, a.mname))
                return false;
            if (!ReadName(buf, p, a.rname))
                return false;
            if (p + 20 > rdata + rdlen || p + 20 > buf.size())
                return false;
            a.serial = ReadU32(buf, p);
            a.refresh = ReadU32(buf, p + 4);
            a.retry = ReadU32(buf, p + 8);
            a.expire = ReadU32(buf, p + 12);
            a.minimum = ReadU32(buf, p + 16);
        }
        else if (a.type == DnsMessage::kTypeTsig)
        {
            std::size_t end = rdata + rdlen;
            std::size_t p = rdata;
            if (!ReadName(buf, p, a.tsigAlgorithm))
                return false;
            if (p + 8 > end || p + 8 > buf.size())
                return false;
            a.tsigTime = 0;
            for (int i = 0; i < 6; ++i)
                a.tsigTime = (a.tsigTime << 8) | buf[p + i];
            a.tsigFudge = ReadU16(buf, p + 6);
            uint16_t macLen = ReadU16(buf, p + 8);
            p += 10;
            if (p + macLen + 6 > end || p + macLen + 6 > buf.size())
                return false;
            a.tsigMac.assign(buf.begin() + p, buf.begin() + p + macLen);
            p += macLen;
            a.tsigOriginalId = ReadU16(buf, p);
            a.tsigError = ReadU16(buf, p + 2);
            uint16_t otherLen = ReadU16(buf, p + 4);
            p += 6;
            if (p + otherLen > end || p + otherLen > buf.size())
                return false;
            a.tsigOther.assign(buf.begin() + p, buf.begin() + p + otherLen);
        }
        off = rdata + rdlen;
        return true;
    };

    for (uint16_t i = 0; i < an; ++i)
    {
        DnsAnswer a;
        if (!readRecord(a))
            return false;
        out.answers.push_back(a);
    }

    for (uint16_t i = 0; i < ns; ++i)
    {
        DnsAnswer a;
        if (!readRecord(a))
            return false;
        out.authority.push_back(a);
    }

    for (uint16_t i = 0; i < ar; ++i)
    {
        DnsAnswer a;
        if (!readRecord(a))
            return false;
        if (a.type == DnsMessage::kTypeOpt)
        {
            out.hasOpt = true;
            out.optUdpSize = a.cls;
            out.optVersion = uint8_t(a.ttl >> 16);
            out.optFlags = uint16_t(a.ttl & 0xFFFFu);
        }
        else if (a.type == DnsMessage::kTypeTsig)
        {
            out.tsig.present = true;
            out.tsig.keyName = a.name;
            out.tsig.algorithm = a.tsigAlgorithm;
            out.tsig.timeSigned = a.tsigTime;
            out.tsig.fudge = a.tsigFudge;
            out.tsig.mac = a.tsigMac;
            out.tsig.originalId = a.tsigOriginalId;
            out.tsig.error = a.tsigError;
            out.tsig.other = a.tsigOther;
        }
        else
        {
            out.additional.push_back(a);
        }
    }

    return true;
}

bool DnsMessage::TsigAlgorithmValid(const std::string &algorithm)
{
    std::string alg = CanonicalTsigAlgorithm(algorithm);
    return alg == "hmac-md5.sig-alg.reg.int." || alg == "hmac-sha1." ||
           alg == "hmac-sha256.";
}

bool DnsMessage::SignTsig(const std::string &secret,
                          const std::vector<uint8_t> *requestMac)
{
    if(!tsig.present || !TsigAlgorithmValid(tsig.algorithm))
        return false;
    std::vector<uint8_t> data = TsigMacInput(*this, tsig, requestMac);
    if(data.empty())
        return false;
    std::vector<uint8_t> mac = TsigHash(tsig.algorithm, secret, data);
    if(mac.empty())
        return false;
    tsig.mac = mac;
    return true;
}

bool DnsMessage::VerifyTsig(const std::string &secret,
                            const std::vector<uint8_t> *requestMac) const
{
    if(!tsig.present || tsig.mac.empty() ||
       !TsigAlgorithmValid(tsig.algorithm))
        return false;
    std::vector<uint8_t> data = TsigMacInput(*this, tsig, requestMac);
    if(data.empty())
        return false;
    std::vector<uint8_t> expected = TsigHash(tsig.algorithm, secret, data);
    if(expected.size() != tsig.mac.size())
        return false;
    uint8_t diff = 0;
    for(std::size_t i = 0; i < expected.size(); ++i)
        diff |= uint8_t(expected[i] ^ tsig.mac[i]);
    return diff == 0;
}
