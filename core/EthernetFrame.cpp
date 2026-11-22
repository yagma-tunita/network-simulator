#include "EthernetFrame.hpp"
#include <utility>

static std::string toHex4(uint16_t v)
{
    static const char *digits = "0123456789abcdef";
    std::string s(4, '0');
    s[0] = digits[(v >> 12) & 0xF];
    s[1] = digits[(v >>  8) & 0xF];
    s[2] = digits[(v >>  4) & 0xF];
    s[3] = digits[(v      ) & 0xF];
    return s;
}

uint16_t EthernetFrame::Tci() const
{
    return uint16_t(((vlanPcp & 0x7) << 13) | ((vlanDei ? 1u : 0u) << 12) |
                    (vlanId & 0x0FFF));
}

EthernetFrame EthernetFrame::WithVlan(uint16_t vid, uint8_t pcp, bool dei) const
{
    EthernetFrame out = *this;
    out.hasVlanTag = true;
    out.vlanId = uint16_t(vid & 0x0FFF);
    out.vlanPcp = uint8_t(pcp & 0x7);
    out.vlanDei = dei;
    return out;
}

EthernetFrame EthernetFrame::WithoutVlan() const
{
    EthernetFrame out = *this;
    out.hasVlanTag = false;
    out.vlanId = 0;
    out.vlanPcp = 0;
    out.vlanDei = false;
    return out;
}

bool EthernetFrame::operator==(const EthernetFrame &e) const
{
    return (dst == e.dst) && (src == e.src) && (type == e.type) &&
           (hasVlanTag == e.hasVlanTag) && (vlanId == e.vlanId) &&
           (vlanPcp == e.vlanPcp) && (vlanDei == e.vlanDei) &&
           (payload == e.payload);
}

bool EthernetFrame::IsBroadcast() const { return dst == Mac::Broadcast(); }

std::string EthernetFrame::ToString() const
{
    std::string out = src.ToString() + "->" + dst.ToString();
    if(hasVlanTag)
        out += " vlan=" + std::to_string(vlanId);
    out = out + " [0x" + toHex4(type) + "] " + std::to_string(payload.size()) + " bytes";
    return out;
}

std::vector<uint8_t> EthernetFrame::ToBytes() const
{
    std::vector<uint8_t> out;
    out.reserve(14 + (hasVlanTag ? 4 : 0) + payload.size());

    for(int i = 0; i < 6; i++) out.push_back(dst.bytes[i]);
    for(int i = 0; i < 6; i++) out.push_back(src.bytes[i]);

    if(hasVlanTag)
    {
        out.push_back(uint8_t((kVlanTpid >> 8) & 0xFF));
        out.push_back(uint8_t(kVlanTpid & 0xFF));
        uint16_t tci = Tci();
        out.push_back(uint8_t((tci >> 8) & 0xFF));
        out.push_back(uint8_t(tci & 0xFF));
    }

    out.push_back(uint8_t((type >> 8) & 0xFF));
    out.push_back(uint8_t(type & 0xFF));

    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

bool EthernetFrame::TryFromBytes(const uint8_t *data, std::size_t len, EthernetFrame &out)
{
    if(data == nullptr || len < 14)
        return false;

    for(int i = 0; i < 6; i++) out.dst.bytes[i] = data[i];
    for(int i = 0; i < 6; i++) out.src.bytes[i] = data[6 + i];

    uint16_t tpid = uint16_t((uint16_t(data[12]) << 8) | data[13]);

    std::size_t off = 14;
    out.hasVlanTag = false;
    out.vlanId = 0;
    out.vlanPcp = 0;
    out.vlanDei = false;

    if(tpid == kVlanTpid)
    {
        if(len < 18)
            return false;
        uint16_t tci = uint16_t((uint16_t(data[14]) << 8) | data[15]);
        out.hasVlanTag = true;
        out.vlanPcp = uint8_t((tci >> 13) & 0x7);
        out.vlanDei = ((tci >> 12) & 0x1) != 0;
        out.vlanId = uint16_t(tci & 0x0FFF);
        out.type = uint16_t((uint16_t(data[16]) << 8) | data[17]);
        off = 18;
    }
    else
    {
        out.type = tpid;
    }

    out.payload.assign(data + off, data + len);
    return true;
}

bool EthernetFrame::TryFromBytes(const std::vector<uint8_t> &data, EthernetFrame &out)
{
    return TryFromBytes(data.data(), data.size(), out);
}

EthernetFrame::EthernetFrame(Mac dst, Mac src, uint16_t type, std::vector<uint8_t> payload)
    : dst(dst), src(src), type(type), payload(std::move(payload)) {}
