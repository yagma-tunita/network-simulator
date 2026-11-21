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

bool EthernetFrame::operator==(const EthernetFrame &e) const{ return (dst == e.dst) && (src == e.src) && (type == e.type) && payload == e.payload;}

bool EthernetFrame::IsBroadcast() const { return dst == Mac::Broadcast();}

std::string EthernetFrame::ToString() const
{
    std::string out = src.ToString() + "->" + dst.ToString();
    out = out + " [0x" + toHex4(type) + "] " + std::to_string(payload.size()) + " bytes";
    return out;
}

EthernetFrame::EthernetFrame(Mac dst, Mac src, uint16_t type, std::vector<uint8_t> payload)
    : dst(dst), src(src), type(type), payload(std::move(payload)) {}
