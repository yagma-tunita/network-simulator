#include "ARP.hpp"
#include "ByteIO.hpp"
#include <cstddef>

static constexpr std::size_t kSize = 28;

using namespace ByteIO;

bool ARP::operator==(const ARP &msg) const
{
    return (op == msg.op)
        && (senderMac == msg.senderMac) && (senderIp == msg.senderIp)
        && (targetMac == msg.targetMac) && (targetIp == msg.targetIp);
}

std::vector<uint8_t> ARP::ToBytes() const
{
    std::vector<uint8_t> buf;
    buf.reserve(kSize);

    AppendU16(buf, 0x0001);
    AppendU16(buf, 0x0800);
    buf.push_back(6);
    buf.push_back(4);
    AppendU16(buf, op);
    AppendMac(buf, senderMac);
    AppendIpv4(buf, senderIp);
    AppendMac(buf, targetMac);
    AppendIpv4(buf, targetIp);

    return buf;
}

bool ARP::TryFromBytes(const std::vector<uint8_t> &buf, ARP &out)
{
    if (buf.size() < kSize) return false;

    if (ReadU16(buf, 0) != 0x0001) return false;
    if (ReadU16(buf, 2) != 0x0800) return false;
    if (buf[4] != 6 || buf[5] != 4) return false;

    out.op        = ReadU16(buf, 6);
    out.senderMac = ReadMac(buf, 8);
    out.senderIp  = ReadIpv4(buf, 14);
    out.targetMac = ReadMac(buf, 18);
    out.targetIp  = ReadIpv4(buf, 24);

    return true;
}

std::string ARP::ToString() const
{
    std::string type;
    switch(op)
    {
    case kReply:
        type = "reply";
        break;

    case kRequest:
        type = "request";
        break;

    default:
        type = "unknown(" + std::to_string(op) + ")";
        break;
    }

    return "ARP " + type + " "
        + senderMac.ToString() + "(" + senderIp.ToString() + ")"
        + " -> "
        + targetMac.ToString() + "(" + targetIp.ToString() + ")";
}

ARP ARP::MakeRequest(Ipv4 senderip, Mac sendermac, Ipv4 targetip) { return ARP(kRequest, sendermac, senderip, Mac::Zero(), targetip);}

ARP ARP::MakeReply(Ipv4 senderip, Mac sendermac, Ipv4 targetip, Mac targetmac){ return ARP(kReply, sendermac, senderip, targetmac, targetip);}

bool ARP::IsRequest() const { return op == kRequest;}

bool ARP::IsReply() const { return op == kReply;}

ARP::ARP(uint16_t op, Mac sendermac, Ipv4 senderip, Mac targetmac, Ipv4 targetip)
    : op(op), senderMac(sendermac), senderIp(senderip), targetMac(targetmac), targetIp(targetip) {}
