#include "Ipv4Subnet.hpp"
#include <cstddef>
#include <stdexcept>

namespace
{
    uint32_t MaskU32(uint8_t prefix)
    {
        if (prefix == 0) return 0;
        return 0xFFFFFFFFu << (32 - prefix);
    }
}

bool Ipv4Subnet::operator==(const Ipv4Subnet &o) const{ return (network == o.network) && prefix == o.prefix;}

bool Ipv4Subnet::operator<(const Ipv4Subnet &o) const
{
    if(network == o.network) return prefix < o.prefix;
    return network < o.network;
}

std::string Ipv4Subnet::ToString() const { return network.ToString() + "/" + std::to_string(prefix);}

Ipv4 Ipv4Subnet::Mask() const { return Ipv4(MaskU32(prefix)); }

Ipv4 Ipv4Subnet::Broadcast() const { return Ipv4(network.value | ~MaskU32(prefix));}

bool Ipv4Subnet::Contains(const Ipv4 &ip) const { return (ip & Mask()) == network;}

bool Ipv4Subnet::TryParse(const std::string &s, Ipv4Subnet &out)
{
    auto pos = s.find('/');
    size_t n = s.length();
    if(pos == std::string::npos) return false;
    std::string left = s.substr(0, pos);
    std::string right = s.substr(pos + 1, n - pos - 1);

    Ipv4 addr;
    if(!Ipv4::TryParse(left, addr) || right.empty())return false;
    int p = 0;
    for(char c : right)
    {
        if(c < '0' || c > '9') return false;
        p = p * 10 + (c - '0');
        if(p > 32) return false;
    }

    out.network = addr & Ipv4(MaskU32(p));
    out.prefix = p;
    return true;
}

Ipv4Subnet::Ipv4Subnet(const Ipv4 &network, uint8_t prefix): network(network), prefix(prefix)
{
    if (this->prefix > 32)
        throw std::invalid_argument("Ipv4Subnet: bad prefix");
    this->network = this->network & Ipv4(MaskU32(this->prefix));
}

Ipv4Subnet::Ipv4Subnet(const std::string &s)
{
    if(!TryParse(s, *this))
            throw std::invalid_argument("Ipv4Subnet: invalid \"" + s + "\"");
}
