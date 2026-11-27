#include "Ipv6Subnet.hpp"
#include <stdexcept>

Ipv6Subnet::Ipv6Subnet(const Ipv6 &ip, uint8_t prefixLen) : prefix(prefixLen)
{
    if(prefix > 128)
        throw std::invalid_argument("invalid IPv6 prefix");
    network = ip;
    std::size_t whole = prefix / 8;
    std::size_t rem = prefix % 8;
    if(rem != 0 && whole < 16)
        network.bytes[whole] &= uint8_t(0xFF << (8 - rem));
    for(std::size_t i = whole + (rem ? 1 : 0); i < 16; ++i)
        network.bytes[i] = 0;
}

Ipv6 Ipv6Subnet::Mask() const
{
    Ipv6 mask;
    std::size_t whole = prefix / 8;
    std::size_t rem = prefix % 8;
    for(std::size_t i = 0; i < whole && i < 16; ++i)
        mask.bytes[i] = 0xFF;
    if(rem != 0 && whole < 16)
        mask.bytes[whole] = uint8_t(0xFF << (8 - rem));
    return mask;
}

bool Ipv6Subnet::Contains(const Ipv6 &ip) const
{
    std::size_t whole = prefix / 8;
    std::size_t rem = prefix % 8;
    for(std::size_t i = 0; i < whole; ++i)
        if(ip.bytes[i] != network.bytes[i])
            return false;
    if(rem != 0)
    {
        uint8_t m = uint8_t(0xFF << (8 - rem));
        if((ip.bytes[whole] & m) != (network.bytes[whole] & m))
            return false;
    }
    return true;
}

std::string Ipv6Subnet::ToString() const
{
    return network.ToString() + "/" + std::to_string(prefix);
}

bool Ipv6Subnet::operator==(const Ipv6Subnet &o) const
{
    return network == o.network && prefix == o.prefix;
}

bool Ipv6Subnet::operator<(const Ipv6Subnet &o) const
{
    if(!(network == o.network))
        return network < o.network;
    return prefix < o.prefix;
}

bool Ipv6Subnet::TryParse(const std::string &s, Ipv6Subnet &out)
{
    std::size_t slash = s.find('/');
    std::string addr = slash == std::string::npos ? s : s.substr(0, slash);
    Ipv6 ip;
    if(!Ipv6::TryParse(addr, ip))
        return false;
    unsigned prefix = 128;
    if(slash != std::string::npos)
    {
        std::string p = s.substr(slash + 1);
        if(p.empty() || p.size() > 3)
            return false;
        prefix = 0;
        for(char c : p)
        {
            if(c < '0' || c > '9')
                return false;
            prefix = prefix * 10 + unsigned(c - '0');
        }
        if(prefix > 128)
            return false;
    }
    out = Ipv6Subnet(ip, uint8_t(prefix));
    return true;
}
