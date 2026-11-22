#include "core/EthernetFrame.hpp"
#include "core/ARP.hpp"
#include "core/IpPacket.hpp"
#include "core/IcmpMessage.hpp"
#include "core/Ipv4.hpp"
#include "core/Ipv4Subnet.hpp"
#include "core/Mac.hpp"

#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

int main()
{
    std::mt19937 rng(0x5eed1234u);
    std::uniform_int_distribution<int> lenDist(0, 80);
    std::uniform_int_distribution<int> byteDist(0, 255);

    const int kIterations = 200000;

    for (int i = 0; i < kIterations; ++i)
    {
        int len = lenDist(rng);
        std::vector<uint8_t> buf(static_cast<std::size_t>(len));
        for (std::size_t j = 0; j < buf.size(); ++j)
            buf[j] = static_cast<uint8_t>(byteDist(rng));

        EthernetFrame ef;
        (void)EthernetFrame::TryFromBytes(buf, ef);

        ARP arp;
        (void)ARP::TryFromBytes(buf, arp);

        IpPacket ip;
        (void)IpPacket::TryFromBytes(buf, ip);

        IcmpMessage icmp;
        (void)IcmpMessage::TryFromBytes(buf, icmp);

        std::string s(buf.begin(), buf.end());
        Ipv4 a;
        (void)Ipv4::TryParse(s, a);
        Ipv4Subnet sn;
        (void)Ipv4Subnet::TryParse(s, sn);
        Mac m;
        (void)Mac::TryParse(s, m);
    }

    std::printf("fuzz: %d iterations clean\n", kIterations);
    return 0;
}
