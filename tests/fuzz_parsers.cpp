#include "core/EthernetFrame.hpp"
#include "core/ARP.hpp"
#include "core/IpPacket.hpp"
#include "core/IcmpMessage.hpp"
#include "core/Icmpv6Message.hpp"
#include "core/Ipv4.hpp"
#include "core/Ipv4Subnet.hpp"
#include "core/Ipv6Packet.hpp"
#include "core/Mac.hpp"
#include "core/BgpMessage.hpp"
#include "core/Lldp.hpp"
#include "core/DhcpMessage.hpp"
#include "core/DnsMessage.hpp"
#include "core/OspfPacket.hpp"
#include "core/TcpSegment.hpp"
#include "core/UdpDatagram.hpp"

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

        Ipv6Packet ip6;
        (void)Ipv6Packet::TryFromBytes(buf, ip6);
        Icmpv6Message icmp6;
        (void)Icmpv6Message::TryFromBytes(buf, Ipv6(), Ipv6(), icmp6);
        BgpMessage bgp;
        (void)BgpMessage::TryFromBytes(buf, bgp);
        LldpFrame lldp;
        (void)LldpFrame::TryFromBytes(buf, lldp);
        UdpDatagram udp;
        (void)UdpDatagram::TryFromBytes(buf, udp);
        TcpSegment tcp;
        (void)TcpSegment::TryFromBytes(buf, tcp);
        DhcpMessage dhcp;
        (void)DhcpMessage::TryFromBytes(buf, dhcp);
        DnsMessage dns;
        (void)DnsMessage::TryFromBytes(buf, dns);
        OspfPacket ospf;
        (void)OspfPacket::TryFromBytes(buf, ospf);

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
