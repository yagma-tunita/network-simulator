#include "Router.hpp"
#include "Port.hpp"
#include "../core/DhcpMessage.hpp"
#include "../core/UdpDatagram.hpp"
#include "../engine/Clock.hpp"
#include <memory>

void Router::SetDhcpRelay(Port *port, bool on, const Ipv4 &server)
{
    if(!port)
        return;
    if(on)
        dhcpRelayServers[port] = server;
    else
        dhcpRelayServers.erase(port);
}

void Router::HandleDhcpRelay(Port *ingress, const IpPacket &pkt,
                             const UdpDatagram &dgram)
{
    DhcpMessage m;
    if(!DhcpMessage::TryFromBytes(dgram.payload, m))
        return;

    if(dgram.dstPort == 67 && m.op == DhcpMessage::BootRequest)
    {
        auto it = dhcpRelayServers.find(ingress);
        if(it == dhcpRelayServers.end())
            return;

        m.giaddr = ingress->ip;
        if(m.hops < 255)
            ++m.hops;

        UdpDatagram out;
        out.srcPort = 67;
        out.dstPort = 67;
        out.payload = m.ToBytes();

        Ipv4 server = it->second;
        const Route *r = FindRoute(server);
        if(!r)
            return;
        Ipv4 next = r->direct ? server : r->nextHop;
        Port *egress = PortForNextHop(next);
        if(!egress)
            return;

        IpPacket relayPacket(egress->ip, server, IpPacket::kUdp, out.ToBytes());
        Mac mac;
        if(arp.Lookup(next, mac))
        {
            egress->Send(std::make_shared<const EthernetFrame>(
                mac, egress->mac, EthernetFrame::kIPv4,
                relayPacket.ToBytes()));
        }
        else
        {
            pending[next].push_back(Pending{
                egress, relayPacket, clock ? clock->Now() : 0 });
            arp.SendArpRequest(next, egress);
        }
        return;
    }

    if(dgram.dstPort == 67 && m.op == DhcpMessage::BootReply)
    {
        Port *clientPort = nullptr;
        for(Port *p : portList)
            if(p->hasIp && p->ip == m.giaddr)
            {
                clientPort = p;
                break;
            }
        if(!clientPort)
            return;

        UdpDatagram out;
        out.srcPort = 67;
        out.dstPort = 68;
        out.payload = m.ToBytes();

        IpPacket reply(pkt.dstIp, Ipv4::Broadcast(), IpPacket::kUdp,
                       out.ToBytes());
        clientPort->Send(std::make_shared<const EthernetFrame>(
            Mac::Broadcast(), clientPort->mac, EthernetFrame::kIPv4,
            reply.ToBytes()));
    }
}
