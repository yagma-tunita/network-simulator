#pragma once

#include "Device.hpp"
#include "ArpAgent.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Mac.hpp"
#include "../core/IpPacket.hpp"
#include "../core/DhcpMessage.hpp"
#include "../core/DnsMessage.hpp"
#include "../core/UdpDatagram.hpp"
#include "../netstack/TcpConnection.hpp"
#include <cstdint>
#include <cstddef>
#include <map>
#include <deque>
#include <memory>
#include <vector>
#include <string>

struct EndDevice : Device
{
    struct PingOutstanding
    {
        Ipv4 dst;
        uint64_t sentAt = 0;
        bool sent = false;
    };

    struct PendingPing
    {
        Port *egress = nullptr;
        Ipv4 nextHop;
        IpPacket pkt;
        uint16_t seq = 0;
    };

    static constexpr std::size_t kMaxPending = 64;
    static constexpr uint64_t kPingTimeout = 50;

    ArpAgent arp;

    Ipv4 gateway;
    bool hasGateway = false;

    bool udpEchoEnabled = false;
    uint16_t udpEchoPort = 7;

    bool tcpEchoEnabled = false;
    uint16_t tcpEchoPort = 0;

    struct TcpClientState
    {
        bool active = false;
        Ipv4 peer;
        uint16_t dport = 0;
        uint16_t sport = 0;
        uint32_t seq = 0;
        uint32_t ack = 0;
        int state = 0;
        std::string text;
    };

    TcpClientState tcpClient;
    Ipv4 tcpSrvPeer;
    uint16_t tcpSrvPeerPort = 0;
    uint32_t tcpSrvSeq = 0;
    uint32_t tcpSrvAck = 0;
    bool tcpSrvActive = false;

    std::deque<TcpConnection> tcpConns;
    bool tcpListenEnabled = false;
    uint16_t tcpListenPort = 0;
    uint16_t nextTcpLocalPort = 40000;

    bool dhcpServerEnabled = false;
    Ipv4 dhcpPoolStart;
    Ipv4 dhcpPoolEnd;
    Ipv4 dhcpSubnetMask;
    Ipv4 dhcpRouter;
    Ipv4 dhcpDns;
    uint8_t dhcpPrefix = 24;
    std::map<Mac, Ipv4> dhcpLeases;

    bool dhcpClientActive = false;
    int dhcpState = 0;
    Port *dhcpClientPort = nullptr;
    uint32_t dhcpXid = 0;
    uint32_t nextDhcpXid = 1;
    Ipv4 dhcpOfferedIp;
    Ipv4 dhcpServerId;

    bool hasDnsServer = false;
    Ipv4 dnsServerIp;

    bool dnsServerEnabled = false;
    std::map<std::string, Ipv4> dnsRecords;

    uint16_t dnsClientPort = 0;
    uint32_t dnsQueryId = 0;
    std::string dnsQueryName;
    uint32_t nextDnsId = 1;
    uint16_t nextDnsClientPort = 53000;

    std::map<uint16_t, PingOutstanding> outstanding;
    std::vector<PendingPing> pendingPings;
    uint16_t nextPingSeq = 0;
    uint64_t droppedPending = 0;

    std::map<uint16_t, uint8_t> traceHops;
    Ipv4 traceTarget;
    uint8_t traceTtl = 0;
    uint8_t traceMaxHops = 0;
    bool traceActive = false;

    void OnFrame(Port *port, FramePtr frame) override;
    void SetClock(Clock *c) override;
    void SetGateway(const Ipv4 &gw) { gateway = gw; hasGateway = true; }
    void SendArpRequest(Ipv4 targetIp);
    bool Lookup(Ipv4 ip, Mac &outMac);
    void SendPing(Ipv4 targetIp, uint16_t seq = 0, uint8_t ttl = IpPacket::kDefaultTtl);
    void SendUdp(Ipv4 targetIp, uint16_t dstPort, const std::string &payload,
                 uint16_t srcPort = 0);
    void SetUdpEcho(bool on, uint16_t port = 7);
    void SetTcpEcho(bool on, uint16_t port = 0);
    void TcpEchoClient(Ipv4 targetIp, uint16_t dstPort, const std::string &text);
    void SetTcpListen(bool on, uint16_t port = 0);
    void TcpConnect(Ipv4 targetIp, uint16_t dstPort, const std::string &text);
    bool HandleTcpStack(Port *port, const IpPacket &pkt);
    void SendTcpSegment(TcpConnection &conn, const TcpSegment &seg);
    TcpConnection *FindTcpConn(uint16_t localPort, Ipv4 remote, uint16_t remotePort);
    void SetDhcpServer(bool on, const Ipv4 &start, const Ipv4 &end,
                       uint8_t prefix, const Ipv4 &gw, const Ipv4 &dns);
    void StartDhcpClient(Port *p);
    void HandleDhcp(Port *port, const IpPacket &pkt, const UdpDatagram &dgram);
    void SendDhcpPacket(Port *egress, const DhcpMessage &msg);
    void SetDnsServer(bool on);
    void AddDnsRecord(const std::string &name, const Ipv4 &ip);
    void DnsQuery(const Ipv4 &server, const std::string &name);
    void HandleDns(Port *port, const IpPacket &pkt, const UdpDatagram &dgram);
    void HandleTcp(Port *port, const IpPacket &pkt, uint64_t now);
    void SendTcpTo(Ipv4 peer, uint16_t sport, uint16_t dport,
                   uint32_t seq, uint32_t ack, uint8_t flags,
                   const std::vector<uint8_t> &payload);
    bool ResolveNextHop(Ipv4 target, Port *&egress, Ipv4 &nextHop);
    void SendEcho(Ipv4 targetIp, uint16_t seq, uint8_t ttl);
    void Traceroute(Ipv4 targetIp, uint8_t maxHops = 30);
    void SendTraceProbe();
    void ScheduleNextTrace();
    void AdvanceTrace();
    void HandleIp(Port *port, FramePtr frame);
    void FlushPending();
    void OnPingTimeout(uint16_t seq);

    EndDevice() = default;
};
