#pragma once

#include "Device.hpp"
#include "ArpAgent.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv6.hpp"
#include "../core/Mac.hpp"
#include "../core/IpPacket.hpp"
#include "../core/Icmpv6Message.hpp"
#include "../core/DhcpMessage.hpp"
#include "../core/DnsMessage.hpp"
#include "../core/UdpDatagram.hpp"
#include "../netstack/TcpConnection.hpp"
#include <cstdint>
#include <cstddef>
#include <map>
#include <unordered_map>
#include <utility>
#include <list>
#include <deque>
#include <tuple>
#include <functional>
#include <memory>
#include <vector>
#include <string>

struct Event;

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
    static constexpr std::size_t kMaxTcpConns = 256;

    ArpAgent arp;

    Ipv4 gateway;
    bool hasGateway = false;
    Ipv6 gateway6;
    bool hasGateway6 = false;

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

    std::list<TcpConnection> tcpConns;
    TcpConnection *tcpLastConn = nullptr;

    using TcpConnKey = std::tuple<uint16_t, uint32_t, uint16_t>;
    struct TcpConnKeyHash
    {
        std::size_t operator()(const TcpConnKey &k) const
        {
            std::size_t h = std::hash<uint32_t>{}(std::get<1>(k));
            h ^= std::size_t(std::get<0>(k)) + 0x9e3779b9u + (h << 6) +
                 (h >> 2);
            h ^= std::size_t(std::get<2>(k)) + 0x9e3779b9u + (h << 6) +
                 (h >> 2);
            return h;
        }
    };
    std::unordered_map<TcpConnKey, TcpConnection *, TcpConnKeyHash>
        tcpConnIndex;
    void IndexTcpConn(TcpConnection &conn);
    bool tcpListenEnabled = false;
    uint16_t tcpListenPort = 0;
    uint16_t tcpPortMin = 40000;
    uint16_t tcpPortMax = 65535;
    uint16_t tcpPortCursor = 40000;
    uint16_t AllocateTcpLocalPort();
    uint16_t TcpMssLimit(Port *port) const;
    void SetTcpPortRange(uint16_t minimum, uint16_t maximum)
    {
        tcpPortMin = minimum;
        tcpPortMax = maximum;
        tcpPortCursor = minimum;
    }
    bool tcpKeepalive = false;
    uint64_t tcpKeepIdle = 300;
    uint64_t tcpKeepInterval = 75;
    uint8_t tcpKeepCount = 3;
    TcpConnection::CongestionControl tcpCongestion = TcpConnection::Reno;
    bool tcpTlp = true;
    bool tcpPrr = true;
    bool tcpRack = true;
    bool tcpPacing = false;
    uint64_t tcpAccepted = 0;
    uint64_t tcpDropped = 0;
    uint64_t tcpResetsSent = 0;
    std::size_t tcpBacklog = 64;
    uint64_t tcpCookiesSent = 0;
    uint64_t tcpCookiesAccepted = 0;

    struct DhcpLease
    {
        Ipv4 ip;
        uint64_t expires = 0;
    };

    bool dhcpServerEnabled = false;
    Ipv4 dhcpPoolStart;
    Ipv4 dhcpPoolEnd;
    Ipv4 dhcpSubnetMask;
    Ipv4 dhcpRouter;
    Ipv4 dhcpDns;
    uint8_t dhcpPrefix = 24;
    uint32_t dhcpLeaseTime = 3600;
    std::map<Mac, DhcpLease> dhcpLeases;

    bool dhcpClientActive = false;
    int dhcpState = 0;
    Port *dhcpClientPort = nullptr;
    uint32_t dhcpXid = 0;
    uint32_t nextDhcpXid = 1;
    Ipv4 dhcpOfferedIp;
    Ipv4 dhcpServerId;
    Ipv4 dhcpServerAddr;
    uint64_t dhcpLeaseSec = 0;
    uint64_t dhcpLeaseEnd = 0;
    uint64_t dhcpRenewAt = 0;
    uint64_t dhcpRebindAt = 0;
    uint64_t dhcpTimerGen = 0;

    std::vector<Ipv4> dnsServers;
    uint32_t dnsTimeout = 100;
    uint8_t dnsMaxAttempts = 2;

    bool dnsServerEnabled = false;
    uint32_t dnsTtl = 60;
    uint32_t dnsNegativeTtl = 60;
    std::map<std::string, std::vector<Ipv4>> dnsRecords;
    std::map<std::string, std::vector<Ipv6>> dnsAaaa;
    std::map<std::string, std::string> dnsCnames;
    std::map<std::pair<std::string, uint16_t>, uint32_t> dnsRrTtl;

    struct DnsMxRecord
    {
        uint16_t preference = 0;
        std::string exchange;
    };
    std::map<std::string, std::vector<DnsMxRecord>> dnsMxRecords;
    std::unordered_map<uint32_t, std::string> dnsReverse;

    struct DnsZone
    {
        std::string name;
        std::string mname;
        std::string rname;
        uint32_t ttl = 60;
        uint32_t serial = 1;
        uint32_t refresh = 3600;
        uint32_t retry = 600;
        uint32_t expire = 86400;
        uint32_t minimum = 60;
    };
    std::map<std::string, DnsZone> dnsZones;
    std::map<std::string, std::vector<std::string>> dnsNsRecords;
    struct DnsSecondaryState
    {
        Ipv4 primary;
        uint64_t refreshAt = 0;
        uint64_t expireAt = 0;
        uint64_t gen = 0;
        bool expired = false;
        bool initialized = false;
    };
    std::map<std::string, DnsSecondaryState> dnsSecondaryZones;
    std::map<std::string, std::vector<Ipv4>> dnsNotifyTargets;

    struct DnsJournalEntry
    {
        uint32_t fromSerial = 0;
        uint32_t toSerial = 0;
        std::vector<DnsAnswer> deleted;
        std::vector<DnsAnswer> added;
    };
    std::map<std::string, std::deque<DnsJournalEntry>> dnsJournal;
    std::vector<Ipv4> dnsAxfrAllow;
    bool dnsAxfrAllowAny = false;
    std::vector<Ipv4> dnsUpdateAllow;
    bool dnsUpdateAllowAny = false;

    struct DnsTsigKey
    {
        std::string secret;
        std::string algorithm;
    };
    std::map<std::string, DnsTsigKey> dnsTsigKeys;
    bool dnsTsigRequired = false;
    bool dnsTsigClient = false;
    std::string dnsTsigClientName;
    std::string dnsTsigClientSecret;
    std::string dnsTsigClientAlgorithm;
    std::vector<uint8_t> axfrRequestMac;

    struct DnsCacheEntry
    {
        std::vector<DnsAnswer> answers;
        uint64_t expires = 0;
        bool negative = false;
        bool nxdomain = false;
        std::list<std::pair<std::string, uint16_t>>::iterator lru;
    };

    struct DnsCacheKeyHash
    {
        std::size_t operator()(
            const std::pair<std::string, uint16_t> &key) const
        {
            std::size_t h = std::hash<std::string>{}(key.first);
            h ^= std::size_t(key.second) + 0x9e3779b9u +
                 (h << 6) + (h >> 2);
            return h;
        }
    };

    std::unordered_map<std::pair<std::string, uint16_t>, DnsCacheEntry,
                       DnsCacheKeyHash> dnsCache;
    std::list<std::pair<std::string, uint16_t>> dnsLru;
    std::size_t dnsCacheMax = 1024;
    uint32_t dnsTtlMin = 0;
    uint32_t dnsTtlMax = 86400;

    uint16_t dnsClientPort = 0;
    uint32_t dnsQueryId = 0;
    uint16_t dnsQueryType = DnsMessage::kTypeA;
    std::string dnsQueryName;
    std::vector<Ipv4> dnsQueryServers;
    std::size_t dnsQueryServerIndex = 0;
    uint8_t dnsQueryAttempt = 0;
    Ipv4 dnsQueryServer;
    uint64_t dnsTimerGen = 0;
    Event *dnsRetryEvent = nullptr;
    uint8_t dnsReferralDepth = 0;
    bool dnsInternalQuery = false;
    std::string dnsOriginalName;
    uint16_t dnsOriginalType = DnsMessage::kTypeA;
    std::string dnsReferralOwner;
    bool dnsTcpActive = false;
    TcpConnection *dnsTcpConn = nullptr;
    uint16_t nextDnsTcpLocalPort = 54000;
    bool axfrActive = false;
    bool axfrInternal = false;
    bool axfrUseIxfr = false;
    uint32_t axfrClientSerial = 0;
    std::string axfrInternalZone;
    std::vector<DnsAnswer> axfrRecords;
    TcpConnection *axfrConn = nullptr;    std::string axfrZone;
    uint16_t axfrId = 0;
    uint8_t axfrSoaCount = 0;
    std::size_t axfrRecordCount = 0;
    uint16_t nextAxfrLocalPort = 55000;
    bool ixfrActive = false;
    TcpConnection *ixfrConn = nullptr;
    uint16_t ixfrId = 0;
    std::string ixfrZone;
    uint32_t ixfrSerial = 0;
    std::vector<uint8_t> ixfrRequestMac;
    uint16_t nextIxfrLocalPort = 56000;
    bool dnsUpdateActive = false;
    uint16_t dnsUpdatePort = 0;
    uint16_t dnsUpdateId = 0;
    Ipv4 dnsUpdateServer;
    std::string dnsUpdateZone;
    std::vector<uint8_t> dnsUpdateRequestMac;
    uint32_t nextDnsId = 1;
    uint16_t nextDnsClientPort = 53000;

    std::map<uint16_t, PingOutstanding> outstanding;
    std::vector<PendingPing> pendingPings;
    std::unordered_map<uint32_t, uint32_t> pendingArpCounts;
    void NotePendingArp(const Ipv4 &nextHop)
    {
        ++pendingArpCounts[nextHop.value];
    }
    void DropPendingArp(const Ipv4 &nextHop)
    {
        auto it = pendingArpCounts.find(nextHop.value);
        if(it == pendingArpCounts.end())
            return;
        if(--it->second == 0)
            pendingArpCounts.erase(it);
    }
    uint16_t nextPingSeq = 0;
    uint64_t droppedPending = 0;
    std::map<Ipv6, Mac> ndCache;
    struct PendingPing6
    {
        Ipv6 target;
        Ipv6 nextHop;
        Port *egress = nullptr;
        uint16_t seq = 0;
        uint8_t hopLimit = 64;
    };
    std::map<Ipv6, std::vector<PendingPing6>> pendingPing6;
    struct Ping6Outstanding
    {
        Ipv6 target;
        uint64_t sentAt = 0;
        bool sent = false;
    };
    std::map<uint16_t, Ping6Outstanding> outstanding6;

    std::map<uint16_t, uint8_t> traceHops;
    Ipv4 traceTarget;
    uint8_t traceTtl = 0;
    uint8_t traceMaxHops = 0;
    bool traceActive = false;
    std::map<uint16_t, uint8_t> traceHops6;
    Ipv6 traceTarget6;
    uint8_t traceTtl6 = 0;
    uint8_t traceMaxHops6 = 0;
    bool traceActive6 = false;

    void OnFrame(Port *port, FramePtr frame) override;
    void SetClock(Clock *c) override;
    void SetGateway(const Ipv4 &gw) { gateway = gw; hasGateway = true; }
    void SetGateway6(const Ipv6 &gw) { gateway6 = gw; hasGateway6 = true; }
    void SendArpRequest(Ipv4 targetIp);
    bool Lookup(Ipv4 ip, Mac &outMac);
    bool ResolveNextHop6(const Ipv6 &target, Port *&egress, Ipv6 &nextHop);
    void SendPing(Ipv4 targetIp, uint16_t seq = 0, uint8_t ttl = IpPacket::kDefaultTtl);
    void SetIpv6(Port *port, const Ipv6 &addr);
    void Ping6(const Ipv6 &targetIp);
    void Traceroute6(const Ipv6 &targetIp, uint8_t maxHops = 30);
    void SendUdp(Ipv4 targetIp, uint16_t dstPort, const std::string &payload,
                 uint16_t srcPort = 0, bool dontFragment = false);
    void SetUdpEcho(bool on, uint16_t port = 7);
    void SetTcpEcho(bool on, uint16_t port = 0);
    void TcpEchoClient(Ipv4 targetIp, uint16_t dstPort, const std::string &text);
    void SetTcpListen(bool on, uint16_t port = 0);
    void SetTcpKeepalive(bool on, uint64_t idle = 300, uint64_t interval = 75,
                         uint8_t count = 3);
    void SetTcpCongestion(TcpConnection::CongestionControl cc)
    {
        tcpCongestion = cc;
    }
    void SetTcpTlp(bool on) { tcpTlp = on; }
    void SetTcpPrr(bool on) { tcpPrr = on; }
    void SetTcpRack(bool on) { tcpRack = on; }
    void SetTcpPacing(bool on) { tcpPacing = on; }
    void TcpConnect(Ipv4 targetIp, uint16_t dstPort, const std::string &text);
    void TcpSend(const std::string &text);
    TcpConnection &NewTcpConnection();
    bool HandleTcpStack(Port *port, const IpPacket &pkt, const Mac &srcMac);
    void SendTcpSegment(TcpConnection &conn, const TcpSegment &seg);
    TcpConnection *FindTcpConn(uint16_t localPort, Ipv4 remote, uint16_t remotePort);
    void CleanupTcpConns();
    void SendTcpReset(Port *ingress, const IpPacket &pkt,
                      const TcpSegment &seg, const Mac &srcMac);
    uint32_t TcpCookieSecret(Port *port) const;
    uint32_t TcpCookie(Port *port, Ipv4 remote, uint16_t rport,
                       uint32_t clientIsn, uint64_t bucket) const;
    void SendTcpCookieSynAck(Port *ingress, const IpPacket &pkt,
                             const TcpSegment &seg, const Mac &srcMac,
                             uint32_t clientIsn);
    bool AcceptTcpCookie(Port *ingress, const IpPacket &pkt,
                         const TcpSegment &seg, const Mac &srcMac);
    void SetDhcpServer(bool on, const Ipv4 &start, const Ipv4 &end,
                       uint8_t prefix, const Ipv4 &gw, const Ipv4 &dns);
    void SetDhcpLeaseTime(uint32_t seconds)
    {
        dhcpLeaseTime = seconds ? seconds : 3600;
    }
    void PurgeDhcpLeases(uint64_t now);
    void StartDhcpClient(Port *p);
    void SendDhcpRelease();
    void ScheduleDhcpTimer(uint64_t at);
    void OnDhcpTimer(uint64_t gen);
    void SendDhcpRenew(bool rebind);
    void HandleDhcp(Port *port, const IpPacket &pkt, const UdpDatagram &dgram);
    void SendDhcpPacket(Port *egress, const DhcpMessage &msg);
    void SetDnsServer(bool on);
    void SetDnsTtl(uint32_t seconds) { dnsTtl = seconds; }
    void SetDnsNegativeTtl(uint32_t seconds) { dnsNegativeTtl = seconds; }
    void SetDnsResolvers(const std::vector<Ipv4> &servers);
    void SetDnsCacheLimit(std::size_t entries);
    void SetDnsTtlBounds(uint32_t minimum, uint32_t maximum)
    {
        dnsTtlMin = minimum;
        dnsTtlMax = maximum;
    }
    uint32_t ClampDnsTtl(uint32_t ttl) const;
    void TouchDnsCache(
        const std::pair<std::string, uint16_t> &key);
    void StoreDnsCache(const std::pair<std::string, uint16_t> &key,
                       const DnsCacheEntry &entry);
    void RemoveDnsCache(const std::pair<std::string, uint16_t> &key);
    void SetDnsRetry(uint32_t timeout, uint8_t attempts)
    {
        dnsTimeout = timeout ? timeout : 1;
        dnsMaxAttempts = attempts ? attempts : 1;
    }
    void AddDnsRecord(const std::string &name, const Ipv4 &ip);
    void AddDnsAaaa(const std::string &name, const Ipv6 &ip);
    void AddDnsCname(const std::string &alias, const std::string &target);
    void AddDnsMx(const std::string &name, uint16_t preference,
                  const std::string &exchange);
    void SetDnsRrTtl(const std::string &name, uint16_t type, uint32_t ttl);
    uint32_t DnsRrTtl(const std::string &name, uint16_t type,
                      uint32_t fallback) const;
    void AddDnsZone(const std::string &zone);
    void AddDnsSecondary(const std::string &zone, const Ipv4 &primary);
    void SetDnsNotifyTargets(const std::string &zone,
                             const std::vector<Ipv4> &targets);
    void NotifyDnsZone(const std::string &zone);
    void NotifyDnsZone(const std::string &zone,
                       const std::vector<Ipv4> &targets);
    void StartDnsSecondaryTransfer(const std::string &zone,
                                   const Ipv4 &primary);
    void ApplyDnsSecondaryTransfer(const std::string &zone,
                                   const std::vector<DnsAnswer> &records);
    void ApplyDnsSecondaryIxfr(const std::string &zone,
                               const std::vector<DnsAnswer> &records,
                               uint32_t clientSerial);
    void ScheduleDnsSecondary(const std::string &zone, uint64_t delay);
    void OnDnsSecondaryTimer(const std::string &zone, uint64_t gen);
    void DnsSecondaryFailed(const std::string &zone);
    void SetDnsSoa(const std::string &zone, const std::string &mname,
                   const std::string &rname, uint32_t ttl, uint32_t serial,
                   uint32_t refresh, uint32_t retry, uint32_t expire,
                   uint32_t minimum);
    void AddDnsNs(const std::string &owner, const std::string &nameserver);
    void SetDnsAxfrAllow(const std::vector<Ipv4> &allow, bool any);
    bool DnsAxfrAllowed(const Ipv4 &client) const;
    void SetDnsUpdateAllow(const std::vector<Ipv4> &allow, bool any);
    bool DnsUpdateAllowed(const Ipv4 &client) const;
    DnsMessage ProcessDnsUpdate(const DnsMessage &m, const Ipv4 &client);
    void DnsUpdateAdd(const Ipv4 &server, const std::string &zone,
                      const std::string &name, const Ipv4 &ip, uint32_t ttl);
    void DnsUpdateDelete(const Ipv4 &server, const std::string &zone,
                         const std::string &name, uint16_t qtype);
    void DnsUpdateCheck(const Ipv4 &server, const std::string &zone,
                        const std::string &name, const Ipv4 &ip);
    void SendDnsUpdate(const Ipv4 &server, const std::string &zone,
                       const std::vector<DnsAnswer> &updates,
                       const std::vector<DnsAnswer> &prereqs = {});
    void AddDnsTsig(const std::string &keyName, const std::string &secret,
                    const std::string &algorithm);
    void SetDnsTsigRequired(bool required) { dnsTsigRequired = required; }
    const DnsTsigKey *FindDnsTsigKey(const std::string &name) const;
    bool HasDnsName(const std::string &name) const;
    std::string FindDnsWildcard(const std::string &name) const;
    void DnsQuery(const std::string &name,
                  uint16_t qtype = DnsMessage::kTypeA);
    void DnsQuery(const Ipv4 &server, const std::string &name,
                  uint16_t qtype = DnsMessage::kTypeA);
    void StartDnsQuery(const std::string &name, uint16_t qtype,
                       const std::vector<Ipv4> &servers);
    void SendDnsQuery();
    void ScheduleDnsRetry(uint64_t delay = 0);
    void CancelDnsRetry();
    void OnDnsTimeout(uint64_t gen);
    void FailDnsQuery();
    void StartDnsTcpQuery();
    void SendDnsTcpQuery(TcpConnection &conn);
    void OnDnsTcpData(TcpConnection &conn, const std::vector<uint8_t> &data);
    void HandleDnsTcpQuery(TcpConnection &conn,
                           const std::vector<uint8_t> &message);
    DnsMessage BuildDnsAxfrResponse(const DnsMessage &m);
    void DnsAxfr(const Ipv4 &server, const std::string &zone);
    void StartDnsAxfr(const Ipv4 &server, const std::string &zone,
                      bool internal, bool useIxfr = false,
                      uint32_t clientSerial = 0);
    void SendDnsAxfrQuery(TcpConnection &conn);
    void DnsIxfr(const Ipv4 &server, const std::string &zone,
                 uint32_t serial);
    void StartDnsIxfr(const Ipv4 &server, const std::string &zone,
                      uint32_t serial);
    void SendDnsIxfrQuery(TcpConnection &conn);
    void OnDnsIxfrData(TcpConnection &conn, const std::vector<uint8_t> &data);
    void FailDnsIxfr();
    DnsMessage BuildDnsIxfrResponse(const DnsMessage &m);
    std::vector<DnsAnswer> SnapshotDnsZone(const std::string &zone) const;
    void RecordDnsJournal(const std::string &zone, uint32_t fromSerial,
                          uint32_t toSerial,
                          const std::vector<DnsAnswer> &before,
                          const std::vector<DnsAnswer> &after);    void OnDnsAxfrData(TcpConnection &conn, const std::vector<uint8_t> &data);
    void FailDnsAxfr();
    bool PrintDnsAnswers(const std::string &name,
                         const std::vector<DnsAnswer> &answers,
                         bool cached = false);
    void HandleDns(Port *port, const IpPacket &pkt, const UdpDatagram &dgram);
    DnsMessage BuildDnsResponse(const DnsMessage &m);
    DnsMessage BuildZonedDnsResponse(const DnsMessage &m);
    bool TryFollowDnsReferral(const DnsMessage &m);
    void ProcessDnsResponse(const DnsMessage &m);
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
    void HandleIpv6(Port *port, FramePtr frame);
    void SendIpv6(Port *egress, const Ipv6 &dstIp, const Mac &dstMac,
                  const Icmpv6Message &msg, uint8_t hopLimit = 64);
    void SendEcho6(Port *egress, const Ipv6 &targetIp, const Ipv6 &nextHop,
                   uint16_t seq, uint8_t hopLimit = 64);
    void SendTrace6Probe();
    void ScheduleNextTrace6();
    void AdvanceTrace6();
    void FlushPending();
    void OnPingTimeout(uint16_t seq);
    void OnPing6Timeout(uint16_t seq);

    EndDevice() = default;
};
