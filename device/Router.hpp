#pragma once

#include "Device.hpp"
#include "ArpAgent.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/Ipv6.hpp"
#include "../core/Ipv6Subnet.hpp"
#include "../core/Ipv6Packet.hpp"
#include "../core/Icmpv6Message.hpp"
#include "../core/IpPacket.hpp"
#include "../core/OspfPacket.hpp"
#include "../core/BgpMessage.hpp"
#include "../netstack/TcpConnection.hpp"
#include <map>
#include <tuple>
#include <vector>
#include <string>
#include <list>
#include <cstddef>

struct Port;
struct UdpDatagram;

struct Route
{
    Ipv4Subnet dst;
    Ipv4 nextHop;
    bool direct = false;
    uint16_t metric = 0;
    bool dynamic = false;
    bool ospf = false;
    bool bgp = false;
    bool external = false;
    uint32_t ospfOrigin = 0;
    Port *learnedFromPort = nullptr;
    uint64_t expiresAt = 0;

    Route() = default;
    Route(const Ipv4Subnet &dst, const Ipv4 &nextHop, bool direct);
};

struct Ipv6Route
{
    Ipv6Subnet dst;
    Ipv6 nextHop;
    bool direct = false;
    Port *port = nullptr;

    Ipv6Route() = default;
    Ipv6Route(const Ipv6Subnet &d, const Ipv6 &nh, bool dir, Port *p = nullptr)
        : dst(d), nextHop(nh), direct(dir), port(p) {}
};

struct BgpPath
{
    Ipv4Subnet prefix;
    Ipv4 nextHop;
    Ipv4 peer;
    std::vector<uint16_t> asPath;
    uint32_t localPref = 100;
    uint32_t receivedLocalPref = 100;
    uint32_t med = 0;
    uint8_t origin = 0;
    Ipv4 routerId;
    bool ebgp = true;
};

struct BgpSelected
{
    Ipv4Subnet prefix;
    Ipv4 nextHop;
    Ipv4 peer;
    std::vector<uint16_t> asPath;
};

struct Router : Device
{
    struct Pending
    {
        Port *egress;
        IpPacket pkt;
        uint64_t enqueuedAt = 0;
    };

    struct Pending6
    {
        Port *egress = nullptr;
        Ipv6Packet pkt;
        uint64_t enqueuedAt = 0;
    };

    struct AclRule
    {
        bool permit;
        Ipv4Subnet src;
        Ipv4Subnet dst;
        uint8_t proto;
    };

    struct Acl6Rule
    {
        bool permit = true;
        Ipv6Subnet src;
        Ipv6Subnet dst;
        uint8_t proto = 0;
    };

    struct NatTranslation
    {
        uint8_t proto = 0;
        Ipv4 insideIp;
        uint16_t insidePort = 0;
        Ipv4 outsideIp;
        uint16_t outsidePort = 0;
    };

    struct NatForward
    {
        uint8_t proto = 0;
        uint16_t publicPort = 0;
        Ipv4 insideIp;
        uint16_t insidePort = 0;
    };

    enum OspfIfState : uint8_t
    {
        OspfIfDown = 0,
        OspfIfWaiting = 1,
        OspfIfDr = 2,
        OspfIfBdr = 3,
        OspfIfDrOther = 4
    };

    enum OspfNbrState : uint8_t
    {
        OspfNbrDown = 0,
        OspfNbrInit = 1,
        OspfNbrTwoWay = 2,
        OspfNbrExStart = 3,
        OspfNbrExchange = 4,
        OspfNbrLoading = 5,
        OspfNbrFull = 6
    };

    struct OspfNeighbor
    {
        uint32_t routerId = 0;
        Ipv4 ip;
        Mac mac;
        uint8_t state = OspfNbrDown;
        uint8_t priority = 1;
        uint32_t cryptoSeq = 0;
        uint64_t lastHello = 0;
        bool master = false;
        bool sentFull = false;
        bool gotFull = false;
        uint32_t ddSeq = 0;
        uint64_t nextResend = 0;
        std::vector<OspfLsa> retrans;
        std::vector<OspfLsrItem> requests;
    };

    struct OspfInterface
    {
        Port *port = nullptr;
        Ipv4 area;
        uint8_t state = OspfIfDown;
        uint8_t priority = 1;
        uint16_t cost = 1;
        bool passive = false;
        uint64_t waitUntil = 0;
        Ipv4 dr;
        Ipv4 bdr;
        Ipv4 drIp;
        Ipv4 bdrIp;
        std::map<uint32_t, OspfNeighbor> neighbors;
    };

    struct OspfExternal
    {
        Ipv4Subnet dst;
        uint32_t metric = 20;
        bool type2 = false;
    };

    struct OspfExtLsa
    {
        OspfLsa lsa;
        Ipv4 nextHop;
        Port *port = nullptr;
    };

    using OspfKey = std::tuple<uint8_t, uint32_t, uint32_t>;

    static constexpr std::size_t kMaxPendingPerDest = 32;
    static constexpr uint64_t kPendingTimeout = 300;
    static constexpr std::size_t kMaxNat = 4096;
    static constexpr uint64_t kRipInterval = 30;
    static constexpr uint64_t kRipTimeout = 180;
    static constexpr uint16_t kRipInfinity = 16;

    ArpAgent arp;
    std::vector<Route> routeTable;
    std::vector<Ipv6Route> route6;
    std::map<Ipv6, Mac> nd6Cache;
    std::map<Ipv6, std::vector<Pending6>> pending6;
    uint64_t droppedPending6 = 0;

    struct RouteTrieNode
    {
        int child[2] = { -1, -1 };
        int route = -1;
    };
    mutable std::vector<RouteTrieNode> routeTrie;
    mutable bool routeTrieDirty = true;

    void MarkRoutesDirty() { routeTrieDirty = true; }
    void RebuildRouteTrie() const;
    std::vector<AclRule> aclIn;
    std::vector<AclRule> aclOut;
    std::vector<Acl6Rule> acl6In;
    std::vector<Acl6Rule> acl6Out;
    std::map<Ipv4, std::vector<Pending>> pending;
    uint64_t droppedPending = 0;

    bool natEnabled = false;
    Port *natInside = nullptr;
    Port *natOutside = nullptr;
    std::vector<NatTranslation> natTable;
    std::vector<NatForward> natForwards;
    uint16_t nextNatPort = 40000;
    std::map<Port *, Ipv4> dhcpRelayServers;
    std::map<Port *, bool> ecnMark;

    bool ripEnabled = false;
    uint64_t ripGen = 0;
    uint64_t ripNextUpdate = 0;

    static constexpr uint64_t kOspfHelloInterval = 10;
    static constexpr uint64_t kOspfDeadInterval = 40;

    bool ospfEnabled = false;
    uint64_t ospfGen = 0;
    uint64_t ospfNextHello = 0;
    uint32_t ospfRouterId = 0;
    uint32_t ospfRouterIdCfg = 0;
    Ipv4 ospfAreaId;
    uint16_t ospfAuthType = OspfPacket::AuthNone;
    uint8_t ospfPassword[8] = {};
    uint8_t ospfKeyId = 0;
    uint32_t ospfCryptoSeq = 0;
    uint8_t ospfDigestAlg = 0;
    std::string ospfKey;
    uint32_t ospfSeq = 1;
    std::map<Port *, uint16_t> ospfCostCfg;
    std::map<Port *, bool> ospfPassiveCfg;
    std::map<Port *, Ipv4> ospfAreaCfg;
    std::map<uint32_t, bool> ospfStubAreas;
    std::map<uint32_t, bool> ospfNssaAreas;
    std::map<uint32_t, std::map<OspfKey, OspfLsa>> ospfLsdb;
    std::map<uint32_t, std::map<Ipv4Subnet, uint32_t>> ospfAreaNets;
    std::map<uint32_t, std::map<uint32_t, uint32_t>> ospfAreaRouterDist;
    std::map<uint32_t, OspfExtLsa> ospfAsbrReach;
    std::vector<OspfExternal> ospfExternals;
    struct OspfSummary
    {
        Ipv4Subnet dst;
        bool notAdvertise = false;
    };
    std::map<uint32_t, std::vector<OspfSummary>> ospfSummaries;
    bool ospfDefaultOriginate = false;
    uint32_t ospfDefaultMetric = 20;
    bool ospfDefaultType2 = true;
    bool ospfRedistConnected = false;
    bool ospfRedistStatic = false;
    uint32_t ospfRedistMetric = 20;
    bool ospfRedistType2 = true;
    std::map<OspfKey, OspfExtLsa> ospfExternalLsdb;
    std::vector<OspfInterface> ospfIfaces;

    bool bgpEnabled = false;
    uint16_t bgpLocalAs = 0;
    Ipv4 bgpRouterId;
    uint64_t bgpGen = 0;
    std::map<Ipv4, uint16_t> bgpNeighbors;
    std::map<Ipv4, uint32_t> bgpLocalPrefIn;
    std::map<Ipv4Subnet, uint32_t> bgpMedOut;
    std::vector<Ipv4Subnet> bgpNetworks;
    std::vector<BgpPath> bgpPaths;
    std::vector<BgpSelected> bgpRib;
    struct BgpSession
    {
        TcpConnection conn;
        bool listener = false;
        Ipv4 localIp;
        Ipv4 peerIp;
        uint16_t remoteAs = 0;
        uint8_t state = 0;
        bool sentUpdates = false;
        uint64_t lastRx = 0;
        uint64_t keepGen = 0;
        uint64_t reconnectGen = 0;
        std::vector<uint8_t> rx;
    };
    std::list<BgpSession> bgpSessions;
    void BgpStart();
    void BgpStop();
    void BgpSetupSession(BgpSession &s);
    void BgpSend(BgpSession &s, const BgpMessage &msg);
    void BgpOnConnected(BgpSession &s);
    void BgpOnData(BgpSession &s, const std::vector<uint8_t> &data);
    void BgpHandle(BgpSession &s, const BgpMessage &msg);
    void BgpScheduleKeepalive(BgpSession &s);
    void BgpKeepaliveTick(BgpSession &s, uint64_t gen);
    void BgpScheduleReconnect(BgpSession &s);
    void BgpReconnectTick(BgpSession &s, uint64_t gen);
    void SendBgpTcpSegment(TcpConnection &conn, const TcpSegment &seg);
    void HandleBgpTcp(Port *port, const IpPacket &pkt, const Mac &srcMac);
    void BgpAddPath(const BgpPath &path);
    void BgpWithdraw(const Ipv4 &peer, const Ipv4Subnet &prefix);
    void BgpWithdrawPeer(const Ipv4 &peer);
    void BgpReapplyPolicy();
    void BgpSelect();

    void FlushPending();
    void AgeOutPending(uint64_t now);

    void AddAcl(bool inbound, bool permit, const Ipv4Subnet &src,
                const Ipv4Subnet &dst, uint8_t proto);
    bool AclAllows(const std::vector<AclRule> &rules, const IpPacket &pkt) const;
    void AddAcl6(bool inbound, bool permit, const Ipv6Subnet &src,
                 const Ipv6Subnet &dst, uint8_t proto);
    bool Acl6Allows(const std::vector<Acl6Rule> &rules,
                    const Ipv6Packet &pkt) const;

    void SetNat(bool on, Port *inside, Port *outside);
    void AddNatForward(uint8_t proto, uint16_t publicPort,
                       const Ipv4 &insideIp, uint16_t insidePort);
    bool ApplyNatIngress(Port *ingress, IpPacket &pkt);
    void ApplyNatEgress(Port *ingress, Port *egress, IpPacket &pkt);
    uint16_t AllocNatPort(uint8_t proto, const Ipv4 &outsideIp);
    void SetDhcpRelay(Port *port, bool on, const Ipv4 &server);
    void SetEcnMark(Port *port, bool on) { ecnMark[port] = on; }
    void HandleDhcpRelay(Port *ingress, const IpPacket &pkt,
                         const UdpDatagram &dgram);

    void SetRip(bool on);
    void RipTick(uint64_t gen);
    void SendRipUpdates();
    void SendRipOnPort(Port *p);
    void HandleRip(Port *ingress, const IpPacket &pkt, const UdpDatagram &dgram);

    uint32_t ComputeOspfRouterId() const;
    void SetOspf(bool on);
    void OspfTick(uint64_t gen);
    void SendOspfHellos();
    void SendOspfHello(Port *p);
    void SendOspfPacket(Port *egress, const OspfPacket &pkt,
                        const Ipv4 &dstIp, const Mac &dstMac);
    void HandleOspf(Port *ingress, const IpPacket &pkt, const Mac &srcMac);
    void HandleOspfHello(Port *ingress, const OspfPacket &pkt,
                         const Mac &srcMac, const Ipv4 &srcIp);
    void OspfElect(OspfInterface &ifc);
    void OspfMaybeAdjacency(OspfInterface &ifc, OspfNeighbor &n);
    void OspfSendDdInitial(OspfInterface &ifc, OspfNeighbor &n);
    void OspfSendDdFull(OspfInterface &ifc, OspfNeighbor &n);
    void OspfHandleDd(Port *ingress, const OspfPacket &pkt, const Mac &srcMac,
                      const Ipv4 &srcIp);
    void OspfProcessHeaders(OspfInterface &ifc, OspfNeighbor &n,
                            const std::vector<OspfLsaHeader> &headers);
    void OspfSendLsr(OspfInterface &ifc, OspfNeighbor &n);
    void OspfHandleLsr(Port *ingress, const OspfPacket &pkt,
                       const Mac &srcMac, const Ipv4 &srcIp);
    void OspfHandleLsu(Port *ingress, const OspfPacket &pkt,
                       const Mac &srcMac, const Ipv4 &srcIp);
    void OspfHandleLsaAck(Port *ingress, const OspfPacket &pkt);
    void OspfSendLsu(OspfInterface &ifc, OspfNeighbor &n,
                     const std::vector<OspfLsa> &lsas);
    void OspfFlood(uint32_t area, const OspfLsa &lsa, Port *except);
    void OspfConverge();
    OspfLsa OspfBuildRouterLsa(uint32_t area);
    OspfLsa OspfBuildNetworkLsa(OspfInterface &ifc);
    OspfInterface *OspfIfcForPort(Port *p);
    void OspfSync();
    void OspfSyncArea(uint32_t area);
    void OspfOriginateSummaries();
    void OspfOriginateAsbrSummaries();
    void AddOspfExternal(const Ipv4Subnet &dst, uint32_t metric, bool type2 = false);
    void SetOspfDefaultOriginate(bool on, uint32_t metric, bool type2);
    void SetOspfRedistribute(bool connected, bool isStatic,
                             uint32_t metric, bool type2);
    void AddOspfSummary(uint32_t area, const Ipv4Subnet &dst,
                        bool notAdvertise);
    void ClearOspfSummaries(uint32_t area);
    void OspfOriginateExternals();
    void OspfFloodExternal(const OspfLsa &lsa, Port *except);

    bool IsMyIp(Ipv4 ip) const;
    bool IsMyIp6(const Ipv6 &ip) const;
    void AddRoute(const Ipv4Subnet &dst, const Ipv4 &nextHop, bool direct);
    void AddRoute(const Route &r);
    void AddRoute6(const Ipv6Subnet &dst, const Ipv6 &nextHop, bool direct,
                   Port *p = nullptr);
    const Route* FindRoute(const Ipv4 &dstip) const;
    const Ipv6Route* FindRoute6(const Ipv6 &dstip) const;
    Port* PortForIpv6NextHop(const Ipv6 &ip) const;
    void RebuildConnected6();
    Port* PortForNextHop(const Ipv4 &ip);
    void RebuildConnected();

    void AddPort(Port* p) override;
    void SetClock(Clock *c) override;
    void OnFrame(Port *port, FramePtr frame) override;
    void HandleIpv6(Port *port, FramePtr frame);
    void SendNs6(Port *egress, const Ipv6 &target);
    void SendIcmp6(Port *egress, const Ipv6 &src, const Ipv6 &dst,
                   const Mac &dstMac, const Icmpv6Message &msg);
    void SendIcmp6Error(Port *ingress, const EthernetFrame &origin,
                        const Ipv6Packet &pkt, uint8_t type, uint8_t code);
    void AgePending6(uint64_t now);
    void FlushPending6(const Ipv6 &neighbor, const Mac &mac);
    void SendIcmpError(Port *ingress, const EthernetFrame &origin,
                       const IpPacket &pkt, uint8_t type,
                       uint8_t code = 0, uint16_t mtu = 0,
                       Ipv4 source = Ipv4::Any());

    Router() = default;
};
