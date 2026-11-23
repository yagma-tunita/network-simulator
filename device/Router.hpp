#pragma once

#include "Device.hpp"
#include "ArpAgent.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/IpPacket.hpp"
#include "../core/OspfPacket.hpp"
#include <map>
#include <tuple>
#include <vector>
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
    uint32_t ospfOrigin = 0;
    Port *learnedFromPort = nullptr;
    uint64_t expiresAt = 0;

    Route() = default;
    Route(const Ipv4Subnet &dst, const Ipv4 &nextHop, bool direct);
};

struct Router : Device
{
    struct Pending
    {
        Port *egress;
        IpPacket pkt;
        uint64_t enqueuedAt = 0;
    };

    struct AclRule
    {
        bool permit;
        Ipv4Subnet src;
        Ipv4Subnet dst;
        uint8_t proto;
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
        uint8_t state = OspfIfDown;
        uint8_t priority = 1;
        uint64_t waitUntil = 0;
        Ipv4 dr;
        Ipv4 bdr;
        Ipv4 drIp;
        Ipv4 bdrIp;
        std::map<uint32_t, OspfNeighbor> neighbors;
    };

    static constexpr std::size_t kMaxPendingPerDest = 32;
    static constexpr uint64_t kPendingTimeout = 300;
    static constexpr std::size_t kMaxNat = 4096;
    static constexpr uint64_t kRipInterval = 30;
    static constexpr uint64_t kRipTimeout = 180;
    static constexpr uint16_t kRipInfinity = 16;

    ArpAgent arp;
    std::vector<Route> routeTable;
    std::vector<AclRule> aclIn;
    std::vector<AclRule> aclOut;
    std::map<Ipv4, std::vector<Pending>> pending;
    uint64_t droppedPending = 0;

    bool natEnabled = false;
    Port *natInside = nullptr;
    Port *natOutside = nullptr;
    std::vector<NatTranslation> natTable;
    std::vector<NatForward> natForwards;
    uint16_t nextNatPort = 40000;

    bool ripEnabled = false;
    uint64_t ripGen = 0;
    uint64_t ripNextUpdate = 0;

    static constexpr uint64_t kOspfHelloInterval = 10;
    static constexpr uint64_t kOspfDeadInterval = 40;

    bool ospfEnabled = false;
    uint64_t ospfGen = 0;
    uint64_t ospfNextHello = 0;
    uint32_t ospfRouterId = 0;
    Ipv4 ospfAreaId;
    uint16_t ospfAuthType = OspfPacket::AuthNone;
    uint8_t ospfPassword[8] = {};
    uint32_t ospfSeq = 1;
    std::map<std::tuple<uint8_t, uint32_t, uint32_t>, OspfLsa> ospfLsdb;
    std::vector<OspfInterface> ospfIfaces;

    void FlushPending();
    void AgeOutPending(uint64_t now);

    void AddAcl(bool inbound, bool permit, const Ipv4Subnet &src,
                const Ipv4Subnet &dst, uint8_t proto);
    bool AclAllows(const std::vector<AclRule> &rules, const IpPacket &pkt) const;

    void SetNat(bool on, Port *inside, Port *outside);
    void AddNatForward(uint8_t proto, uint16_t publicPort,
                       const Ipv4 &insideIp, uint16_t insidePort);
    bool ApplyNatIngress(Port *ingress, IpPacket &pkt);
    void ApplyNatEgress(Port *ingress, Port *egress, IpPacket &pkt);
    uint16_t AllocNatPort(uint8_t proto, const Ipv4 &outsideIp);

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
    void OspfFlood(const OspfLsa &lsa, Port *except);
    void OspfConverge();
    OspfLsa OspfBuildRouterLsa();
    OspfLsa OspfBuildNetworkLsa(OspfInterface &ifc);
    void OspfSync();

    bool IsMyIp(Ipv4 ip) const;
    void AddRoute(const Ipv4Subnet &dst, const Ipv4 &nextHop, bool direct);
    void AddRoute(const Route &r);
    const Route* FindRoute(const Ipv4 &dstip) const;
    Port* PortForNextHop(const Ipv4 &ip);
    void RebuildConnected();

    void AddPort(Port* p) override;
    void SetClock(Clock *c) override;
    void OnFrame(Port *port, FramePtr frame) override;
    void SendIcmpError(Port *ingress, const EthernetFrame &origin,
                       const IpPacket &pkt, uint8_t type);

    Router() = default;
};
