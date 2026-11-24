#pragma once

#include "../core/TcpSegment.hpp"
#include "../core/Ipv4.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <map>
#include <set>
#include <functional>

struct Scheduler;

struct TcpConnection
{
    enum State
    {
        Closed, Listening, SynSent, SynRcvd, Established,
        FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait
    };

    State state = Closed;

    Ipv4 localIp, remoteIp;
    uint16_t localPort = 0, remotePort = 0;

    uint32_t iss = 0, sndUna = 0, sndNxt = 0;
    uint32_t irs = 0, rcvNxt = 0;
    uint16_t rcvWnd = 65535;
    uint32_t mss = 1000;
    uint8_t peerWscale = 0;
    uint8_t rcvWscale = 7;
    bool wsEnabled = false;
    bool sackEnabled = false;
    bool tsEnabled = false;
    uint32_t tsRecent = 0;
    std::map<uint32_t, uint64_t> tsSent;

    bool nagle = true;
    bool ackPending = false;
    uint64_t ackGen = 0;
    uint8_t delayedAckSegs = 0;
    static constexpr uint64_t kDelayedAckDelay = 2;

    std::map<uint32_t, std::vector<uint8_t>> unacked;
    std::map<uint32_t, std::vector<uint8_t>> ooo;

    std::function<void(const TcpSegment &)> out;
    std::function<void(const std::vector<uint8_t> &)> onData;
    std::function<void()> onConnected;
    std::function<void()> onReset;
    std::function<void()> onKeepaliveTimeout;
    Scheduler *scheduler = nullptr;

    bool keepaliveEnabled = false;
    uint64_t keepIdle = 300;
    uint64_t keepInterval = 75;
    uint8_t keepMaxProbes = 3;
    uint8_t keepProbes = 0;
    uint64_t lastActivity = 0;
    uint64_t keepGen = 0;

    uint32_t cwnd = 1000;
    uint32_t ssthresh = 65535;
    uint16_t sndWnd = 8192;
    uint32_t dupAcks = 0;
    bool inRecovery = false;
    uint32_t recover = 0;
    uint32_t cwndBeforeRecovery = 0;
    std::set<uint32_t> sackRetrans;
    uint64_t dsacks = 0;
    std::vector<uint8_t> sendBuf;
    std::size_t sendOff = 0;

    uint64_t rto = 50;
    uint64_t rtoMin = 20;
    uint64_t rtoMax = 500;
    double srtt = 0;
    double rttvar = 0;
    bool rttValid = false;
    uint64_t rttStart = 0;
    bool rttTiming = false;
    uint32_t backoff = 0;
    uint64_t rtoGen = 0;
    uint64_t twGen = 0;

    uint8_t lastFlags = 0;
    uint32_t lastSeq = 0;
    uint32_t lastAck = 0;
    std::vector<uint8_t> lastPayload;
    bool lastValid = false;

    uint32_t retransmits = 0;
    uint64_t totalRetransmits = 0;
    uint32_t maxRetransmits = 8;

    void SetScheduler(Scheduler *s);
    void SetKeepalive(bool on, uint64_t idle = 300, uint64_t interval = 75,
                      uint8_t probes = 3);
    void OnKeepaliveEvent(uint64_t gen);
    void UpdateRtt(double sample);
    void OnDelayedAckEvent(uint64_t gen);
    void ScheduleDelayedAck();
    void FlushDelayedAck();
    void RetransmitSackHole(const std::vector<std::pair<uint32_t, uint32_t>> &sacks);
    void ClearSackRetrans();
    void Listen(Ipv4 local, uint16_t lport);
    void OpenPassiveCookie(Ipv4 local, uint16_t lport, Ipv4 remote,
                           uint16_t rport, uint32_t clientIsn, uint32_t serverIsn);
    void OpenActive(Ipv4 local, uint16_t lport, Ipv4 remote, uint16_t rport,
                    uint32_t isn = 0);
    void OnSegment(const TcpSegment &seg, Ipv4 srcIp = Ipv4::Any());
    void SendData(const std::vector<uint8_t> &data);
    void Close();
    void Abort();

    void OnRtoEvent(uint64_t gen);
    void OnTwEvent(uint64_t gen);

    void SendSeg(uint8_t flags, uint32_t seq, uint32_t ack,
                 const std::vector<uint8_t> &payload, bool track,
                 const std::vector<uint8_t> &options = {});
    void Pump();
    void StartRto();
    void CancelRto();
    void OnRto();
    void DrainOoo();
    void Deliver(const std::vector<uint8_t> &data);
    void EnterTimeWait();
};
