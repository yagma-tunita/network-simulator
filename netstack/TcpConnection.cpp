#include "TcpConnection.hpp"
#include "../engine/Scheduler.hpp"
#include "../engine/Event.hpp"
#include <memory>
#include <utility>

namespace
{
    struct RtoEvent : Event
    {
        TcpConnection *conn;
        uint64_t gen;
        RtoEvent(TcpConnection *c, uint64_t g) : conn(c), gen(g) {}
        void Execute(Engine &) override { conn->OnRtoEvent(gen); }
        const char *Name() const override { return "tcp-rto"; }
    };

    struct TwEvent : Event
    {
        TcpConnection *conn;
        uint64_t gen;
        TwEvent(TcpConnection *c, uint64_t g) : conn(c), gen(g) {}
        void Execute(Engine &) override { conn->OnTwEvent(gen); }
        const char *Name() const override { return "tcp-timewait"; }
    };

    struct KeepaliveEvent : Event
    {
        TcpConnection *conn;
        uint64_t gen;
        KeepaliveEvent(TcpConnection *c, uint64_t g) : conn(c), gen(g) {}
        void Execute(Engine &) override { conn->OnKeepaliveEvent(gen); }
        const char *Name() const override { return "tcp-keepalive"; }
    };

    struct DelayedAckEvent : Event
    {
        TcpConnection *conn;
        uint64_t gen;
        DelayedAckEvent(TcpConnection *c, uint64_t g) : conn(c), gen(g) {}
        void Execute(Engine &) override { conn->OnDelayedAckEvent(gen); }
        const char *Name() const override { return "tcp-delayed-ack"; }
    };

    std::vector<uint8_t> BuildSynOptions(uint16_t mss, uint8_t wscale,
                                         uint32_t tsVal, uint32_t tsEcr)
    {
        std::vector<uint8_t> o;
        o.push_back(2);
        o.push_back(4);
        o.push_back(uint8_t(mss >> 8));
        o.push_back(uint8_t(mss));
        o.push_back(3);
        o.push_back(3);
        o.push_back(wscale);
        o.push_back(4);
        o.push_back(2);
        o.push_back(8);
        o.push_back(10);
        o.push_back(uint8_t(tsVal >> 24));
        o.push_back(uint8_t(tsVal >> 16));
        o.push_back(uint8_t(tsVal >> 8));
        o.push_back(uint8_t(tsVal));
        o.push_back(uint8_t(tsEcr >> 24));
        o.push_back(uint8_t(tsEcr >> 16));
        o.push_back(uint8_t(tsEcr >> 8));
        o.push_back(uint8_t(tsEcr));
        return o;
    }

    std::vector<uint8_t> BuildTimestampOption(uint32_t tsVal, uint32_t tsEcr)
    {
        std::vector<uint8_t> o;
        o.push_back(8);
        o.push_back(10);
        o.push_back(uint8_t(tsVal >> 24));
        o.push_back(uint8_t(tsVal >> 16));
        o.push_back(uint8_t(tsVal >> 8));
        o.push_back(uint8_t(tsVal));
        o.push_back(uint8_t(tsEcr >> 24));
        o.push_back(uint8_t(tsEcr >> 16));
        o.push_back(uint8_t(tsEcr >> 8));
        o.push_back(uint8_t(tsEcr));
        return o;
    }

    void ParseTcpOptions(const std::vector<uint8_t> &opts, uint16_t &mss,
                         uint8_t &wscale, bool &hasMss, bool &hasWs,
                         bool &hasSack, bool &hasTs, uint32_t &tsVal,
                         uint32_t &tsEcr,
                         std::vector<std::pair<uint32_t, uint32_t>> &sacks)
    {
        hasMss = false;
        hasWs = false;
        hasSack = false;
        hasTs = false;
        std::size_t i = 0;
        while(i < opts.size())
        {
            uint8_t kind = opts[i];
            if(kind == 0)
                break;
            if(kind == 1)
            {
                ++i;
                continue;
            }
            if(i + 1 >= opts.size())
                break;
            uint8_t len = opts[i + 1];
            if(len < 2 || i + len > opts.size())
                break;
            if(kind == 2 && len == 4)
            {
                mss = uint16_t((uint16_t(opts[i + 2]) << 8) | opts[i + 3]);
                hasMss = true;
            }
            else if(kind == 3 && len == 3)
            {
                wscale = opts[i + 2];
                hasWs = true;
            }
            else if(kind == 4 && len == 2)
            {
                hasSack = true;
            }
            else if(kind == 8 && len == 10)
            {
                tsVal = (uint32_t(opts[i + 2]) << 24) |
                        (uint32_t(opts[i + 3]) << 16) |
                        (uint32_t(opts[i + 4]) << 8) |
                        uint32_t(opts[i + 5]);
                tsEcr = (uint32_t(opts[i + 6]) << 24) |
                        (uint32_t(opts[i + 7]) << 16) |
                        (uint32_t(opts[i + 8]) << 8) |
                        uint32_t(opts[i + 9]);
                hasTs = true;
            }
            else if(kind == 5 && len >= 10 && (len - 2) % 8 == 0)
            {
                std::size_t n = (len - 2) / 8;
                for(std::size_t b = 0; b < n && b < 3; ++b)
                {
                    std::size_t p = i + 2 + b * 8;
                    uint32_t left = (uint32_t(opts[p]) << 24) |
                                    (uint32_t(opts[p + 1]) << 16) |
                                    (uint32_t(opts[p + 2]) << 8) |
                                    uint32_t(opts[p + 3]);
                    uint32_t right = (uint32_t(opts[p + 4]) << 24) |
                                     (uint32_t(opts[p + 5]) << 16) |
                                     (uint32_t(opts[p + 6]) << 8) |
                                     uint32_t(opts[p + 7]);
                    sacks.push_back({ left, right });
                }
            }
            i += len;
        }
    }

    std::vector<uint8_t> EncodeSackBlocks(
        const std::vector<std::pair<uint32_t, uint32_t>> &blocks)
    {
        if(blocks.empty())
            return {};
        std::vector<uint8_t> o;
        o.push_back(5);
        o.push_back(uint8_t(2 + blocks.size() * 8));
        for(const auto &b : blocks)
        {
            o.push_back(uint8_t(b.first >> 24));
            o.push_back(uint8_t(b.first >> 16));
            o.push_back(uint8_t(b.first >> 8));
            o.push_back(uint8_t(b.first));
            o.push_back(uint8_t(b.second >> 24));
            o.push_back(uint8_t(b.second >> 16));
            o.push_back(uint8_t(b.second >> 8));
            o.push_back(uint8_t(b.second));
        }
        return o;
    }

    std::vector<uint8_t> BuildSackOption(
        const std::map<uint32_t, std::vector<uint8_t>> &ooo)
    {
        std::vector<std::pair<uint32_t, uint32_t>> blocks;
        for(const auto &kv : ooo)
        {
            uint32_t left = kv.first;
            uint32_t right = left + uint32_t(kv.second.size());
            if(!blocks.empty() && left <= blocks.back().second)
            {
                if(right > blocks.back().second)
                    blocks.back().second = right;
            }
            else
            {
                blocks.push_back({ left, right });
            }
            if(blocks.size() >= 3)
                break;
        }
        return EncodeSackBlocks(blocks);
    }

    std::vector<uint8_t> BuildDsackOption(
        const std::map<uint32_t, std::vector<uint8_t>> &ooo,
        uint32_t left, uint32_t right)
    {
        std::vector<std::pair<uint32_t, uint32_t>> blocks;
        blocks.push_back({ left, right });
        for(const auto &kv : ooo)
        {
            if(blocks.size() >= 3)
                break;
            uint32_t l = kv.first;
            uint32_t r = l + uint32_t(kv.second.size());
            if(l <= blocks.back().second)
            {
                if(r > blocks.back().second)
                    blocks.back().second = r;
            }
            else
            {
                blocks.push_back({ l, r });
            }
        }
        return EncodeSackBlocks(blocks);
    }

    uint32_t MakeIsn(Ipv4 local, uint16_t lport, Ipv4 remote, uint16_t rport)
    {
        uint32_t h = 2166136261u;
        h = (h ^ local.value) * 16777619u;
        h = (h ^ remote.value) * 16777619u;
        h = (h ^ uint32_t(lport)) * 16777619u;
        h = (h ^ uint32_t(rport)) * 16777619u;
        h ^= h >> 16;
        return h ? h : 1;
    }
}

void TcpConnection::SetScheduler(Scheduler *s)
{
    scheduler = s;
}

static uint64_t TcpNow(Scheduler *s)
{
    return s ? s->Now() : 0;
}

void TcpConnection::UpdateRtt(double sample)
{
    if(!rttValid)
    {
        srtt = sample;
        rttvar = sample / 2.0;
        rttValid = true;
    }
    else
    {
        double diff = srtt > sample ? srtt - sample : sample - srtt;
        rttvar = (3.0 * rttvar + diff) / 4.0;
        srtt = (7.0 * srtt + sample) / 8.0;
    }
    double est = srtt + 4.0 * rttvar;
    if(est < double(rtoMin)) est = double(rtoMin);
    if(est > double(rtoMax)) est = double(rtoMax);
    rto = uint64_t(est);
}

void TcpConnection::ScheduleDelayedAck()
{
    if(!scheduler)
    {
        FlushDelayedAck();
        return;
    }
    ackPending = true;
    ++ackGen;
    scheduler->ScheduleAfter(kDelayedAckDelay,
        std::make_unique<DelayedAckEvent>(this, ackGen));
}

void TcpConnection::OnDelayedAckEvent(uint64_t gen)
{
    if(gen != ackGen || !ackPending)
        return;
    FlushDelayedAck();
}

void TcpConnection::FlushDelayedAck()
{
    ackPending = false;
    delayedAckSegs = 0;
    ++ackGen;

    std::vector<uint8_t> opt;
    if(sackEnabled)
        opt = BuildSackOption(ooo);
    SendSeg(TcpSegment::kAck, sndNxt, rcvNxt, std::vector<uint8_t>(), false, opt);
}

void TcpConnection::ClearSackRetrans()
{
    for(auto it = sackRetrans.begin(); it != sackRetrans.end(); )
    {
        if(*it < sndUna)
            it = sackRetrans.erase(it);
        else
            ++it;
    }
}

void TcpConnection::RetransmitSackHole(
    const std::vector<std::pair<uint32_t, uint32_t>> &sacks)
{
    uint32_t maxRight = 0;
    for(const auto &b : sacks)
        if(b.second > maxRight) maxRight = b.second;

    uint32_t chosen = 0;
    bool found = false;
    for(const auto &kv : unacked)
    {
        if(kv.first < sndUna)
            continue;
        if(!sacks.empty() && kv.first >= maxRight)
            break;

        bool covered = false;
        for(const auto &b : sacks)
            if(kv.first >= b.first && kv.first < b.second)
            {
                covered = true;
                break;
            }
        if(!covered && !sackRetrans.count(kv.first))
        {
            chosen = kv.first;
            found = true;
            break;
        }
    }

    if(!found)
        return;

    auto it = unacked.find(chosen);
    if(it == unacked.end())
        return;

    sackRetrans.insert(chosen);
    ++retransmits;
    ++totalRetransmits;
    SendSeg(TcpSegment::kAck | TcpSegment::kPsh, it->first, rcvNxt,
            it->second, true);
    StartRto();
}

void TcpConnection::SetKeepalive(bool on, uint64_t idle, uint64_t interval,
                                 uint8_t probes)
{
    keepaliveEnabled = on;
    if(idle > 0) keepIdle = idle;
    if(interval > 0) keepInterval = interval;
    keepMaxProbes = probes;
    keepProbes = 0;
    lastActivity = TcpNow(scheduler);
    ++keepGen;

    if(on && state == Established && scheduler)
        scheduler->ScheduleAfter(keepIdle,
            std::make_unique<KeepaliveEvent>(this, keepGen));
}

void TcpConnection::OnKeepaliveEvent(uint64_t gen)
{
    if(gen != keepGen || !keepaliveEnabled || state != Established)
        return;

    uint64_t now = TcpNow(scheduler);
    if(keepProbes == 0 && now - lastActivity < keepIdle)
    {
        scheduler->ScheduleAfter(keepIdle - (now - lastActivity),
            std::make_unique<KeepaliveEvent>(this, keepGen));
        return;
    }

    if(keepProbes < keepMaxProbes)
    {
        ++keepProbes;
        uint32_t seq = sndNxt > 0 ? sndNxt - 1 : 0;
        SendSeg(TcpSegment::kAck, seq, rcvNxt, std::vector<uint8_t>(), false);
        scheduler->ScheduleAfter(keepInterval,
            std::make_unique<KeepaliveEvent>(this, keepGen));
        return;
    }

    if(onKeepaliveTimeout) onKeepaliveTimeout();
    Abort();
}

void TcpConnection::Listen(Ipv4 local, uint16_t lport)
{
    localIp = local;
    localPort = lport;
    state = Listening;
}

void TcpConnection::OpenPassiveCookie(Ipv4 local, uint16_t lport, Ipv4 remote,
                                      uint16_t rport, uint32_t clientIsn,
                                      uint32_t serverIsn)
{
    localIp = local;
    localPort = lport;
    remoteIp = remote;
    remotePort = rport;
    irs = clientIsn;
    rcvNxt = clientIsn + 1;
    iss = serverIsn;
    sndUna = iss;
    sndNxt = iss + 1;
    cwnd = mss;
    ssthresh = 65535;
    sndWnd = 8192;
    dupAcks = 0;
    state = SynRcvd;
}

void TcpConnection::OpenActive(Ipv4 local, uint16_t lport, Ipv4 remote,
                               uint16_t rport, uint32_t isn)
{
    localIp = local;
    localPort = lport;
    remoteIp = remote;
    remotePort = rport;
    iss = isn ? isn : MakeIsn(local, lport, remote, rport);
    sndUna = iss;
    sndNxt = iss + 1;
    cwnd = mss;
    ssthresh = 65535;
    sndWnd = 8192;
    dupAcks = 0;
    rto = 50;
    rttValid = false;
    rttTiming = false;
    state = SynSent;
    SendSeg(TcpSegment::kSyn, iss, 0, std::vector<uint8_t>(), true);
    StartRto();
}

void TcpConnection::SendSeg(uint8_t flags, uint32_t seq, uint32_t ack,
                            const std::vector<uint8_t> &payload, bool track,
                            const std::vector<uint8_t> &options)
{
    if(!out) return;

    TcpSegment s;
    s.srcPort = localPort;
    s.dstPort = remotePort;
    s.seq = seq;
    s.ack = ack;
    s.flags = flags;
    uint32_t win = rcvWnd;
    if((flags & TcpSegment::kSyn) || !wsEnabled)
        s.window = uint16_t(win > 65535 ? 65535 : win);
    else
    {
        uint32_t scaled = win >> rcvWscale;
        s.window = uint16_t(scaled > 65535 ? 65535 : scaled);
    }
    uint32_t tv = uint32_t(TcpNow(scheduler));
    if(flags & TcpSegment::kSyn)
        s.options = BuildSynOptions(uint16_t(mss), rcvWscale, tv, tsRecent);
    else
    {
        s.options = options;
        if(tsEnabled)
        {
            std::vector<uint8_t> ts = BuildTimestampOption(tv, tsRecent);
            s.options.insert(s.options.end(), ts.begin(), ts.end());
        }
    }
    s.payload = payload;
    out(s);

    if(!payload.empty() || (flags & (TcpSegment::kSyn | TcpSegment::kFin)))
    {
        lastActivity = TcpNow(scheduler);
        keepProbes = 0;
        tsSent[tv] = lastActivity;
        if(tsSent.size() > 64)
            tsSent.erase(tsSent.begin());
    }
    if((flags & TcpSegment::kAck) && !payload.empty())
    {
        ackPending = false;
        delayedAckSegs = 0;
        ++ackGen;
    }

    if(track)
    {
        lastFlags = flags;
        lastSeq = seq;
        lastAck = ack;
        lastPayload = payload;
        lastValid = true;
    }
}

void TcpConnection::StartRto()
{
    CancelRto();
    if(!scheduler) return;
    uint64_t delay = rto;
    if(delay < rtoMin) delay = rtoMin;
    if(delay > rtoMax) delay = rtoMax;
    scheduler->ScheduleAfter(delay, std::make_unique<RtoEvent>(this, rtoGen));
}

void TcpConnection::CancelRto()
{
    ++rtoGen;
}

void TcpConnection::OnRtoEvent(uint64_t gen)
{
    if(gen != rtoGen) return;
    OnRto();
}

void TcpConnection::OnRto()
{
    if(sndWnd == 0 && sendOff < sendBuf.size())
    {
        SendSeg(TcpSegment::kAck, sndUna, rcvNxt, std::vector<uint8_t>(), false);
        if(rto < rtoMax) rto = (rto * 2 > rtoMax) ? rtoMax : rto * 2;
        StartRto();
        return;
    }

    ++retransmits;
    ++totalRetransmits;
    if(retransmits > maxRetransmits)
    {
        Abort();
        return;
    }

    rttTiming = false;
    ++backoff;
    if(rto < rtoMax) rto = (rto * 2 > rtoMax) ? rtoMax : rto * 2;

    ssthresh = (sndNxt - sndUna) / 2;
    if(ssthresh < 2 * mss) ssthresh = 2 * mss;
    cwnd = mss;

    if(!unacked.empty())
    {
        auto it = unacked.begin();
        SendSeg(TcpSegment::kAck | TcpSegment::kPsh, it->first, rcvNxt,
                it->second, false);
    }
    else if(lastValid)
    {
        SendSeg(lastFlags, lastSeq, lastAck, lastPayload, false);
    }
    else
    {
        return;
    }

    StartRto();
}

void TcpConnection::OnTwEvent(uint64_t gen)
{
    if(gen != twGen) return;
    state = Closed;
}

void TcpConnection::Deliver(const std::vector<uint8_t> &data)
{
    if(onData && !data.empty()) onData(data);
}

void TcpConnection::DrainOoo()
{
    bool progressed = false;
    for(;;)
    {
        auto it = ooo.find(rcvNxt);
        if(it == ooo.end()) break;
        Deliver(it->second);
        rcvNxt += uint32_t(it->second.size());
        ooo.erase(it);
        progressed = true;
    }
    if(progressed)
        FlushDelayedAck();
}

void TcpConnection::EnterTimeWait()
{
    state = TimeWait;
    CancelRto();
    if(scheduler)
    {
        uint64_t gen = ++twGen;
        scheduler->ScheduleAfter(2 * rto, std::make_unique<TwEvent>(this, gen));
    }
}

void TcpConnection::OnSegment(const TcpSegment &seg, Ipv4 srcIp)
{
    if(seg.dstPort != localPort) return;
    if(state != Listening && remotePort != 0 && seg.srcPort != remotePort) return;

    uint8_t flags = seg.flags;
    bool syn = (flags & TcpSegment::kSyn) != 0;
    bool ack = (flags & TcpSegment::kAck) != 0;
    bool fin = (flags & TcpSegment::kFin) != 0;

    uint16_t pmss = 0;
    uint8_t pwscale = 0;
    bool hasMss = false;
    bool hasWs = false;
    bool hasSack = false;
    bool hasTs = false;
    uint32_t tsVal = 0;
    uint32_t tsEcr = 0;
    std::vector<std::pair<uint32_t, uint32_t>> sacks;
    ParseTcpOptions(seg.options, pmss, pwscale, hasMss, hasWs, hasSack,
                    hasTs, tsVal, tsEcr, sacks);
    if(hasMss)
    {
        if(pmss < 536) pmss = 536;
        if(pmss > 1460) pmss = 1460;
        mss = pmss;
    }
    if(syn && hasWs)
    {
        if(pwscale > 14) pwscale = 14;
        peerWscale = pwscale;
        wsEnabled = true;
    }
    if(syn && hasSack)
        sackEnabled = true;
    if(hasTs)
    {
        if(syn)
        {
            tsEnabled = true;
            tsRecent = tsVal;
        }
        else if(tsEnabled && !(flags & TcpSegment::kRst))
        {
            int32_t delta = int32_t(tsVal - tsRecent);
            if(delta < 0)
                return;
            if(delta > 0)
                tsRecent = tsVal;
        }
    }

    if(flags & TcpSegment::kRst)
    {
        bool ok = false;
        if(state == SynSent)
            ok = ack && seg.ack == sndNxt;
        else if(state != Listening)
            ok = seg.seq >= rcvNxt &&
                 (uint32_t(seg.seq - rcvNxt) < (rcvWnd ? rcvWnd : 1));
        if(ok)
        {
            if(onReset) onReset();
            Abort();
        }
        return;
    }

    lastActivity = TcpNow(scheduler);
    keepProbes = 0;

    if(state == Established && seg.payload.empty() && (flags & TcpSegment::kAck) &&
       !syn && !fin && rcvNxt > 0 && seg.seq == rcvNxt - 1)
    {
        SendSeg(TcpSegment::kAck, sndNxt, rcvNxt, std::vector<uint8_t>(), false);
        return;
    }

    if(state == Listening)
    {
        if(syn)
        {
            remoteIp = !(srcIp == Ipv4::Any()) ? srcIp : remoteIp;
            remotePort = seg.srcPort;
            irs = seg.seq;
            rcvNxt = irs + 1;
            iss = MakeIsn(localIp, localPort, remoteIp, remotePort);
            sndUna = iss;
            sndNxt = iss + 1;
            cwnd = mss;
            ssthresh = 65535;
            sndWnd = 8192;
            dupAcks = 0;
            state = SynRcvd;
            SendSeg(TcpSegment::kSyn | TcpSegment::kAck, iss, rcvNxt,
                    std::vector<uint8_t>(), true);
            StartRto();
        }
        return;
    }

    if(state == SynSent)
    {
        if(syn && ack && seg.ack == iss + 1)
        {
            irs = seg.seq;
            rcvNxt = irs + 1;
            sndUna = seg.ack;
            CancelRto();
            state = Established;
            SendSeg(TcpSegment::kAck, sndNxt, rcvNxt, std::vector<uint8_t>(), false);
            if(onConnected) onConnected();
            if(keepaliveEnabled && scheduler)
            {
                lastActivity = TcpNow(scheduler);
                ++keepGen;
                scheduler->ScheduleAfter(keepIdle,
                    std::make_unique<KeepaliveEvent>(this, keepGen));
            }
        }
        else if(syn && !ack)
        {
            irs = seg.seq;
            rcvNxt = irs + 1;
            sndWnd = seg.window;
            if(wsEnabled)
                sndWnd = uint32_t(seg.window) << peerWscale;
            state = SynRcvd;
            SendSeg(TcpSegment::kSyn | TcpSegment::kAck, iss, rcvNxt,
                    std::vector<uint8_t>(), true);
            StartRto();
        }
        return;
    }

    if(state == SynRcvd)
    {
        if(ack && seg.ack == sndNxt)
        {
            sndUna = seg.ack;
            CancelRto();
            state = Established;
            if(onConnected) onConnected();
            if(keepaliveEnabled && scheduler)
            {
                lastActivity = TcpNow(scheduler);
                ++keepGen;
                scheduler->ScheduleAfter(keepIdle,
                    std::make_unique<KeepaliveEvent>(this, keepGen));
            }
        }
        return;
    }

    if(state == Closed || state == TimeWait)
    {
        if(state == TimeWait && fin)
            SendSeg(TcpSegment::kAck, sndNxt, rcvNxt + 1, std::vector<uint8_t>(), false);
        return;
    }

    if(ack)
    {
        if(sackEnabled && !sacks.empty() && sacks[0].first < sacks[0].second &&
           sacks[0].second <= seg.ack)
        {
            ++dsacks;
            if(inRecovery && cwndBeforeRecovery > cwnd)
            {
                cwnd = cwndBeforeRecovery;
                inRecovery = false;
                sackRetrans.clear();
            }
        }

        sndWnd = seg.window;
        if(wsEnabled)
            sndWnd = uint32_t(seg.window) << peerWscale;

        if(seg.ack > sndUna)
        {
            uint32_t acked = seg.ack - sndUna;
            bool wasRecovery = inRecovery;
            sndUna = seg.ack;
            backoff = 0;
            retransmits = 0;
            dupAcks = 0;

            bool sampled = false;
            if(hasTs && tsEcr != 0)
            {
                auto tsit = tsSent.find(tsEcr);
                if(tsit != tsSent.end())
                {
                    uint64_t now = TcpNow(scheduler);
                    UpdateRtt(double(now - tsit->second));
                    tsSent.erase(tsit);
                    rttTiming = false;
                    sampled = true;
                }
            }
            if(!sampled && rttTiming)
            {
                uint64_t now = TcpNow(scheduler);
                UpdateRtt(double(now - rttStart));
                rttTiming = false;
            }

            if(cwnd < ssthresh)
                cwnd += acked;
            else
                cwnd += (cwnd > 0) ? (mss * mss) / cwnd : mss;
            if(cwnd > 65535) cwnd = 65535;

            std::map<uint32_t, std::vector<uint8_t>> keep;
            for(auto &kv : unacked)
            {
                uint32_t end = kv.first + uint32_t(kv.second.size());
                if(end <= sndUna)
                    continue;
                if(kv.first < sndUna)
                {
                    std::size_t cut = std::size_t(sndUna - kv.first);
                    keep[sndUna] = std::vector<uint8_t>(
                        kv.second.begin() + std::ptrdiff_t(cut), kv.second.end());
                }
                else
                {
                    keep[kv.first] = kv.second;
                }
            }
            unacked.swap(keep);
            ClearSackRetrans();

            if(wasRecovery)
            {
                if(sndUna >= recover)
                {
                    inRecovery = false;
                    sackRetrans.clear();
                    cwnd = ssthresh;
                }
                else
                {
                    cwnd = ssthresh + 3 * mss;
                    RetransmitSackHole(sacks);
                }
            }

            if(sendOff == sendBuf.size() && sndUna == sndNxt)
            {
                sendBuf.clear();
                sendOff = 0;
            }

            if(state == FinWait1 && sndUna == sndNxt)
                state = FinWait2;
            if(state == Closing && sndUna == sndNxt)
                EnterTimeWait();
            if(state == LastAck && sndUna == sndNxt)
                state = Closed;

            Pump();

            if(sndUna == sndNxt)
                CancelRto();
            else
                StartRto();

            if(sndWnd == 0 && sendOff < sendBuf.size())
                StartRto();
        }
        else if(seg.ack == sndUna && sndUna < sndNxt && seg.payload.empty())
        {
            ++dupAcks;
            if(dupAcks == 3)
            {
                if(!inRecovery || sndUna >= recover)
                {
                    inRecovery = true;
                    recover = sndNxt;
                    cwndBeforeRecovery = cwnd;
                    ssthresh = cwnd / 2;
                    if(ssthresh < 2 * mss) ssthresh = 2 * mss;
                    cwnd = ssthresh + 3 * mss;
                    sackRetrans.clear();
                }
                else
                {
                    cwnd += mss;
                }
                RetransmitSackHole(sacks);
            }
            else if(dupAcks > 3 && inRecovery)
            {
                cwnd += mss;
                RetransmitSackHole(sacks);
            }
        }

        if(sndWnd == 0 && sendOff < sendBuf.size())
            StartRto();
        else if(sndWnd > 0 && sendOff < sendBuf.size())
            Pump();
    }

    if(!seg.payload.empty())
    {
        if(seg.seq == rcvNxt)
        {
            Deliver(seg.payload);
            rcvNxt += uint32_t(seg.payload.size());
            ++delayedAckSegs;
            if(delayedAckSegs >= 2 || !ooo.empty())
                FlushDelayedAck();
            else
                ScheduleDelayedAck();
            DrainOoo();
        }
        else if(seg.seq > rcvNxt)
        {
            ooo[seg.seq] = seg.payload;
            FlushDelayedAck();
        }
        else
        {
            if(sackEnabled && seg.seq < rcvNxt)
            {
                uint32_t right = seg.seq + uint32_t(seg.payload.size());
                if(right > rcvNxt) right = rcvNxt;
                std::vector<uint8_t> opt = BuildDsackOption(ooo, seg.seq, right);
                ackPending = false;
                delayedAckSegs = 0;
                ++ackGen;
                SendSeg(TcpSegment::kAck, sndNxt, rcvNxt,
                        std::vector<uint8_t>(), false, opt);
            }
            else
            {
                FlushDelayedAck();
            }
        }
    }

    if(fin)
    {
        if(seg.seq + uint32_t(seg.payload.size()) == rcvNxt)
        {
            rcvNxt += 1;
            FlushDelayedAck();

            if(state == Established) state = CloseWait;
            else if(state == FinWait1)
            {
                if(sndUna == sndNxt) EnterTimeWait();
                else state = Closing;
            }
            else if(state == FinWait2) EnterTimeWait();
            else if(state == Closing) EnterTimeWait();
            else if(state == LastAck) state = Closed;
        }
    }
}

void TcpConnection::Pump()
{
    bool sent = false;

    while(sendOff < sendBuf.size())
    {
        uint32_t inFlight = sndNxt - sndUna;
        uint32_t limit = cwnd < sndWnd ? cwnd : sndWnd;
        if(inFlight >= limit) break;

        uint32_t avail = limit - inFlight;
        if(nagle && !unacked.empty() && (sendBuf.size() - sendOff) < mss)
            break;
        uint32_t n = mss;
        if(n > avail) n = avail;
        if(n > sendBuf.size() - sendOff) n = uint32_t(sendBuf.size() - sendOff);
        if(n == 0) break;

        std::vector<uint8_t> chunk(sendBuf.begin() + std::ptrdiff_t(sendOff),
                                   sendBuf.begin() + std::ptrdiff_t(sendOff + n));
        uint32_t seq = sndNxt;
        if(unacked.empty() && !rttTiming)
        {
            rttStart = TcpNow(scheduler);
            rttTiming = true;
        }
        unacked[seq] = chunk;
        SendSeg(TcpSegment::kAck | TcpSegment::kPsh, seq, rcvNxt, chunk, true);
        sndNxt += n;
        sendOff += n;
        sent = true;
    }

    if(sent) StartRto();
}

void TcpConnection::SendData(const std::vector<uint8_t> &data)
{
    if(state != Established && state != CloseWait) return;
    sendBuf.insert(sendBuf.end(), data.begin(), data.end());
    Pump();
    if(sndWnd == 0 && sendOff < sendBuf.size())
        StartRto();
}

void TcpConnection::Close()
{
    if(state == Established)
    {
        SendSeg(TcpSegment::kFin | TcpSegment::kAck, sndNxt, rcvNxt,
                std::vector<uint8_t>(), true);
        unacked[sndNxt] = std::vector<uint8_t>();
        sndNxt += 1;
        state = FinWait1;
        StartRto();
    }
    else if(state == CloseWait)
    {
        SendSeg(TcpSegment::kFin | TcpSegment::kAck, sndNxt, rcvNxt,
                std::vector<uint8_t>(), true);
        unacked[sndNxt] = std::vector<uint8_t>();
        sndNxt += 1;
        state = LastAck;
        StartRto();
    }
}

void TcpConnection::Abort()
{
    state = Closed;
    CancelRto();
    lastValid = false;
    unacked.clear();
    ooo.clear();
}
