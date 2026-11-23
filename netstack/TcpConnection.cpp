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

    std::vector<uint8_t> BuildSynOptions(uint16_t mss, uint8_t wscale)
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
        o.push_back(1);
        o.push_back(1);
        o.push_back(1);
        return o;
    }

    void ParseTcpOptions(const std::vector<uint8_t> &opts, uint16_t &mss,
                         uint8_t &wscale, bool &hasMss, bool &hasWs,
                         bool &hasSack,
                         std::vector<std::pair<uint32_t, uint32_t>> &sacks)
    {
        hasMss = false;
        hasWs = false;
        hasSack = false;
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
}

void TcpConnection::SetScheduler(Scheduler *s)
{
    scheduler = s;
}

static uint64_t TcpNow(Scheduler *s)
{
    return s ? s->Now() : 0;
}

void TcpConnection::Listen(Ipv4 local, uint16_t lport)
{
    localIp = local;
    localPort = lport;
    state = Listening;
}

void TcpConnection::OpenActive(Ipv4 local, uint16_t lport, Ipv4 remote,
                               uint16_t rport, uint32_t isn)
{
    localIp = local;
    localPort = lport;
    remoteIp = remote;
    remotePort = rport;
    iss = isn;
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
    if(flags & TcpSegment::kSyn)
        s.options = BuildSynOptions(uint16_t(mss), rcvWscale);
    else
        s.options = options;
    s.payload = payload;
    out(s);

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
    {
        std::vector<uint8_t> opt;
        if(sackEnabled)
            opt = BuildSackOption(ooo);
        SendSeg(TcpSegment::kAck, sndNxt, rcvNxt, std::vector<uint8_t>(), false, opt);
    }
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
    std::vector<std::pair<uint32_t, uint32_t>> sacks;
    ParseTcpOptions(seg.options, pmss, pwscale, hasMss, hasWs, hasSack, sacks);
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

    if(flags & TcpSegment::kRst)
    {
        if(state != Listening)
            Abort();
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
            iss = 2000;
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
        if(seg.ack > sndUna)
        {
            uint32_t acked = seg.ack - sndUna;
            sndUna = seg.ack;
            backoff = 0;
            retransmits = 0;
            dupAcks = 0;
            sndWnd = seg.window;
            if(wsEnabled)
                sndWnd = uint32_t(seg.window) << peerWscale;

            if(rttTiming)
            {
                uint64_t now = TcpNow(scheduler);
                double sample = double(now - rttStart);
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
                ssthresh = cwnd / 2;
                if(ssthresh < 2 * mss) ssthresh = 2 * mss;
                cwnd = ssthresh;

                uint32_t rseq = sndUna;
                if(!sacks.empty())
                {
                    uint32_t maxRight = 0;
                    for(const auto &b : sacks)
                        if(b.second > maxRight) maxRight = b.second;

                    for(const auto &kv : unacked)
                    {
                        if(kv.first >= maxRight)
                            break;
                        bool covered = false;
                        for(const auto &b : sacks)
                            if(kv.first >= b.first && kv.first < b.second)
                            {
                                covered = true;
                                break;
                            }
                        if(!covered)
                        {
                            rseq = kv.first;
                            break;
                        }
                    }
                }

                auto it = unacked.find(rseq);
                if(it == unacked.end()) it = unacked.lower_bound(rseq);
                if(it != unacked.end())
                {
                    ++retransmits;
                    ++totalRetransmits;
                    SendSeg(TcpSegment::kAck | TcpSegment::kPsh,
                            it->first, rcvNxt, it->second, true);
                    StartRto();
                }
                dupAcks = 0;
            }
        }
    }

    if(!seg.payload.empty())
    {
        if(seg.seq == rcvNxt)
        {
            Deliver(seg.payload);
            rcvNxt += uint32_t(seg.payload.size());
            std::vector<uint8_t> opt;
            if(sackEnabled)
                opt = BuildSackOption(ooo);
            SendSeg(TcpSegment::kAck, sndNxt, rcvNxt, std::vector<uint8_t>(), false, opt);
            DrainOoo();
        }
        else if(seg.seq > rcvNxt)
        {
            ooo[seg.seq] = seg.payload;
            std::vector<uint8_t> opt;
            if(sackEnabled)
                opt = BuildSackOption(ooo);
            SendSeg(TcpSegment::kAck, sndNxt, rcvNxt, std::vector<uint8_t>(), false, opt);
        }
        else
        {
            std::vector<uint8_t> opt;
            if(sackEnabled)
                opt = BuildSackOption(ooo);
            SendSeg(TcpSegment::kAck, sndNxt, rcvNxt, std::vector<uint8_t>(), false, opt);
        }
    }

    if(fin)
    {
        if(seg.seq + uint32_t(seg.payload.size()) == rcvNxt)
        {
            rcvNxt += 1;
            SendSeg(TcpSegment::kAck, sndNxt, rcvNxt, std::vector<uint8_t>(), false);

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
