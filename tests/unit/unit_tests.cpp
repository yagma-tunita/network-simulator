#include "core/Ipv4.hpp"
#include "core/Ipv4Subnet.hpp"
#include "core/Mac.hpp"
#include "core/ARP.hpp"
#include "core/IpPacket.hpp"
#include "core/IcmpMessage.hpp"
#include "core/EthernetFrame.hpp"
#include "core/UdpDatagram.hpp"
#include "core/TcpSegment.hpp"
#include "core/DhcpMessage.hpp"
#include "core/DnsMessage.hpp"
#include "core/RipMessage.hpp"
#include "core/OspfPacket.hpp"
#include "core/Md5.hpp"
#include "core/Sha.hpp"
#include "device/StpBpdu.hpp"
#include "device/EndDevice.hpp"
#include "device/Router.hpp"
#include "device/Port.hpp"
#include "topo/Topology.hpp"
#include "topo/JsonConfig.hpp"
#include "topo/CommandRunner.hpp"
#include "topo/Export.hpp"
#include "netstack/TcpConnection.hpp"
#include "engine/Engine.hpp"
#include "engine/Event.hpp"
#include "engine/Pcap.hpp"

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <iostream>
#include <functional>
#include <utility>
#include <fstream>

static int g_pass = 0;
static int g_fail = 0;

static void check(bool cond, const char *expr, const char *file, int line)
{
    if (cond)
    {
        ++g_pass;
    }
    else
    {
        ++g_fail;
        std::fprintf(stderr, "FAIL %s:%d  %s\n", file, line, expr);
    }
}

#define CHECK(x) check((x), #x, __FILE__, __LINE__)

namespace
{
    struct ChainEvent : Event
    {
        void Execute(Engine &en) override
        {
            en.ScheduleAfter(1, std::make_unique<ChainEvent>());
            en.ScheduleAfter(1, std::make_unique<ChainEvent>());
        }
        const char *Name() const override { return "chain"; }
    };

    struct CountEvent : Event
    {
        int *counter;
        explicit CountEvent(int *c) : counter(c) {}
        void Execute(Engine &) override { ++*counter; }
        const char *Name() const override { return "count"; }
    };

    std::string Capture(const std::function<void()> &fn)
    {
        std::ostringstream ss;
        std::streambuf *old = std::cout.rdbuf(ss.rdbuf());
        fn();
        std::cout.rdbuf(old);
        return ss.str();
    }
}

struct SegEvent : Event
{
    TcpConnection *dst;
    TcpSegment seg;
    Ipv4 src;

    SegEvent(TcpConnection *d, const TcpSegment &s, const Ipv4 &ip)
        : dst(d), seg(s), src(ip) {}

    void Execute(Engine &) override { dst->OnSegment(seg, src); }
    const char *Name() const override { return "tcp-wire"; }
};

struct Wire
{
    Engine *engine;
    TcpConnection *a;
    TcpConnection *b;
    bool dropA = false;

    Wire(Engine *e, TcpConnection *A, TcpConnection *B) : engine(e), a(A), b(B)
    {
        a->out = [this](const TcpSegment &s) {
            if(dropA) { dropA = false; return; }
            engine->ScheduleAfter(1, std::make_unique<SegEvent>(b, s, a->localIp));
        };
        b->out = [this](const TcpSegment &s) {
            engine->ScheduleAfter(1, std::make_unique<SegEvent>(a, s, b->localIp));
        };
    }
};

static void TestIpv4()
{
    Ipv4 a;
    CHECK(Ipv4::TryParse("192.168.1.1", a));
    CHECK(a.ToString() == "192.168.1.1");
    CHECK(a == Ipv4(192, 168, 1, 1));
    CHECK(!Ipv4::TryParse("256.0.0.1", a));
    CHECK(!Ipv4::TryParse("1.2.3", a));
    CHECK(!Ipv4::TryParse("1.2.3.4.5", a));
    CHECK(!Ipv4::TryParse("1.2.3.a", a));
    CHECK(!Ipv4::TryParse("", a));
    CHECK(Ipv4::Any() == Ipv4(0, 0, 0, 0));
    CHECK(Ipv4::Broadcast() == Ipv4(255, 255, 255, 255));
}

static void TestSubnet()
{
    Ipv4Subnet s("192.168.1.0/24");
    CHECK(s.prefix == 24);
    CHECK(s.Contains(Ipv4("192.168.1.1")));
    CHECK(s.Contains(Ipv4("192.168.1.254")));
    CHECK(!s.Contains(Ipv4("192.168.2.1")));
    CHECK(s.Mask() == Ipv4("255.255.255.0"));
    CHECK(s.Broadcast() == Ipv4("192.168.1.255"));

    Ipv4Subnet z("0.0.0.0/0");
    CHECK(z.Contains(Ipv4("8.8.8.8")));

    Ipv4Subnet h("10.0.0.5/32");
    CHECK(h.network == Ipv4("10.0.0.5"));
    CHECK(h.Contains(Ipv4("10.0.0.5")));
    CHECK(!h.Contains(Ipv4("10.0.0.6")));

    Ipv4Subnet bad;
    CHECK(!Ipv4Subnet::TryParse("10.0.0.0/33", bad));
    CHECK(!Ipv4Subnet::TryParse("10.0.0.0", bad));
}

static void TestMac()
{
    Mac m;
    CHECK(Mac::TryParse("aa:bb:cc:dd:ee:ff", m));
    CHECK(m.ToString() == "aa:bb:cc:dd:ee:ff");

    Mac n;
    CHECK(Mac::TryParse("AA-BB-CC-DD-EE-FF", n));
    CHECK(n == m);

    CHECK(!Mac::TryParse("aa:bb:cc:dd:ee", m));
    CHECK(!Mac::TryParse("gg:bb:cc:dd:ee:ff", m));
    CHECK(Mac::Broadcast().IsGroup());
    CHECK(!m.IsGroup());
    CHECK(m != Mac::Broadcast());
}

static void TestArp()
{
    ARP req = ARP::MakeRequest(Ipv4("192.168.1.1"), Mac("aa:aa:aa:aa:aa:01"),
                               Ipv4("192.168.1.2"));
    std::vector<uint8_t> b = req.ToBytes();
    CHECK(b.size() == 28);

    ARP out;
    CHECK(ARP::TryFromBytes(b, out));
    CHECK(out == req);
    CHECK(out.IsRequest());

    std::vector<uint8_t> shortBuf(b.begin(), b.begin() + 27);
    CHECK(!ARP::TryFromBytes(shortBuf, out));

    b[1] = 0x02;
    CHECK(!ARP::TryFromBytes(b, out));
}

static void TestIpPacket()
{
    std::vector<uint8_t> data{1, 2, 3, 4, 5};
    IpPacket p(Ipv4("10.0.0.1"), Ipv4("10.0.0.2"), IpPacket::kIcmp, data);
    std::vector<uint8_t> b = p.ToBytes();
    CHECK(b.size() == IpPacket::kHeaderSize + data.size());

    IpPacket out;
    CHECK(IpPacket::TryFromBytes(b, out));
    CHECK(out == p);

    CHECK(!IpPacket::TryFromBytes(std::vector<uint8_t>(10, 0), out));

    std::vector<uint8_t> bad = b;
    bad[0] = 0x44;
    CHECK(!IpPacket::TryFromBytes(bad, out));

    std::vector<uint8_t> badck = b;
    badck[8] ^= 0x01;
    CHECK(!IpPacket::TryFromBytes(badck, out));

    std::vector<uint8_t> trunc(b.begin(), b.begin() + 12);
    CHECK(!IpPacket::TryFromBytes(trunc, out));

    IpPacket t;
    t.ttl = 1;
    t.DecTtl();
    CHECK(t.ttl == 0);
    t.DecTtl();
    CHECK(t.ttl == 0);
}

static void TestIcmp()
{
    IcmpMessage m;
    m.type = IcmpMessage::kEchoRequest;
    m.id = 0x1234;
    m.seq = 7;
    m.payload = {9, 8, 7};

    std::vector<uint8_t> b = m.ToBytes();
    IcmpMessage out;
    CHECK(IcmpMessage::TryFromBytes(b, out));
    CHECK(out == m);
    CHECK(!IcmpMessage::TryFromBytes(std::vector<uint8_t>(7, 0), out));
}

static void TestEthernet()
{
    Mac d("01:00:00:00:00:02");
    Mac s("0a:00:00:00:00:01");
    std::vector<uint8_t> pl{1, 2, 3, 4};
    EthernetFrame f(d, s, EthernetFrame::kIPv4, pl);

    std::vector<uint8_t> plain = f.ToBytes();
    CHECK(plain.size() == 14 + pl.size());
    CHECK(plain[12] == 0x08 && plain[13] == 0x00);

    EthernetFrame r;
    CHECK(EthernetFrame::TryFromBytes(plain, r));
    CHECK(r == f);
    CHECK(!r.HasVlan());

    EthernetFrame t = f.WithVlan(100, 5, true);
    std::vector<uint8_t> tagged = t.ToBytes();
    CHECK(tagged.size() == 18 + pl.size());
    CHECK(tagged[12] == 0x81 && tagged[13] == 0x00);
    CHECK(tagged[16] == 0x08 && tagged[17] == 0x00);

    EthernetFrame rt;
    CHECK(EthernetFrame::TryFromBytes(tagged, rt));
    CHECK(rt == t);
    CHECK(rt.HasVlan());
    CHECK(rt.VlanId() == 100);
    CHECK(rt.vlanPcp == 5);
    CHECK(rt.vlanDei);
    CHECK(rt.Tci() == t.Tci());

    EthernetFrame u = rt.WithoutVlan();
    CHECK(!u.HasVlan());

    CHECK(!EthernetFrame::TryFromBytes(std::vector<uint8_t>(13, 0), r));
    std::vector<uint8_t> shortTagged(tagged.begin(), tagged.begin() + 17);
    CHECK(!EthernetFrame::TryFromBytes(shortTagged, rt));
}

static void TestStpBpdu()
{
    StpBpdu b;
    b.flags = 0;
    b.rootPriority = 4096;
    b.rootMac = Mac("11:11:11:11:11:01");
    b.rootPathCost = 19;
    b.bridgePriority = 32768;
    b.bridgeMac = Mac("22:22:22:22:22:01");
    b.portId = 2;
    b.messageAge = 0;

    std::vector<uint8_t> raw = b.ToBytes();
    CHECK(raw.size() == StpBpdu::kSize);

    StpBpdu out;
    CHECK(StpBpdu::TryFromBytes(raw, out));
    CHECK(out == b);
    CHECK(!StpBpdu::TryFromBytes(std::vector<uint8_t>(34, 0), out));

    std::vector<uint8_t> bad = raw;
    bad[3] = 0x02;
    CHECK(!StpBpdu::TryFromBytes(bad, out));
}

static void TestTopologyCaps()
{
    Topology t;
    for(std::size_t i = 0; i < Topology::kMaxDevices; ++i)
        t.AddEndDevice("D" + std::to_string(i));

    bool threw = false;
    try { t.AddEndDevice("overflow"); }
    catch(const std::length_error &) { threw = true; }
    CHECK(threw);
}

static void TestEngineEventCap()
{
    Engine e;
    e.maxEvents = 100;
    e.ScheduleAfter(0, std::make_unique<ChainEvent>());
    e.Run();
    CHECK(e.halted);
    CHECK(e.queue.Size() <= 100);
    CHECK(!e.queue.Empty());
}

static void TestIpExtra()
{
    Ipv4 a;
    CHECK(Ipv4::TryParse("0.0.0.0", a));
    CHECK(a == Ipv4::Any());
    CHECK(Ipv4::TryParse("255.255.255.255", a));
    CHECK(a == Ipv4::Broadcast());
    CHECK(!Ipv4::TryParse("1.2.3.256", a));
    CHECK(!Ipv4::TryParse("1..2.3", a));
    CHECK(!Ipv4::TryParse("1.2.3.", a));

    bool threw = false;
    try { Ipv4Subnet bad(Ipv4("10.0.0.0"), 33); }
    catch(const std::invalid_argument &) { threw = true; }
    CHECK(threw);

    Ipv4Subnet s;
    CHECK(!Ipv4Subnet::TryParse("10.0.0.0/", s));
    CHECK(!Ipv4Subnet::TryParse("10.0.0.0/abc", s));

    Mac m("aa:bb:cc:dd:ee:ff");
    CHECK(m.ToString() == "aa:bb:cc:dd:ee:ff");
    CHECK(!(m == Mac::Broadcast()));
    CHECK(Mac::Zero() < m);
}

static void TestMessagesExtra()
{
    ARP rep = ARP::MakeReply(Ipv4("10.0.0.2"), Mac("aa:aa:aa:aa:aa:02"),
                             Ipv4("10.0.0.1"), Mac("aa:aa:aa:aa:aa:01"));
    CHECK(rep.IsReply());
    CHECK(rep.ToString().find("reply") != std::string::npos);
    std::vector<uint8_t> rb = rep.ToBytes();
    rb[3] = 0x02;
    ARP outArp;
    CHECK(!ARP::TryFromBytes(rb, outArp));

    IpPacket p(Ipv4("1.1.1.1"), Ipv4("2.2.2.2"), IpPacket::kIcmp, {1, 2});
    CHECK(p.ToString().find("1.1.1.1") != std::string::npos);
    bool threw = false;
    try { IpPacket huge(Ipv4::Any(), Ipv4::Any(), 1, std::vector<uint8_t>(65600, 0)); (void)huge.ToBytes(); }
    catch(const std::length_error &) { threw = true; }
    CHECK(threw);

    IcmpMessage icmp;
    icmp.type = IcmpMessage::kTimeExceeded;
    std::vector<uint8_t> ib = icmp.ToBytes();
    IcmpMessage iout;
    CHECK(IcmpMessage::TryFromBytes(ib, iout));
    CHECK(iout.type == IcmpMessage::kTimeExceeded);
    CHECK(iout.ToString().find("ICMP") != std::string::npos);

    StpBpdu b;
    b.version = StpBpdu::kRstpVersion;
    StpBpdu bout;
    CHECK(StpBpdu::TryFromBytes(b.ToBytes(), bout));
    CHECK(bout.version == StpBpdu::kRstpVersion);
}

static void TestEngineBasics()
{
    Engine e;
    int count = 0;
    e.ScheduleAt(10, std::make_unique<CountEvent>(&count));
    e.ScheduleAt(5, std::make_unique<CountEvent>(&count));
    e.RunUntil(5);
    CHECK(count == 1);
    CHECK(e.Now() == 5);
    e.RunUntil(10);
    CHECK(count == 2);

    e.Reset();
    CHECK(e.Now() == 0);
    CHECK(e.queue.Empty());

    int traced = 0;
    e.trace = [&](uint64_t, const char *) { ++traced; };
    e.ScheduleAfter(1, std::make_unique<CountEvent>(&count));
    e.Run();
    CHECK(traced == 1);
}

static void TestTopologyBuilder()
{
    Topology t;
    t.AddEndDevice("A");
    t.AddSwitch("S");
    t.AddRouter("R");
    t.AddPort("A", Mac("aa:aa:aa:aa:aa:01"), Ipv4("10.0.0.1"), 24);
    t.AddPort("S", Mac("11:11:11:11:11:01"));
    t.AddPort("R", Mac("22:22:22:22:22:01"), Ipv4("10.0.0.254"), 24);
    t.Connect("A", 0, "S", 0, 2);
    CHECK(t.FindPort("A", 0) != nullptr);

    bool threw = false;
    try { t.FindDevice("nope"); } catch(const std::invalid_argument &) { threw = true; }
    CHECK(threw);
    threw = false;
    try { t.FindPort("A", 9); } catch(const std::out_of_range &) { threw = true; }
    CHECK(threw);
    threw = false;
    try { t.AddEndDevice("A"); } catch(const std::invalid_argument &) { threw = true; }
    CHECK(threw);

    t.RenameDevice("A", "HOST");
    CHECK(t.devices.count("HOST") == 1);
    CHECK(t.devices.count("A") == 0);
    t.SetPortIp("HOST", 0, Ipv4("10.0.0.9"), 24);
    CHECK(t.FindPort("HOST", 0)->ip == Ipv4("10.0.0.9"));

    t.Disconnect("HOST", 0);
    CHECK(t.links.empty());
    t.Connect("HOST", 0, "S", 0);
    t.RemovePort("S", 0);
    t.RemoveDevice("HOST");
    CHECK(t.devices.count("HOST") == 0);

    t.AddRoute("R", Ipv4Subnet("192.168.0.0/24"), Ipv4("10.0.0.1"));
    Router *r = dynamic_cast<Router *>(t.FindDevice("R"));
    CHECK(r != nullptr);
    CHECK(r->FindRoute(Ipv4("192.168.0.5")) != nullptr);

    t.Clear();
    CHECK(t.devices.empty());
    CHECK(t.ports.empty());
    CHECK(t.links.empty());
}

static void TestPingEndToEnd()
{
    Engine e;
    Topology t;
    t.SetEngine(&e);
    t.AddEndDevice("A");
    t.AddEndDevice("B");
    t.AddPort("A", Mac("aa:aa:aa:aa:aa:01"), Ipv4("10.0.0.1"), 24);
    t.AddPort("B", Mac("aa:aa:aa:aa:aa:02"), Ipv4("10.0.0.2"), 24);
    t.Connect("A", 0, "B", 0);

    EndDevice *a = dynamic_cast<EndDevice *>(t.FindDevice("A"));
    CHECK(a != nullptr);
    std::string out = Capture([&]() {
        a->SendPing(Ipv4("10.0.0.2"));
        e.RunUntil(1000);
    });
    CHECK(out.find("ping reply") != std::string::npos);
}

static void TestRouteEndToEnd()
{
    Engine e;
    Topology t;
    t.SetEngine(&e);
    t.AddEndDevice("A");
    t.AddEndDevice("B");
    t.AddRouter("R");
    t.AddPort("A", Mac("aa:aa:aa:aa:aa:01"), Ipv4("10.0.0.2"), 24);
    t.AddPort("R", Mac("22:22:22:22:22:01"), Ipv4("10.0.0.254"), 24);
    t.AddPort("B", Mac("bb:bb:bb:bb:bb:02"), Ipv4("10.0.1.2"), 24);
    t.AddPort("R", Mac("22:22:22:22:22:02"), Ipv4("10.0.1.254"), 24);
    t.Connect("A", 0, "R", 0);
    t.Connect("R", 1, "B", 0);

    EndDevice *a = dynamic_cast<EndDevice *>(t.FindDevice("A"));
    CHECK(a != nullptr);
    a->SetGateway(Ipv4("10.0.0.254"));
    std::string out = Capture([&]() {
        a->SendPing(Ipv4("10.0.1.2"));
        e.RunUntil(1000);
    });
    CHECK(out.find("ping reply") != std::string::npos);
}

static void TestIcmpErrors()
{
    Engine e;
    Topology t;
    t.SetEngine(&e);
    t.AddEndDevice("A");
    t.AddEndDevice("B");
    t.AddRouter("R");
    t.AddPort("A", Mac("aa:aa:aa:aa:aa:01"), Ipv4("10.0.0.2"), 24);
    t.AddPort("R", Mac("22:22:22:22:22:01"), Ipv4("10.0.0.254"), 24);
    t.AddPort("B", Mac("bb:bb:bb:bb:bb:02"), Ipv4("10.0.1.2"), 24);
    t.AddPort("R", Mac("22:22:22:22:22:02"), Ipv4("10.0.1.254"), 24);
    t.Connect("A", 0, "R", 0);
    t.Connect("R", 1, "B", 0);

    EndDevice *a = dynamic_cast<EndDevice *>(t.FindDevice("A"));
    CHECK(a != nullptr);
    a->SetGateway(Ipv4("10.0.0.254"));

    std::string out = Capture([&]() {
        a->SendPing(Ipv4("10.9.9.9"));
        e.RunUntil(1000);
    });
    CHECK(out.find("icmp unreachable") != std::string::npos);

    std::string out2 = Capture([&]() {
        a->SendPing(Ipv4("10.0.1.2"), 0, 1);
        e.RunUntil(2000);
    });
    CHECK(out2.find("icmp time exceeded") != std::string::npos);
}

static void TestPcapCaps()
{
    PcapWriter w;
    w.maxFrames = 2;
    w.maxBytes = 1024;
    CHECK(w.Open("/tmp/yanas_unit.pcap"));
    std::vector<uint8_t> frame(10, 0);
    w.Write(0, frame);
    w.Write(1, frame);
    w.Write(2, frame);
    CHECK(w.overflow);
    CHECK(w.Count() == 2);
    w.Close();
    std::remove("/tmp/yanas_unit.pcap");
}

static void TestJsonRoundTrip()
{
    Topology t;
    t.AddEndDevice("A");
    t.AddEndDevice("B");
    t.AddPort("A", Mac("aa:aa:aa:aa:aa:01"), Ipv4("10.0.0.1"), 24);
    t.AddPort("B", Mac("aa:aa:aa:aa:aa:02"), Ipv4("10.0.0.2"), 24);
    t.Connect("A", 0, "B", 0);

    LayoutMap layout;
    layout["A"] = std::make_pair(10, 20);
    std::string err;
    CHECK(SaveTopologyJson(t, "/tmp/yanas_unit.yn", layout, err));

    std::vector<std::string> cmds;
    LayoutMap parsed;
    std::string err2;
    CHECK(ParseConfigJson("/tmp/yanas_unit.yn", cmds, parsed, err2));
    CHECK(!cmds.empty());
    CHECK(parsed.count("A") == 1);
    CHECK(!ParseConfigJson("/tmp/yanas_missing.yn", cmds, parsed, err2));
    std::remove("/tmp/yanas_unit.yn");
}

static void TestCommandRunner()
{
    Engine e;
    Topology t;
    t.SetEngine(&e);
    CommandContext ctx;
    ctx.engine = &e;
    ctx.topo = &t;

    std::string out = Capture([&]() {
        RunScriptLine(ctx, "add-device PC1 end");
        RunScriptLine(ctx, "state");
    });
    CHECK(t.devices.count("PC1") == 1);
    CHECK(out.find("\"name\":\"PC1\"") != std::string::npos);

    RunScriptLine(ctx, "remove-device PC1");
    CHECK(t.devices.count("PC1") == 0);

    Capture([&]() { RunScriptLine(ctx, "new"); });
    CHECK(t.devices.empty());
}

static void TestExport()
{
    Topology t;
    t.AddEndDevice("A");
    t.AddSwitch("S");
    t.AddPort("A", Mac("aa:aa:aa:aa:aa:01"), Ipv4("10.0.0.1"), 24);
    t.AddPort("S", Mac("11:11:11:11:11:01"));
    t.Connect("A", 0, "S", 0);

    std::string err;
    CHECK(ExportDot(t, "/tmp/yn_unit.dot", err));
    CHECK(ExportSvg(t, "/tmp/yn_unit.svg", err));

    std::ifstream dot("/tmp/yn_unit.dot");
    std::stringstream ds;
    ds << dot.rdbuf();
    CHECK(ds.str().find("graph") != std::string::npos);

    std::ifstream svg("/tmp/yn_unit.svg");
    std::stringstream ss;
    ss << svg.rdbuf();
    CHECK(ss.str().find("<svg") != std::string::npos);

    std::remove("/tmp/yn_unit.dot");
    std::remove("/tmp/yn_unit.svg");
}

static void TestTraceroute()
{
    Engine e;
    Topology t;
    t.SetEngine(&e);
    t.AddEndDevice("A");
    t.AddEndDevice("B");
    t.AddRouter("R");
    t.AddPort("A", Mac("aa:aa:aa:aa:aa:01"), Ipv4("10.0.0.2"), 24);
    t.AddPort("R", Mac("22:22:22:22:22:01"), Ipv4("10.0.0.254"), 24);
    t.AddPort("B", Mac("bb:bb:bb:bb:bb:02"), Ipv4("10.0.1.2"), 24);
    t.AddPort("R", Mac("22:22:22:22:22:02"), Ipv4("10.0.1.254"), 24);
    t.Connect("A", 0, "R", 0);
    t.Connect("R", 1, "B", 0);

    EndDevice *a = dynamic_cast<EndDevice *>(t.FindDevice("A"));
    CHECK(a != nullptr);
    a->SetGateway(Ipv4("10.0.0.254"));
    std::string out = Capture([&]() {
        a->Traceroute(Ipv4("10.0.1.2"), 5);
        e.RunUntil(2000);
    });
    CHECK(out.find("hop 1: 10.0.0.254") != std::string::npos);
    CHECK(out.find("hop 2: 10.0.1.2") != std::string::npos);
}

static void TestUdp()
{
    UdpDatagram d;
    d.srcPort = 1234;
    d.dstPort = 7;
    d.payload = { 1, 2, 3 };

    std::vector<uint8_t> b = d.ToBytes();
    CHECK(b.size() == 11);

    UdpDatagram out;
    CHECK(UdpDatagram::TryFromBytes(b, out));
    CHECK(out == d);
    CHECK(!UdpDatagram::TryFromBytes(std::vector<uint8_t>(7, 0), out));

    std::vector<uint8_t> bad = b;
    bad[4] = 0;
    bad[5] = 4;
    CHECK(!UdpDatagram::TryFromBytes(bad, out));
}

static void TestUdpEcho()
{
    Engine e;
    Topology t;
    t.SetEngine(&e);
    t.AddEndDevice("A");
    t.AddEndDevice("B");
    t.AddPort("A", Mac("aa:aa:aa:aa:aa:01"), Ipv4("10.0.0.1"), 24);
    t.AddPort("B", Mac("aa:aa:aa:aa:aa:02"), Ipv4("10.0.0.2"), 24);
    t.Connect("A", 0, "B", 0);

    EndDevice *a = dynamic_cast<EndDevice *>(t.FindDevice("A"));
    EndDevice *b = dynamic_cast<EndDevice *>(t.FindDevice("B"));
    CHECK(a != nullptr && b != nullptr);
    b->SetUdpEcho(true, 7);

    std::string out = Capture([&]() {
        a->SendUdp(Ipv4("10.0.0.2"), 7, "hello");
        e.RunUntil(1000);
    });
    CHECK(out.find("udp from 10.0.0.2:7 \"hello\"") != std::string::npos);
}

static void TestCommands()
{
    Engine e;
    Topology t;
    t.SetEngine(&e);
    CommandContext ctx;
    ctx.engine = &e;
    ctx.topo = &t;

    std::string out = Capture([&]() {
        RunScriptLine(ctx, "generate tree 2 2");
        RunScriptLine(ctx, "map");
        RunScriptLine(ctx, "devices");
        RunScriptLine(ctx, "links");
    });
    CHECK(t.devices.size() == 11);
    CHECK(out.find("map:") != std::string::npos);
    CHECK(out.find("generated tree") != std::string::npos);

    Capture([&]() { RunScriptLine(ctx, "new"); });

    std::string out2 = Capture([&]() {
        RunScriptLine(ctx, "add-device A end");
        RunScriptLine(ctx, "add-device B end");
        RunScriptLine(ctx, "add-port A aa:aa:aa:aa:aa:01 10.0.0.1/24");
        RunScriptLine(ctx, "add-port B aa:aa:aa:aa:aa:02 10.0.0.2/24");
        RunScriptLine(ctx, "connect A:0 B:0");
        RunScriptLine(ctx, "udp-echo B on 7");
        RunScriptLine(ctx, "udp-send A 10.0.0.2 7 hi");
        RunScriptLine(ctx, "run 100");
    });
    CHECK(out2.find("udp from 10.0.0.2:7 \"hi\"") != std::string::npos);
}

static void TestTcpSegment()
{
    TcpSegment s;
    s.srcPort = 1234;
    s.dstPort = 80;
    s.seq = 100;
    s.ack = 200;
    s.flags = TcpSegment::kSyn | TcpSegment::kAck;
    s.payload = { 1, 2 };

    std::vector<uint8_t> b = s.ToBytes();
    CHECK(b.size() == 22);

    TcpSegment out;
    CHECK(TcpSegment::TryFromBytes(b, out));
    CHECK(out == s);
    CHECK(!TcpSegment::TryFromBytes(std::vector<uint8_t>(19, 0), out));

    std::vector<uint8_t> bad = b;
    bad[12] = 0x20;
    CHECK(!TcpSegment::TryFromBytes(bad, out));

    TcpSegment c;
    c.srcPort = 1111;
    c.dstPort = 2222;
    c.seq = 10;
    c.ack = 20;
    c.flags = TcpSegment::kAck;
    c.options = { 2, 4, 0x05, 0xB4 };
    c.payload = { 9, 8 };

    Ipv4 srcIp("10.0.0.1"), dstIp("10.0.0.2");
    std::vector<uint8_t> cb = c.ToBytes(srcIp, dstIp);
    TcpSegment co;
    CHECK(TcpSegment::TryFromBytes(cb, co, srcIp, dstIp));
    CHECK(co == c);

    std::vector<uint8_t> badc = cb;
    badc.back() ^= 0xFF;
    CHECK(!TcpSegment::TryFromBytes(badc, co, srcIp, dstIp));
}

static void TestDhcpMessage()
{
    DhcpMessage m;
    m.op = DhcpMessage::BootRequest;
    m.xid = 0x12345678u;
    m.chaddr = Mac("aa:aa:aa:aa:aa:01");
    m.type = DhcpMessage::Discover;

    std::vector<uint8_t> b = m.ToBytes();
    CHECK(b.size() >= 240);

    DhcpMessage out;
    CHECK(DhcpMessage::TryFromBytes(b, out));
    CHECK(out.op == DhcpMessage::BootRequest);
    CHECK(out.xid == 0x12345678u);
    CHECK(out.type == DhcpMessage::Discover);
    CHECK(out.chaddr == m.chaddr);

    m.op = DhcpMessage::BootReply;
    m.type = DhcpMessage::Ack;
    m.yiaddr = Ipv4("10.0.0.100");
    m.hasServerId = true;
    m.serverId = Ipv4("10.0.0.1");
    m.hasSubnetMask = true;
    m.subnetMask = Ipv4("255.255.255.0");
    m.hasRouter = true;
    m.router = Ipv4("10.0.0.1");
    m.hasDns = true;
    m.dns = Ipv4("10.0.0.53");
    m.hasLease = true;
    m.leaseTime = 3600;

    b = m.ToBytes();
    CHECK(DhcpMessage::TryFromBytes(b, out));
    CHECK(out.type == DhcpMessage::Ack);
    CHECK(out.yiaddr == Ipv4("10.0.0.100"));
    CHECK(out.hasServerId && out.serverId == Ipv4("10.0.0.1"));
    CHECK(out.hasSubnetMask && out.subnetMask == Ipv4("255.255.255.0"));
    CHECK(out.hasRouter && out.router == Ipv4("10.0.0.1"));
    CHECK(out.hasDns && out.dns == Ipv4("10.0.0.53"));
    CHECK(out.hasLease && out.leaseTime == 3600);

    CHECK(!DhcpMessage::TryFromBytes(std::vector<uint8_t>(10, 0), out));
    std::vector<uint8_t> trunc(b.begin(), b.begin() + 239);
    CHECK(!DhcpMessage::TryFromBytes(trunc, out));
    std::vector<uint8_t> bad = b;
    bad[236] = 0x11;
    CHECK(!DhcpMessage::TryFromBytes(bad, out));
}

static void TestDnsMessage()
{
    DnsMessage q;
    q.id = 7;
    q.flags = 0x0100;
    q.questions.push_back(DnsQuestion{ "example.com", 1, 1 });

    std::vector<uint8_t> b = q.ToBytes();
    CHECK(!b.empty());

    DnsMessage out;
    CHECK(DnsMessage::TryFromBytes(b, out));
    CHECK(out.id == 7);
    CHECK(!out.IsResponse());
    CHECK(out.questions.size() == 1);
    CHECK(out.questions[0].name == "example.com");
    CHECK(out.questions[0].qtype == 1);

    DnsMessage r;
    r.id = 7;
    r.flags = 0x8180;
    r.questions = q.questions;
    DnsAnswer a;
    a.name = "example.com";
    a.type = 1;
    a.cls = 1;
    a.ttl = 60;
    a.ip = Ipv4("10.0.0.1");
    r.answers.push_back(a);

    std::vector<uint8_t> rb = r.ToBytes();
    CHECK(DnsMessage::TryFromBytes(rb, out));
    CHECK(out.IsResponse());
    CHECK(out.Rcode() == 0);
    CHECK(out.answers.size() == 1);
    CHECK(out.answers[0].ip == Ipv4("10.0.0.1"));

    DnsMessage cname;
    cname.id = 8;
    cname.flags = 0x8180;
    cname.questions = q.questions;
    DnsAnswer ca;
    ca.name = "www.example.com";
    ca.type = 5;
    ca.target = "example.com";
    cname.answers.push_back(ca);
    std::vector<uint8_t> cb = cname.ToBytes();
    CHECK(DnsMessage::TryFromBytes(cb, out));
    CHECK(out.answers.size() == 1);
    CHECK(out.answers[0].type == 5);
    CHECK(out.answers[0].target == "example.com");

    CHECK(!DnsMessage::TryFromBytes(std::vector<uint8_t>(5, 0), out));

    DnsMessage badq;
    badq.questions.push_back(DnsQuestion{ "a..b", 1, 1 });
    CHECK(badq.ToBytes().empty());
}

static void TestRipMessage()
{
    RipMessage m;
    m.command = RipMessage::kResponse;
    m.entries.push_back(RipEntry{ Ipv4("10.0.0.0"), Ipv4("255.255.255.0"), 1 });
    m.entries.push_back(RipEntry{ Ipv4("192.168.2.0"), Ipv4("255.255.255.0"), 2 });

    std::vector<uint8_t> b = m.ToBytes();
    CHECK(b.size() == 4 + 40);

    RipMessage out;
    CHECK(RipMessage::TryFromBytes(b, out));
    CHECK(out.command == RipMessage::kResponse);
    CHECK(out.entries.size() == 2);
    CHECK(out.entries[0].dst == Ipv4("10.0.0.0"));
    CHECK(out.entries[0].mask == Ipv4("255.255.255.0"));
    CHECK(out.entries[0].metric == 1);
    CHECK(out.entries[1].metric == 2);

    CHECK(!RipMessage::TryFromBytes(std::vector<uint8_t>(3, 0), out));

    std::vector<uint8_t> bad = b;
    bad.pop_back();
    CHECK(!RipMessage::TryFromBytes(bad, out));

    RipMessage inf;
    inf.entries.push_back(RipEntry{ Ipv4("10.0.0.0"), Ipv4("255.0.0.0"), 20 });
    std::vector<uint8_t> ib = inf.ToBytes();
    CHECK(RipMessage::TryFromBytes(ib, out));
    CHECK(out.entries[0].metric == 16);
}

static void TestOspfPacket()
{
    OspfLsa r;
    r.header.type = OspfPacket::RouterLsa;
    r.header.id = Ipv4("1.1.1.1");
    r.header.advRouter = Ipv4("1.1.1.1");
    r.header.seq = 0x80000001u;
    r.flags = 0x01;
    r.links.push_back(OspfRouterLink{ Ipv4("10.0.0.2"), Ipv4("10.0.0.1"), 1, 10 });
    r.links.push_back(OspfRouterLink{ Ipv4("192.168.1.0"), Ipv4("255.255.255.0"), 3, 1 });

    std::vector<uint8_t> rb = OspfPacket::EncodeLsa(r);
    CHECK(rb.size() == 20 + 4 + 24);

    std::size_t off = 0;
    OspfLsa rd;
    CHECK(OspfPacket::DecodeLsa(rb, off, rb.size(), rd));
    CHECK(off == rb.size());
    CHECK(rd.header.type == OspfPacket::RouterLsa);
    CHECK(rd.header.id == Ipv4("1.1.1.1"));
    CHECK(rd.links.size() == 2);
    CHECK(rd.links[0].type == 1);
    CHECK(rd.links[0].metric == 10);
    CHECK(rd.links[1].type == 3);
    CHECK(rd.links[1].id == Ipv4("192.168.1.0"));

    std::vector<uint8_t> badLsa = rb;
    badLsa[24] ^= 0x01;
    off = 0;
    CHECK(!OspfPacket::DecodeLsa(badLsa, off, badLsa.size(), rd));

    OspfLsa n;
    n.header.type = OspfPacket::NetworkLsa;
    n.header.id = Ipv4("10.0.0.1");
    n.header.advRouter = Ipv4("1.1.1.1");
    n.mask = Ipv4("255.255.255.0");
    n.attached.push_back(Ipv4("1.1.1.1"));
    n.attached.push_back(Ipv4("2.2.2.2"));

    std::vector<uint8_t> nb = OspfPacket::EncodeLsa(n);
    off = 0;
    CHECK(OspfPacket::DecodeLsa(nb, off, nb.size(), rd));
    CHECK(rd.header.type == OspfPacket::NetworkLsa);
    CHECK(rd.mask == Ipv4("255.255.255.0"));
    CHECK(rd.attached.size() == 2);
    CHECK(rd.attached[1] == Ipv4("2.2.2.2"));

    OspfLsa sm;
    sm.header.type = OspfPacket::SummaryLsa;
    sm.header.id = Ipv4("192.168.3.0");
    sm.header.advRouter = Ipv4("1.1.1.1");
    sm.mask = Ipv4("255.255.255.0");
    sm.metric = 7;
    std::vector<uint8_t> sb = OspfPacket::EncodeLsa(sm);
    off = 0;
    CHECK(OspfPacket::DecodeLsa(sb, off, sb.size(), rd));
    CHECK(rd.header.type == OspfPacket::SummaryLsa);
    CHECK(rd.mask == Ipv4("255.255.255.0"));
    CHECK(rd.metric == 7);

    OspfLsa asbr;
    asbr.header.type = OspfPacket::SummaryAsbrLsa;
    asbr.header.id = Ipv4("3.3.3.3");
    asbr.header.advRouter = Ipv4("1.1.1.1");
    asbr.metric = 9;
    std::vector<uint8_t> asbrb = OspfPacket::EncodeLsa(asbr);
    off = 0;
    CHECK(OspfPacket::DecodeLsa(asbrb, off, asbrb.size(), rd));
    CHECK(rd.header.type == OspfPacket::SummaryAsbrLsa);
    CHECK(rd.metric == 9);

    OspfLsa ext;
    ext.header.type = OspfPacket::ExternalLsa;
    ext.header.id = Ipv4("172.16.0.0");
    ext.header.advRouter = Ipv4("3.3.3.3");
    ext.mask = Ipv4("255.255.0.0");
    ext.forwarding = Ipv4("10.0.0.9");
    ext.metric = 0x80000014u;
    std::vector<uint8_t> extb = OspfPacket::EncodeLsa(ext);
    off = 0;
    CHECK(OspfPacket::DecodeLsa(extb, off, extb.size(), rd));
    CHECK(rd.header.type == OspfPacket::ExternalLsa);
    CHECK(rd.mask == Ipv4("255.255.0.0"));
    CHECK(rd.forwarding == Ipv4("10.0.0.9"));
    CHECK((rd.metric & 0x00FFFFFFu) == 20);
    CHECK((rd.metric & 0x80000000u) != 0);

    OspfLsa n7;
    n7.header.type = OspfPacket::NssaExternalLsa;
    n7.header.id = Ipv4("172.16.0.0");
    n7.header.advRouter = Ipv4("4.4.4.4");
    n7.mask = Ipv4("255.255.0.0");
    n7.forwarding = Ipv4("10.0.0.7");
    n7.metric = 20;
    std::vector<uint8_t> n7b = OspfPacket::EncodeLsa(n7);
    off = 0;
    CHECK(OspfPacket::DecodeLsa(n7b, off, n7b.size(), rd));
    CHECK(rd.header.type == OspfPacket::NssaExternalLsa);
    CHECK(rd.mask == Ipv4("255.255.0.0"));
    CHECK(rd.forwarding == Ipv4("10.0.0.7"));
    CHECK(rd.metric == 20);

    OspfPacket hello;
    hello.type = OspfPacket::Hello;
    hello.routerId = Ipv4("1.1.1.1");
    hello.areaId = Ipv4::Any();
    hello.helloMask = Ipv4("255.255.255.0");
    hello.helloInterval = 10;
    hello.deadInterval = 40;
    hello.dr = Ipv4("10.0.0.1");
    hello.bdr = Ipv4::Any();
    hello.neighbors.push_back(Ipv4("2.2.2.2"));
    hello.authType = OspfPacket::AuthSimple;
    const char *pw = "secret";
    for(int i = 0; i < 6; ++i)
        hello.auth[i] = uint8_t(pw[i]);

    std::vector<uint8_t> hb = hello.ToBytes();
    OspfPacket out;
    CHECK(OspfPacket::TryFromBytes(hb, out));
    CHECK(out.type == OspfPacket::Hello);
    CHECK(out.routerId == Ipv4("1.1.1.1"));
    CHECK(out.helloMask == Ipv4("255.255.255.0"));
    CHECK(out.deadInterval == 40);
    CHECK(out.neighbors.size() == 1);
    CHECK(out.neighbors[0] == Ipv4("2.2.2.2"));
    CHECK(out.authType == OspfPacket::AuthSimple);
    CHECK(out.auth[0] == 's' && out.auth[5] == 't');

    std::vector<uint8_t> badPkt = hb;
    badPkt[30] ^= 0x01;
    CHECK(!OspfPacket::TryFromBytes(badPkt, out));

    OspfPacket dd;
    dd.type = OspfPacket::DatabaseDescription;
    dd.routerId = Ipv4("1.1.1.1");
    dd.areaId = Ipv4::Any();
    dd.ddFlags = 0x02;
    dd.ddSeq = 1234;
    dd.ddHeaders.push_back(r.header);
    std::vector<uint8_t> db = dd.ToBytes();
    CHECK(OspfPacket::TryFromBytes(db, out));
    CHECK(out.type == OspfPacket::DatabaseDescription);
    CHECK(out.ddSeq == 1234);
    CHECK(out.ddHeaders.size() == 1);
    CHECK(out.ddHeaders[0].id == Ipv4("1.1.1.1"));

    OspfPacket lsr;
    lsr.type = OspfPacket::LinkStateRequest;
    lsr.routerId = Ipv4("1.1.1.1");
    lsr.areaId = Ipv4::Any();
    lsr.requests.push_back(OspfLsrItem{ 1, Ipv4("2.2.2.2"), Ipv4("2.2.2.2") });
    std::vector<uint8_t> lb = lsr.ToBytes();
    CHECK(OspfPacket::TryFromBytes(lb, out));
    CHECK(out.type == OspfPacket::LinkStateRequest);
    CHECK(out.requests.size() == 1);
    CHECK(out.requests[0].id == Ipv4("2.2.2.2"));

    OspfPacket lsu;
    lsu.type = OspfPacket::LinkStateUpdate;
    lsu.routerId = Ipv4("1.1.1.1");
    lsu.areaId = Ipv4::Any();
    lsu.lsas.push_back(r);
    lsu.lsas.push_back(n);
    std::vector<uint8_t> ub = lsu.ToBytes();
    CHECK(OspfPacket::TryFromBytes(ub, out));
    CHECK(out.type == OspfPacket::LinkStateUpdate);
    CHECK(out.lsas.size() == 2);
    CHECK(out.lsas[0].header.type == OspfPacket::RouterLsa);
    CHECK(out.lsas[0].links.size() == 2);
    CHECK(out.lsas[1].header.type == OspfPacket::NetworkLsa);
    CHECK(out.lsas[1].attached.size() == 2);

    std::vector<uint8_t> badLsu = ub;
    badLsu.back() ^= 0x01;
    CHECK(!OspfPacket::TryFromBytes(badLsu, out));

    OspfPacket ack;
    ack.type = OspfPacket::LinkStateAck;
    ack.routerId = Ipv4("1.1.1.1");
    ack.areaId = Ipv4::Any();
    ack.acks.push_back(r.header);
    std::vector<uint8_t> ab = ack.ToBytes();
    CHECK(OspfPacket::TryFromBytes(ab, out));
    CHECK(out.type == OspfPacket::LinkStateAck);
    CHECK(out.acks.size() == 1);
    CHECK(out.acks[0].advRouter == Ipv4("1.1.1.1"));

    CHECK(!OspfPacket::TryFromBytes(std::vector<uint8_t>(23, 0), out));
}

static std::string Md5Hex(const std::vector<uint8_t> &data)
{
    std::array<uint8_t, 16> d = Md5(data);
    static const char *hex = "0123456789abcdef";
    std::string out;
    for(uint8_t b : d)
    {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0f]);
    }
    return out;
}

static void TestMd5()
{
    CHECK(Md5Hex({}) == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(Md5Hex({'a', 'b', 'c'}) == "900150983cd24fb0d6963f7d28e17f72");
    CHECK(Md5Hex({'m', 'e', 's', 's', 'a', 'g', 'e', ' ',
                  'd', 'i', 'g', 'e', 's', 't'}) ==
          "f96b697d7cb7938d525a2f31aaf161d0");
}

static void TestOspfMd5()
{
    std::string key = "0123456789abcdef";
    OspfPacket p;
    p.type = OspfPacket::Hello;
    p.routerId = Ipv4("10.0.0.1");
    p.areaId = Ipv4::Any();
    p.authType = OspfPacket::AuthMd5;
    p.authKeyId = 7;
    p.cryptoSeq = 42;
    p.md5Key = key;
    p.helloMask = Ipv4("255.255.255.0");
    p.helloInterval = 10;
    p.deadInterval = 40;

    std::vector<uint8_t> b = p.ToBytes();
    CHECK(b.size() == 60);

    OspfPacket out;
    CHECK(OspfPacket::TryFromBytes(b, out, key));
    CHECK(out.authType == OspfPacket::AuthMd5);
    CHECK(out.authKeyId == 7);
    CHECK(out.cryptoSeq == 42);
    CHECK(out.type == OspfPacket::Hello);

    CHECK(!OspfPacket::TryFromBytes(b, out, "ffffffffffffffff"));
    std::vector<uint8_t> bad = b;
    bad.back() ^= 0x01;
    CHECK(!OspfPacket::TryFromBytes(bad, out, key));

    OspfPacket badKey;
    badKey.type = OspfPacket::Hello;
    badKey.md5Key = "short";
    badKey.authType = OspfPacket::AuthMd5;
    CHECK(badKey.ToBytes().empty());
}

static void TestSha()
{
    auto hex = [](const uint8_t *d, std::size_t n) {
        static const char *h = "0123456789abcdef";
        std::string o;
        for(std::size_t i = 0; i < n; ++i)
        {
            o.push_back(h[d[i] >> 4]);
            o.push_back(h[d[i] & 0x0f]);
        }
        return o;
    };
    std::vector<uint8_t> abc{ 'a', 'b', 'c' };
    std::array<uint8_t, 20> s1 = Sha1(abc);
    CHECK(hex(s1.data(), 20) == "a9993e364706816aba3e25717850c26c9cd0d89d");
    std::array<uint8_t, 32> s2 = Sha256(abc);
    CHECK(hex(s2.data(), 32) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void TestOspfSha()
{
    OspfPacket p;
    p.type = OspfPacket::Hello;
    p.routerId = Ipv4("10.0.0.1");
    p.areaId = Ipv4::Any();
    p.authType = OspfPacket::AuthMd5;
    p.digestAlg = 2;
    p.authKeyId = 9;
    p.cryptoSeq = 3;
    p.md5Key = "secret";
    p.helloMask = Ipv4("255.255.255.0");
    p.helloInterval = 10;
    p.deadInterval = 40;

    std::vector<uint8_t> b = p.ToBytes();
    CHECK(b.size() == 24 + 20 + 32);

    OspfPacket out;
    CHECK(OspfPacket::TryFromBytes(b, out, "secret", 2));
    CHECK(out.authType == OspfPacket::AuthMd5);
    CHECK(out.digestAlg == 2);
    CHECK(out.authKeyId == 9);
    CHECK(out.cryptoSeq == 3);
    CHECK(!OspfPacket::TryFromBytes(b, out, "wrong", 2));
    CHECK(!OspfPacket::TryFromBytes(b, out, "secret", 1));

    std::vector<uint8_t> sha1b = p.ToBytes();
    OspfPacket p1 = p;
    p1.digestAlg = 1;
    sha1b = p1.ToBytes();
    CHECK(sha1b.size() == 24 + 20 + 20);
    CHECK(OspfPacket::TryFromBytes(sha1b, out, "secret", 1));
}

static void TestTcpEcho()
{
    Engine e;
    Topology t;
    t.SetEngine(&e);
    t.AddEndDevice("A");
    t.AddEndDevice("B");
    t.AddPort("A", Mac("aa:aa:aa:aa:aa:01"), Ipv4("10.0.0.1"), 24);
    t.AddPort("B", Mac("aa:aa:aa:aa:aa:02"), Ipv4("10.0.0.2"), 24);
    t.Connect("A", 0, "B", 0);

    EndDevice *a = dynamic_cast<EndDevice *>(t.FindDevice("A"));
    EndDevice *b = dynamic_cast<EndDevice *>(t.FindDevice("B"));
    CHECK(a != nullptr && b != nullptr);
    b->SetTcpEcho(true, 80);

    std::string out = Capture([&]() {
        a->TcpEchoClient(Ipv4("10.0.0.2"), 80, "hello");
        e.RunUntil(2000);
    });
    CHECK(out.find("tcp-lite echo from 10.0.0.2:80 \"hello\"") != std::string::npos);
}

static void TestAcl()
{
    Engine e;
    Topology t;
    t.SetEngine(&e);
    t.AddEndDevice("A");
    t.AddEndDevice("B");
    t.AddRouter("R");
    t.AddPort("A", Mac("aa:aa:aa:aa:aa:01"), Ipv4("10.0.0.2"), 24);
    t.AddPort("R", Mac("22:22:22:22:22:01"), Ipv4("10.0.0.254"), 24);
    t.AddPort("B", Mac("bb:bb:bb:bb:bb:02"), Ipv4("10.0.1.2"), 24);
    t.AddPort("R", Mac("22:22:22:22:22:02"), Ipv4("10.0.1.254"), 24);
    t.Connect("A", 0, "R", 0);
    t.Connect("R", 1, "B", 0);

    EndDevice *a = dynamic_cast<EndDevice *>(t.FindDevice("A"));
    Router *r = dynamic_cast<Router *>(t.FindDevice("R"));
    CHECK(a != nullptr && r != nullptr);
    a->SetGateway(Ipv4("10.0.0.254"));
    r->AddAcl(true, false, Ipv4Subnet("10.0.0.0/24"),
              Ipv4Subnet("10.0.1.0/24"), IpPacket::kIcmp);

    std::string out = Capture([&]() {
        a->SendPing(Ipv4("10.0.1.2"));
        e.RunUntil(500);
    });
    CHECK(out.find("ping timeout") != std::string::npos);
}

static void TestTcpCore()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    b.Listen(Ipv4("10.0.0.2"), 80);
    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 80, 1000);

    std::string got;
    b.onData = [&](const std::vector<uint8_t> &d) {
        got.append(reinterpret_cast<const char *>(d.data()), d.size());
    };

    e.RunUntil(1000);
    CHECK(a.state == TcpConnection::Established);
    CHECK(b.state == TcpConnection::Established);
    CHECK(a.wsEnabled);
    CHECK(b.wsEnabled);
    CHECK(a.peerWscale == 7);
    CHECK(b.peerWscale == 7);
    CHECK(a.mss == 1000);
    CHECK(b.mss == 1000);
    CHECK(a.tsEnabled);
    CHECK(b.tsEnabled);

    a.SendData({ 'h', 'e', 'l', 'l', 'o' });
    e.RunUntil(2000);
    CHECK(got == "hello");

    a.Close();
    e.RunUntil(3000);
    b.Close();
    e.RunUntil(20000);
    CHECK(a.state == TcpConnection::Closed);
    CHECK(b.state == TcpConnection::Closed);
}

static void TestTcpSack()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    b.Listen(Ipv4("10.0.0.2"), 80);
    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 80, 1000);

    std::string got;
    b.onData = [&](const std::vector<uint8_t> &d) {
        got.append(reinterpret_cast<const char *>(d.data()), d.size());
    };

    e.RunUntil(1000);
    CHECK(a.state == TcpConnection::Established);
    CHECK(a.sackEnabled);
    CHECK(b.sackEnabled);

    a.mss = 5;
    b.mss = 5;
    w.dropA = true;
    a.SendData({ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                 'q', 'r', 's', 't' });
    e.RunUntil(5000);

    CHECK(got == "abcdefghijklmnopqrst");
    CHECK(a.totalRetransmits > 0);
    CHECK(!a.inRecovery);
}

static void TestTcpSimultaneous()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 40001, 1000);
    b.OpenActive(Ipv4("10.0.0.2"), 40001, Ipv4("10.0.0.1"), 40000, 2000);
    e.RunUntil(2000);
    CHECK(a.state == TcpConnection::Established);
    CHECK(b.state == TcpConnection::Established);

    a.Close();
    b.Close();
    e.RunUntil(20000);
    CHECK(a.state == TcpConnection::Closed);
    CHECK(b.state == TcpConnection::Closed);
}

static void TestTcpPersist()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    b.Listen(Ipv4("10.0.0.2"), 80);
    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 80, 1000);

    std::string got;
    b.onData = [&](const std::vector<uint8_t> &d) {
        got.append(reinterpret_cast<const char *>(d.data()), d.size());
    };

    e.RunUntil(1000);
    CHECK(a.state == TcpConnection::Established);

    b.rcvWnd = 0;
    b.SendSeg(TcpSegment::kAck, b.sndNxt, b.rcvNxt, std::vector<uint8_t>(), false);
    e.RunUntil(1100);
    CHECK(a.sndWnd == 0);

    a.SendData({ 'z' });
    e.RunUntil(2000);

    b.rcvWnd = 65535;
    b.SendSeg(TcpSegment::kAck, b.sndNxt, b.rcvNxt, std::vector<uint8_t>(), false);
    e.RunUntil(6000);
    CHECK(got == "z");
}

static void TestTcpLimit()
{
    Engine e;
    Topology t;
    t.SetEngine(&e);
    t.AddEndDevice("A");
    t.AddEndDevice("B");
    t.AddPort("A", Mac("aa:aa:aa:aa:aa:01"), Ipv4("10.0.0.1"), 24);
    t.AddPort("B", Mac("aa:aa:aa:aa:aa:02"), Ipv4("10.0.0.2"), 24);
    t.Connect("A", 0, "B", 0);

    EndDevice *a = dynamic_cast<EndDevice *>(t.FindDevice("A"));
    CHECK(a != nullptr);
    for(std::size_t i = 0; i < EndDevice::kMaxTcpConns; ++i)
    {
        TcpConnection c;
        c.state = TcpConnection::Established;
        a->tcpConns.push_back(c);
    }

    std::string out = Capture([&]() {
        a->TcpConnect(Ipv4("10.0.0.2"), 80, "x");
    });
    CHECK(out.find("tcp: connection limit") != std::string::npos);
    CHECK(a->tcpConns.size() == EndDevice::kMaxTcpConns);
}

static void TestTcpDelayedAck()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    b.Listen(Ipv4("10.0.0.2"), 80);
    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 80, 0);

    std::string got;
    b.onData = [&](const std::vector<uint8_t> &d) {
        got.append(reinterpret_cast<const char *>(d.data()), d.size());
    };

    e.RunUntil(1000);
    uint64_t t = e.now;
    a.SendData({ 'x' });
    e.RunUntil(t + 2);
    CHECK(a.sndUna != a.sndNxt);
    e.RunUntil(t + 50);
    CHECK(a.sndUna == a.sndNxt);
    CHECK(got == "x");
}

static void TestTcpNagle()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    b.Listen(Ipv4("10.0.0.2"), 80);
    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 80, 0);

    std::string got;
    b.onData = [&](const std::vector<uint8_t> &d) {
        got.append(reinterpret_cast<const char *>(d.data()), d.size());
    };

    e.RunUntil(1000);
    uint64_t t = e.now;
    a.SendData({ 'a' });
    a.SendData({ 'b' });
    CHECK(a.sndNxt - a.sndUna == 1);
    e.RunUntil(t + 100);
    CHECK(got == "ab");
}

static void TestTcpDsack()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    b.Listen(Ipv4("10.0.0.2"), 80);
    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 80, 0);

    std::string got;
    b.onData = [&](const std::vector<uint8_t> &d) {
        got.append(reinterpret_cast<const char *>(d.data()), d.size());
    };

    e.RunUntil(1000);
    uint32_t dseq = a.sndNxt;
    a.SendData({ 'x' });
    e.RunUntil(1500);
    CHECK(got == "x");
    CHECK(a.dsacks == 0);

    TcpSegment dup;
    dup.srcPort = a.localPort;
    dup.dstPort = 80;
    dup.seq = dseq;
    dup.ack = b.sndNxt;
    dup.flags = TcpSegment::kAck | TcpSegment::kPsh;
    dup.window = 65535;
    dup.payload = { 'x' };
    b.OnSegment(dup, a.localIp);
    e.RunUntil(2000);
    CHECK(a.dsacks > 0);
}

static void TestTcpLargeTransfer()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    b.Listen(Ipv4("10.0.0.2"), 80);
    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 80, 0);

    std::vector<uint8_t> big(65536, 0x5a);
    std::size_t got = 0;
    b.onData = [&](const std::vector<uint8_t> &d) { got += d.size(); };

    e.RunUntil(1000);
    CHECK(a.state == TcpConnection::Established);

    a.SendData(big);
    e.RunUntil(200000);
    CHECK(got == big.size());
}

static void TestTcpPaws()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    b.Listen(Ipv4("10.0.0.2"), 80);
    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 80, 0);

    std::string got;
    b.onData = [&](const std::vector<uint8_t> &d) {
        got.append(reinterpret_cast<const char *>(d.data()), d.size());
    };

    e.RunUntil(1000);
    CHECK(a.state == TcpConnection::Established);
    CHECK(b.tsEnabled);
    CHECK(b.tsRecent > 0);

    auto tsopt = [](uint32_t val, uint32_t ecr) {
        std::vector<uint8_t> o{ 8, 10 };
        for(int i = 3; i >= 0; --i) o.push_back(uint8_t(val >> (8 * i)));
        for(int i = 3; i >= 0; --i) o.push_back(uint8_t(ecr >> (8 * i)));
        return o;
    };

    TcpSegment old;
    old.srcPort = a.localPort;
    old.dstPort = 80;
    old.seq = a.sndNxt;
    old.ack = b.sndNxt;
    old.flags = TcpSegment::kAck | TcpSegment::kPsh;
    old.options = tsopt(b.tsRecent - 1, 0);
    old.payload = { 'z' };
    b.OnSegment(old, a.localIp);
    CHECK(got.empty());

    TcpSegment fresh = old;
    fresh.options = tsopt(b.tsRecent + 1, 0);
    b.OnSegment(fresh, a.localIp);
    CHECK(got == "z");
}

static void TestTcpRstValidation()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    b.Listen(Ipv4("10.0.0.2"), 80);
    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 80, 0);
    e.RunUntil(1000);
    CHECK(a.state == TcpConnection::Established);

    TcpSegment rst;
    rst.srcPort = 80;
    rst.dstPort = 40000;
    rst.flags = TcpSegment::kRst | TcpSegment::kAck;
    rst.seq = a.rcvNxt + 70000;
    rst.ack = a.sndNxt;
    a.OnSegment(rst, b.localIp);
    CHECK(a.state == TcpConnection::Established);

    rst.seq = a.rcvNxt;
    a.OnSegment(rst, b.localIp);
    CHECK(a.state == TcpConnection::Closed);
}

static void TestTcpRttReset()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    b.Listen(Ipv4("10.0.0.2"), 80);
    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 80, 1000);
    e.RunUntil(1000);
    CHECK(a.state == TcpConnection::Established);
    CHECK(!a.rttValid);

    a.SendData({ 'a', 'b' });
    e.RunUntil(2000);
    CHECK(a.rttValid);
    CHECK(a.rto >= a.rtoMin);
    CHECK(a.rto <= a.rtoMax);

    TcpSegment rst;
    rst.srcPort = 80;
    rst.dstPort = 40000;
    rst.seq = b.sndNxt;
    rst.ack = a.sndNxt;
    rst.flags = TcpSegment::kRst | TcpSegment::kAck;
    a.OnSegment(rst, b.localIp);
    CHECK(a.state == TcpConnection::Closed);
}

static void TestTcpRetransmit()
{
    Engine e;
    TcpConnection a, b;
    a.SetScheduler(&e);
    b.SetScheduler(&e);
    Wire w(&e, &a, &b);

    b.Listen(Ipv4("10.0.0.2"), 80);
    a.OpenActive(Ipv4("10.0.0.1"), 40000, Ipv4("10.0.0.2"), 80, 1000);

    std::string got;
    b.onData = [&](const std::vector<uint8_t> &d) {
        got.append(reinterpret_cast<const char *>(d.data()), d.size());
    };

    e.RunUntil(1000);
    CHECK(a.state == TcpConnection::Established);

    w.dropA = true;
    a.SendData({ 'x' });
    e.RunUntil(5000);

    CHECK(got == "x");
    CHECK(a.totalRetransmits > 0);
}

int main()
{
    TestIpv4();
    TestSubnet();
    TestMac();
    TestArp();
    TestIpPacket();
    TestIcmp();
    TestEthernet();
    TestStpBpdu();
    TestTopologyCaps();
    TestEngineEventCap();
    TestIpExtra();
    TestMessagesExtra();
    TestEngineBasics();
    TestTopologyBuilder();
    TestPingEndToEnd();
    TestRouteEndToEnd();
    TestIcmpErrors();
    TestPcapCaps();
    TestJsonRoundTrip();
    TestCommandRunner();
    TestExport();
    TestTraceroute();
    TestUdp();
    TestUdpEcho();
    TestCommands();
    TestTcpSegment();
    TestDhcpMessage();
    TestDnsMessage();
    TestRipMessage();
    TestOspfPacket();
    TestMd5();
    TestOspfMd5();
    TestSha();
    TestOspfSha();
    TestTcpEcho();
    TestAcl();
    TestTcpCore();
    TestTcpRetransmit();
    TestTcpSack();
    TestTcpRttReset();
    TestTcpDsack();
    TestTcpRstValidation();
    TestTcpSimultaneous();
    TestTcpPersist();
    TestTcpLimit();
    TestTcpDelayedAck();
    TestTcpNagle();
    TestTcpLargeTransfer();
    TestTcpPaws();

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
