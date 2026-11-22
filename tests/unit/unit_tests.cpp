#include "core/Ipv4.hpp"
#include "core/Ipv4Subnet.hpp"
#include "core/Mac.hpp"
#include "core/ARP.hpp"
#include "core/IpPacket.hpp"
#include "core/IcmpMessage.hpp"
#include "core/EthernetFrame.hpp"
#include "device/StpBpdu.hpp"

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

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

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
