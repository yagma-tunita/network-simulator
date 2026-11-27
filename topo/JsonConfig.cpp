#include "JsonConfig.hpp"
#include "Topology.hpp"
#include "../device/Device.hpp"
#include "../device/EndDevice.hpp"
#include "../device/Switch.hpp"
#include "../device/Router.hpp"
#include "../device/Port.hpp"
#include "../link/Link.hpp"
#include <fstream>
#include <sstream>
#include <map>
#include <string>
#include <vector>
#include <stdexcept>
#include <cctype>

namespace
{
    std::string Quote(const std::string &s)
    {
        std::string o = "\"";
        for(char c : s)
        {
            if(c == '"' || c == '\\') o += '\\';
            o += c;
        }
        o += "\"";
        return o;
    }

    const char *KindOf(const Device *d)
    {
        if(dynamic_cast<const Router *>(d)) return "router";
        if(dynamic_cast<const Switch *>(d)) return "switch";
        return "end";
    }

    const char *AclProtoName4(uint8_t proto)
    {
        if(proto == 1) return "icmp";
        if(proto == 6) return "tcp";
        if(proto == 17) return "udp";
        return "any";
    }

    const char *AclProtoName6(uint8_t proto)
    {
        if(proto == 58) return "icmpv6";
        if(proto == 6) return "tcp";
        if(proto == 17) return "udp";
        return "any";
    }

    struct JVal
    {
        enum Type { Null, Bool, Num, Str, Arr, Obj } type = Null;
        bool b = false;
        double num = 0;
        std::string str;
        std::vector<JVal> arr;
        std::vector<std::pair<std::string, JVal>> obj;

        const JVal *Get(const std::string &k) const
        {
            for(const auto &kv : obj) if(kv.first == k) return &kv.second;
            return nullptr;
        }
        std::string S(const std::string &k, const std::string &def = "") const
        {
            const JVal *v = Get(k);
            return (v && v->type == Str) ? v->str : def;
        }
        double N(const std::string &k, double def = 0) const
        {
            const JVal *v = Get(k);
            return (v && v->type == Num) ? v->num : def;
        }
        bool B(const std::string &k, bool def = false) const
        {
            const JVal *v = Get(k);
            return (v && v->type == Bool) ? v->b : def;
        }
    };

    struct Parser
    {
        const std::string &s;
        std::size_t i = 0;
        explicit Parser(const std::string &src) : s(src) {}

        void Ws()
        {
            while(i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
        }

        JVal Parse()
        {
            Ws();
            JVal v = Value();
            Ws();
            if(i != s.size()) throw std::runtime_error("trailing characters in JSON");
            return v;
        }

        JVal Value()
        {
            Ws();
            if(i >= s.size()) throw std::runtime_error("unexpected end of JSON");
            char c = s[i];
            if(c == '{') return Object();
            if(c == '[') return Array();
            if(c == '"') { JVal v; v.type = JVal::Str; v.str = String(); return v; }
            if(c == 't' || c == 'f') return Bool();
            if(c == 'n') return Null();
            return Number();
        }

        JVal Object()
        {
            JVal v; v.type = JVal::Obj;
            ++i;
            Ws();
            if(i < s.size() && s[i] == '}') { ++i; return v; }
            while(true)
            {
                Ws();
                std::string key = String();
                Ws();
                if(i >= s.size() || s[i] != ':') throw std::runtime_error("expected ':'");
                ++i;
                JVal val = Value();
                v.obj.emplace_back(std::move(key), std::move(val));
                Ws();
                if(i < s.size() && s[i] == ',') { ++i; continue; }
                if(i < s.size() && s[i] == '}') { ++i; break; }
                throw std::runtime_error("expected ',' or '}'");
            }
            return v;
        }

        JVal Array()
        {
            JVal v; v.type = JVal::Arr;
            ++i;
            Ws();
            if(i < s.size() && s[i] == ']') { ++i; return v; }
            while(true)
            {
                v.arr.push_back(Value());
                Ws();
                if(i < s.size() && s[i] == ',') { ++i; continue; }
                if(i < s.size() && s[i] == ']') { ++i; break; }
                throw std::runtime_error("expected ',' or ']'");
            }
            return v;
        }

        std::string String()
        {
            if(i >= s.size() || s[i] != '"') throw std::runtime_error("expected string");
            ++i;
            std::string out;
            while(i < s.size())
            {
                char c = s[i++];
                if(c == '"') return out;
                if(c == '\\')
                {
                    if(i >= s.size()) break;
                    char e = s[i++];
                    switch(e)
                    {
                    case 'n': out += '\n'; break;
                    case 't': out += '\t'; break;
                    case 'r': out += '\r'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    default: out += e; break;
                    }
                }
                else
                {
                    out += c;
                }
            }
            throw std::runtime_error("unterminated string");
        }

        JVal Bool()
        {
            JVal v; v.type = JVal::Bool;
            if(s.compare(i, 4, "true") == 0) { v.b = true; i += 4; }
            else if(s.compare(i, 5, "false") == 0) { v.b = false; i += 5; }
            else throw std::runtime_error("bad literal");
            return v;
        }

        JVal Null()
        {
            if(s.compare(i, 4, "null") != 0) throw std::runtime_error("bad literal");
            i += 4;
            return JVal{};
        }

        JVal Number()
        {
            std::size_t start = i;
            if(i < s.size() && s[i] == '-') ++i;
            while(i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
            if(i < s.size() && s[i] == '.')
            {
                ++i;
                while(i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
            }
            if(i < s.size() && (s[i] == 'e' || s[i] == 'E'))
            {
                ++i;
                if(i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
                while(i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
            }
            if(start == i) throw std::runtime_error("bad number");
            JVal v; v.type = JVal::Num;
            v.num = std::stod(s.substr(start, i - start));
            return v;
        }
    };

    std::string Int(double d)
    {
        return std::to_string(static_cast<long long>(d));
    }
}

bool SaveTopologyJson(const Topology &topo, const std::string &path,
                      const LayoutMap &layout, std::string &err)
{
    std::ofstream out(path);
    if(!out) { err = "cannot open '" + path + "'"; return false; }

    out << "{\n";

    out << "  \"devices\": [";
    bool first = true;
    for(const auto &kv : topo.devices)
    {
        const Device *d = kv.second.get();
        if(!first) out << ",";
        first = false;
        out << "{\"name\":" << Quote(kv.first) << ",\"kind\":" << Quote(KindOf(d)) << "}";
    }
    out << "],\n";

    out << "  \"ports\": [";
    first = true;
    for(const auto &kv : topo.devices)
    {
        const Device *d = kv.second.get();
        for(std::size_t i = 0; i < d->portList.size(); ++i)
        {
            const Port *p = d->portList[i];
            if(!first) out << ",";
            first = false;
            out << "{\"device\":" << Quote(kv.first)
                << ",\"mac\":" << Quote(p->mac.ToString())
                << ",\"ip\":" << Quote(p->hasIp ? p->ip.ToString() : std::string())
                << ",\"prefix\":" << int(p->subnet.prefix)
                << ",\"ip6\":" << Quote(p->hasIp6 ? p->ip6.ToString() : std::string())
                << ",\"prefix6\":" << int(p->prefix6)
                << ",\"vlan\":" << p->vlan
                << ",\"tagged\":" << (p->tagged ? "true" : "false") << "}";
        }
    }
    out << "],\n";

    std::map<const Port *, std::pair<std::string, std::size_t>> pmap;
    for(const auto &kv : topo.devices)
    {
        const Device *d = kv.second.get();
        for(std::size_t i = 0; i < d->portList.size(); ++i)
            pmap[d->portList[i]] = { kv.first, i };
    }

    out << "  \"nat\": [";
    first = true;
    for(const auto &kv : topo.devices)
    {
        const Router *r = dynamic_cast<const Router *>(kv.second.get());
        if(!r || !r->natEnabled || !r->natInside || !r->natOutside)
            continue;
        auto in = pmap.find(r->natInside);
        auto outPort = pmap.find(r->natOutside);
        if(in == pmap.end() || outPort == pmap.end())
            continue;
        if(!first) out << ",";
        first = false;
        out << "{\"router\":" << Quote(kv.first)
            << ",\"inside\":" << Quote(in->second.first + ":" +
                                      std::to_string(in->second.second))
            << ",\"outside\":" << Quote(outPort->second.first + ":" +
                                       std::to_string(outPort->second.second))
            << "}";
    }
    out << "],\n";

    out << "  \"natForwards\": [";
    first = true;
    for(const auto &kv : topo.devices)
    {
        const Router *r = dynamic_cast<const Router *>(kv.second.get());
        if(!r)
            continue;
        for(const Router::NatForward &f : r->natForwards)
        {
            if(!first) out << ",";
            first = false;
            out << "{\"router\":" << Quote(kv.first)
                << ",\"proto\":" << Quote(f.proto == IpPacket::kTcp
                                            ? "tcp" : "udp")
                << ",\"public\":" << f.publicPort
                << ",\"inside-ip\":" << Quote(f.insideIp.ToString())
                << ",\"inside-port\":" << f.insidePort << "}";
        }
    }
    out << "],\n";

    out << "  \"span\": [";
    first = true;
    for(const auto &kv : topo.devices)
    {
        const Switch *sw = dynamic_cast<const Switch *>(kv.second.get());
        if(!sw || !sw->spanSource || !sw->spanDest)
            continue;
        auto src = pmap.find(sw->spanSource);
        auto dst = pmap.find(sw->spanDest);
        if(src == pmap.end() || dst == pmap.end())
            continue;
        if(!first) out << ",";
        first = false;
        out << "{\"switch\":" << Quote(kv.first)
            << ",\"src\":" << Quote(src->second.first + ":" +
                                   std::to_string(src->second.second))
            << ",\"dst\":" << Quote(dst->second.first + ":" +
                                   std::to_string(dst->second.second))
            << "}";
    }
    out << "],\n";

    out << "  \"links\": [";
    first = true;
    for(const auto &lp : topo.links)
    {
        const Link *l = lp.get();
        auto a = pmap.find(l->A);
        auto b = pmap.find(l->B);
        if(a == pmap.end() || b == pmap.end()) continue;
        if(!first) out << ",";
        first = false;
        out << "{\"a_device\":" << Quote(a->second.first)
            << ",\"a_port\":" << a->second.second
            << ",\"b_device\":" << Quote(b->second.first)
            << ",\"b_port\":" << b->second.second
            << ",\"delay\":" << l->delay << "}";
    }
    out << "],\n";

    out << "  \"stp\": [";
    first = true;
    for(const auto &kv : topo.devices)
    {
        const Switch *sw = dynamic_cast<const Switch *>(kv.second.get());
        if(!sw || !sw->stpEnabled) continue;
        if(!first) out << ",";
        first = false;
        out << "{\"device\":" << Quote(kv.first)
            << ",\"enabled\":true"
            << ",\"priority\":" << sw->stpBridgePriority
            << ",\"mode\":" << Quote(sw->rstp ? "rstp" : "stp") << "}";
    }
    out << "],\n";

    out << "  \"routes\": [";
    first = true;
    for(const auto &kv : topo.devices)
    {
        const Router *r = dynamic_cast<const Router *>(kv.second.get());
        if(!r) continue;
        for(const Route &rt : r->routeTable)
        {
            if(rt.direct) continue;
            if(!first) out << ",";
            first = false;
            out << "{\"router\":" << Quote(kv.first)
                << ",\"dst\":" << Quote(rt.dst.ToString())
                << ",\"next\":" << Quote(rt.nextHop.ToString()) << "}";
        }
    }
    out << "],\n";

    out << "  \"routes6\": [";
    first = true;
    for(const auto &kv : topo.devices)
    {
        const Router *r = dynamic_cast<const Router *>(kv.second.get());
        if(!r) continue;
        for(const Ipv6Route &rt : r->route6)
        {
            if(rt.direct) continue;
            if(!first) out << ",";
            first = false;
            out << "{\"router\":" << Quote(kv.first)
                << ",\"dst\":" << Quote(rt.dst.ToString())
                << ",\"next\":" << Quote(rt.nextHop.ToString()) << "}";
        }
    }
    out << "],\n";

    out << "  \"gateways\": [";
    first = true;
    for(const auto &kv : topo.devices)
    {
        const EndDevice *e = dynamic_cast<const EndDevice *>(kv.second.get());
        if(!e || !e->hasGateway) continue;
        if(!first) out << ",";
        first = false;
        out << "{\"device\":" << Quote(kv.first)
            << ",\"ip\":" << Quote(e->gateway.ToString()) << "}";
    }
    out << "],\n";

    out << "  \"gateways6\": [";
    first = true;
    for(const auto &kv : topo.devices)
    {
        const EndDevice *e = dynamic_cast<const EndDevice *>(kv.second.get());
        if(!e || !e->hasGateway6) continue;
        if(!first) out << ",";
        first = false;
        out << "{\"device\":" << Quote(kv.first)
            << ",\"ip\":" << Quote(e->gateway6.ToString()) << "}";
    }
    out << "],\n";

    out << "  \"acl\": [";
    first = true;
    for(const auto &kv : topo.devices)
    {
        const Router *r = dynamic_cast<const Router *>(kv.second.get());
        if(!r) continue;
        auto emit = [&](const std::vector<Router::AclRule> &rules,
                        const char *dir) {
            for(const Router::AclRule &a : rules)
            {
                if(!first) out << ",";
                first = false;
                out << "{\"router\":" << Quote(kv.first)
                    << ",\"dir\":" << Quote(dir)
                    << ",\"action\":" << Quote(a.permit ? "allow" : "deny")
                    << ",\"src\":" << Quote(a.src.ToString())
                    << ",\"dst\":" << Quote(a.dst.ToString())
                    << ",\"proto\":" << Quote(AclProtoName4(a.proto)) << "}";
            }
        };
        emit(r->aclIn, "in");
        emit(r->aclOut, "out");
    }
    out << "],\n";

    out << "  \"acl6\": [";
    first = true;
    for(const auto &kv : topo.devices)
    {
        const Router *r = dynamic_cast<const Router *>(kv.second.get());
        if(!r) continue;
        auto emit = [&](const std::vector<Router::Acl6Rule> &rules,
                        const char *dir) {
            for(const Router::Acl6Rule &a : rules)
            {
                if(!first) out << ",";
                first = false;
                out << "{\"router\":" << Quote(kv.first)
                    << ",\"dir\":" << Quote(dir)
                    << ",\"action\":" << Quote(a.permit ? "allow" : "deny")
                    << ",\"src\":" << Quote(a.src.ToString())
                    << ",\"dst\":" << Quote(a.dst.ToString())
                    << ",\"proto\":" << Quote(AclProtoName6(a.proto)) << "}";
            }
        };
        emit(r->acl6In, "in");
        emit(r->acl6Out, "out");
    }
    out << "],\n";

    out << "  \"layout\": [";
    first = true;
    for(const auto &kv : layout)
    {
        if(!first) out << ",";
        first = false;
        out << "{\"device\":" << Quote(kv.first)
            << ",\"x\":" << kv.second.first
            << ",\"y\":" << kv.second.second << "}";
    }
    out << "]\n";

    out << "}\n";
    return true;
}

bool ParseConfigJson(const std::string &path, std::vector<std::string> &cmds,
                     LayoutMap &layout, std::string &err)
{
    std::ifstream in(path);
    if(!in) { err = "cannot open '" + path + "'"; return false; }

    std::stringstream ss;
    ss << in.rdbuf();
    std::string text = ss.str();

    JVal root;
    try
    {
        Parser p(text);
        root = p.Parse();
    }
    catch(const std::exception &e)
    {
        err = e.what();
        return false;
    }

    if(root.type != JVal::Obj) { err = "top-level JSON must be an object"; return false; }

    std::map<std::string, std::size_t> idx;

    const JVal *devs = root.Get("devices");
    if(devs && devs->type == JVal::Arr)
        for(const auto &d : devs->arr)
            cmds.push_back("add-device " + d.S("name") + " " + d.S("kind"));

    const JVal *ports = root.Get("ports");
    if(ports && ports->type == JVal::Arr)
    {
        for(const auto &p : ports->arr)
        {
            std::string dev = p.S("device");
            std::string mac = p.S("mac");
            std::string ip = p.S("ip");
            std::string ip6 = p.S("ip6");
            int prefix6 = int(p.N("prefix6", 64));
            int prefix = int(p.N("prefix", 0));
            bool tagged = p.B("tagged", false);
            int vlan = int(p.N("vlan", 0));

            std::string cmd = "add-port " + dev + " " + mac;
            if(!ip.empty()) cmd += " " + ip + "/" + std::to_string(prefix);
            cmds.push_back(cmd);

            std::size_t pi = idx[dev]++;
            std::string ref = dev + ":" + std::to_string(pi);
            if(!ip6.empty()) cmds.push_back("set-ip6 " + ref + " " + ip6 + "/" + std::to_string(prefix6));
            if(tagged) cmds.push_back("set-trunk " + ref + " " + std::to_string(vlan));
            else if(vlan != 0) cmds.push_back("set-vlan " + ref + " " + std::to_string(vlan));
        }
    }

    const JVal *links = root.Get("links");
    if(links && links->type == JVal::Arr)
    {
        for(const auto &l : links->arr)
        {
            cmds.push_back("connect " +
                l.S("a_device") + ":" + Int(l.N("a_port")) + " " +
                l.S("b_device") + ":" + Int(l.N("b_port")) + " " +
                Int(l.N("delay", 1)));
        }
    }

    const JVal *stp = root.Get("stp");
    if(stp && stp->type == JVal::Arr)
    {
        for(const auto &s : stp->arr)
        {
            std::string dev = s.S("device");
            cmds.push_back("set-bridge " + dev + " " + Int(s.N("priority", 32768)));
            cmds.push_back("set-stp-mode " + dev + " " + s.S("mode", "stp"));
            if(s.B("enabled", true)) cmds.push_back("set-stp " + dev + " on");
        }
    }

    const JVal *routes = root.Get("routes");
    if(routes && routes->type == JVal::Arr)
        for(const auto &r : routes->arr)
            cmds.push_back("add-route " + r.S("router") + " " + r.S("dst") + " " + r.S("next"));

    const JVal *routes6 = root.Get("routes6");
    if(routes6 && routes6->type == JVal::Arr)
        for(const auto &r : routes6->arr)
            cmds.push_back("add-route6 " + r.S("router") + " " + r.S("dst") + " " + r.S("next"));

    const JVal *gws = root.Get("gateways");
    if(gws && gws->type == JVal::Arr)
        for(const auto &g : gws->arr)
            cmds.push_back("set-gateway " + g.S("device") + " " + g.S("ip"));

    const JVal *gws6 = root.Get("gateways6");
    if(gws6 && gws6->type == JVal::Arr)
        for(const auto &g : gws6->arr)
            cmds.push_back("set-gateway6 " + g.S("device") + " " + g.S("ip"));

    const JVal *acls = root.Get("acl");
    if(acls && acls->type == JVal::Arr)
        for(const auto &a : acls->arr)
            cmds.push_back("acl " + a.S("router") + " " + a.S("dir") + " " +
                           a.S("action") + " " + a.S("src") + " " +
                           a.S("dst") + " " + a.S("proto"));

    const JVal *acls6 = root.Get("acl6");
    if(acls6 && acls6->type == JVal::Arr)
        for(const auto &a : acls6->arr)
            cmds.push_back("acl6 " + a.S("router") + " " + a.S("dir") + " " +
                           a.S("action") + " " + a.S("src") + " " +
                           a.S("dst") + " " + a.S("proto"));

    const JVal *nat = root.Get("nat");
    if(nat && nat->type == JVal::Arr)
        for(const auto &n : nat->arr)
            cmds.push_back("nat " + n.S("router") + " on " +
                           n.S("inside") + " " + n.S("outside"));

    const JVal *natForwards = root.Get("natForwards");
    if(natForwards && natForwards->type == JVal::Arr)
        for(const auto &n : natForwards->arr)
            cmds.push_back("nat-port " + n.S("router") + " " + n.S("proto") +
                           " " + Int(n.N("public")) + " " + n.S("inside-ip") +
                           " " + Int(n.N("inside-port")));

    const JVal *span = root.Get("span");
    if(span && span->type == JVal::Arr)
        for(const auto &s : span->arr)
            cmds.push_back("span " + s.S("switch") + " " + s.S("src") +
                           " " + s.S("dst"));

    const JVal *lay = root.Get("layout");
    if(lay && lay->type == JVal::Arr)
    {
        for(const auto &e : lay->arr)
        {
            std::string dev = e.S("device");
            if(dev.empty()) continue;
            layout[dev] = { int(e.N("x", 0)), int(e.N("y", 0)) };
        }
    }

    return true;
}
