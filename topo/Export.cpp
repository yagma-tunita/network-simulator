#include "Export.hpp"
#include "Topology.hpp"
#include "../device/Device.hpp"
#include "../device/Port.hpp"
#include "../device/Switch.hpp"
#include "../device/Router.hpp"
#include "../link/Link.hpp"
#include <fstream>
#include <sstream>
#include <cmath>
#include <map>
#include <string>
#include <utility>
#include <cstddef>

namespace
{
    const char *KindOf(const Device *d)
    {
        if(dynamic_cast<const Router *>(d)) return "router";
        if(dynamic_cast<const Switch *>(d)) return "switch";
        return "end";
    }

    const char *ColorOf(const Device *d)
    {
        if(dynamic_cast<const Router *>(d)) return "#b26a00";
        if(dynamic_cast<const Switch *>(d)) return "#2e7d32";
        return "#305a9e";
    }

    std::string Esc(const std::string &s)
    {
        std::string o;
        for(char c : s)
        {
            switch(c)
            {
            case '&': o += "&amp;"; break;
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break;
            case '"': o += "&quot;"; break;
            default: o += c;
            }
        }
        return o;
    }

    std::string FirstIp(const Device *d)
    {
        for(const Port *p : d->portList)
            if(p->hasIp) return p->ip.ToString() + "/" + std::to_string(p->subnet.prefix);
        return std::string();
    }
}

bool ExportDot(const Topology &topo, const std::string &path, std::string &err)
{
    std::ofstream out(path);
    if(!out) { err = "cannot open '" + path + "'"; return false; }

    out << "graph yanas_net {\n"
        << "  graph [rankdir=LR, splines=true];\n"
        << "  node [style=filled, fontname=\"Helvetica\"];\n";

    for(const auto &kv : topo.devices)
    {
        const Device *d = kv.second.get();
        const char *shape = dynamic_cast<const Router *>(d) ? "diamond"
                          : dynamic_cast<const Switch *>(d) ? "box" : "ellipse";
        std::string ip = FirstIp(d);
        out << "  \"" << Esc(kv.first) << "\" [shape=" << shape
            << ", color=\"" << ColorOf(d) << "\", fontcolor=\"white\", label=\""
            << Esc(kv.first) << (ip.empty() ? "" : "\\n" + Esc(ip)) << "\"];\n";
    }

    std::map<const Port *, std::string> pmap;
    for(const auto &kv : topo.devices)
        for(const Port *p : kv.second.get()->portList) pmap[p] = kv.first;

    for(const auto &lp : topo.links)
    {
        const Link *l = lp.get();
        auto a = pmap.find(l->A);
        auto b = pmap.find(l->B);
        if(a == pmap.end() || b == pmap.end()) continue;
        out << "  \"" << Esc(a->second) << "\" -- \"" << Esc(b->second)
            << "\" [label=\"" << l->delay << "\"];\n";
    }

    out << "}\n";
    return true;
}

bool ExportSvg(const Topology &topo, const std::string &path, std::string &err)
{
    std::ofstream out(path);
    if(!out) { err = "cannot open '" + path + "'"; return false; }

    std::size_t n = topo.devices.size();
    int cols = int(std::ceil(std::sqrt(double(n > 0 ? n : 1))));
    if(cols < 1) cols = 1;

    std::map<std::string, std::pair<int, int>> pos;
    int i = 0;
    for(const auto &kv : topo.devices)
    {
        int c = i % cols;
        int r = i / cols;
        pos[kv.first] = { 90 + c * 180, 70 + r * 140 };
        ++i;
    }

    int rows = (int(n) + cols - 1) / cols;
    int width = cols * 180 + 40;
    int height = rows * 140 + 60;

    out << "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"" << width
        << "\" height=\"" << height << "\" viewBox=\"0 0 " << width << " "
        << height << "\">\n";
    out << "<rect width=\"100%\" height=\"100%\" fill=\"#eef3f7\"/>\n";
    out << "<text x=\"16\" y=\"24\" font-family=\"Tahoma, sans-serif\" font-size=\"14\" "
           "font-weight=\"bold\" fill=\"#10202e\">yanas net topology</text>\n";

    std::map<const Port *, std::string> pmap;
    for(const auto &kv : topo.devices)
        for(const Port *p : kv.second.get()->portList) pmap[p] = kv.first;

    for(const auto &lp : topo.links)
    {
        const Link *l = lp.get();
        auto a = pmap.find(l->A);
        auto b = pmap.find(l->B);
        if(a == pmap.end() || b == pmap.end()) continue;
        auto pa = pos.find(a->second);
        auto pb = pos.find(b->second);
        if(pa == pos.end() || pb == pos.end()) continue;

        out << "<line x1=\"" << pa->second.first << "\" y1=\"" << pa->second.second
            << "\" x2=\"" << pb->second.first << "\" y2=\"" << pb->second.second
            << "\" stroke=\"" << (l->enabled ? "#59636e" : "#c62828")
            << "\" stroke-width=\"3\""
            << (l->enabled ? "" : " stroke-dasharray=\"6 5\"") << "/>\n";
    }

    for(const auto &kv : topo.devices)
    {
        auto it = pos.find(kv.first);
        if(it == pos.end()) continue;
        const Device *d = kv.second.get();
        int cx = it->second.first;
        int cy = it->second.second;
        int left = cx - 60, top = cy - 27;

        out << "<rect x=\"" << left << "\" y=\"" << top
            << "\" width=\"120\" height=\"54\" fill=\"#ffffff\" stroke=\"#28323c\" stroke-width=\"1\"/>\n";
        out << "<rect x=\"" << left << "\" y=\"" << top
            << "\" width=\"120\" height=\"15\" fill=\"" << ColorOf(d) << "\"/>\n";
        out << "<text x=\"" << left + 5 << "\" y=\"" << top + 11
            << "\" font-family=\"Tahoma, sans-serif\" font-size=\"9\" fill=\"#ffffff\">"
            << Esc(KindOf(d)) << "</text>\n";
        out << "<text x=\"" << left + 6 << "\" y=\"" << top + 29
            << "\" font-family=\"Tahoma, sans-serif\" font-size=\"12\" font-weight=\"bold\" "
               "fill=\"#10202e\">" << Esc(kv.first) << "</text>\n";

        std::string ip = FirstIp(d);
        if(!ip.empty())
            out << "<text x=\"" << left + 6 << "\" y=\"" << top + 43
                << "\" font-family=\"Tahoma, sans-serif\" font-size=\"9\" fill=\"#455a64\">"
                << Esc(ip) << "</text>\n";
    }

    out << "</svg>\n";
    return true;
}
