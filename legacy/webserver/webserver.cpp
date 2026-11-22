#include "webserver.hpp"
#include "Version.hpp"
#include "../engine/Engine.hpp"
#include "../topo/Topology.hpp"
#include "../topo/CommandRunner.hpp"
#include "../device/Device.hpp"
#include "../device/Port.hpp"
#include "../device/Switch.hpp"
#include "../device/Router.hpp"
#include "../device/EndDevice.hpp"
#include "../link/Link.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/Mac.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <cstring>
#include <cctype>
#include <cstdint>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>
#include <cstddef>
#include <stdexcept>

#ifdef _WIN32
using socket_t = SOCKET;
static const socket_t kInvalidSocket = INVALID_SOCKET;
using iolen_t = int;
inline void CloseSock(socket_t s) { if(s != INVALID_SOCKET) closesocket(s); }
inline bool StartSockets()
{
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0;
}
#else
using socket_t = int;
static const socket_t kInvalidSocket = -1;
using iolen_t = ssize_t;
inline void CloseSock(socket_t s) { if(s >= 0) close(s); }
inline bool StartSockets() { return true; }
#endif

namespace
{
    std::string JsonQuote(const std::string &s)
    {
        std::string o = "\"";
        for(char c : s)
        {
            switch(c)
            {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if(static_cast<unsigned char>(c) < 0x20) o += ' ';
                else o += c;
            }
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

    const char *StpStateName(const Port *p)
    {
        const Switch *sw = dynamic_cast<const Switch *>(p->owner);
        if(!sw || !sw->stpEnabled) return "up";

        switch(p->stpState)
        {
        case StpPortState::Disabled:   return "disabled";
        case StpPortState::Blocking:   return "blocking";
        case StpPortState::Listening:  return "listening";
        case StpPortState::Learning:   return "learning";
        case StpPortState::Forwarding: return "forwarding";
        }
        return "up";
    }

    std::string StateJson(Engine &engine, Topology &topo)
    {
        std::map<const Port *, std::pair<std::string, std::size_t>> pmap;
        for(const auto &kv : topo.devices)
        {
            const Device *d = kv.second.get();
            for(std::size_t i = 0; i < d->portList.size(); ++i)
                pmap[d->portList[i]] = { kv.first, i };
        }

        std::ostringstream o;
        o << "{\"name\":" << JsonQuote(YANAS_NAME)
          << ",\"version\":" << JsonQuote(YANAS_VERSION)
          << ",\"time\":" << engine.Now()
          << ",\"queue\":" << engine.queue.Size()
          << ",\"devices\":[";

        bool first = true;
        for(const auto &kv : topo.devices)
        {
            const Device *d = kv.second.get();
            if(!first) o << ",";
            first = false;

            o << "{\"name\":" << JsonQuote(kv.first)
              << ",\"kind\":" << JsonQuote(KindOf(d))
              << ",\"ports\":[";

            for(std::size_t i = 0; i < d->portList.size(); ++i)
            {
                const Port *p = d->portList[i];
                if(i) o << ",";
                o << "{\"index\":" << i
                  << ",\"mac\":" << JsonQuote(p->mac.ToString())
                  << ",\"ip\":"
                  << (p->hasIp
                        ? JsonQuote(p->ip.ToString() + "/" + std::to_string(p->subnet.prefix))
                        : std::string("null"))
                  << ",\"vlan\":" << p->vlan
                  << ",\"tagged\":" << (p->tagged ? "true" : "false")
                  << ",\"state\":" << JsonQuote(StpStateName(p))
                  << ",\"rx\":" << p->rx
                  << ",\"tx\":" << p->tx
                  << ",\"drop\":" << p->drop
                  << "}";
            }
            o << "]}";
        }

        o << "],\"links\":[";
        first = true;
        for(const auto &lp : topo.links)
        {
            const Link *l = lp.get();
            auto a = pmap.find(l->A);
            auto b = pmap.find(l->B);
            if(a == pmap.end() || b == pmap.end()) continue;
            if(!first) o << ",";
            first = false;
            o << "{\"a\":" << JsonQuote(a->second.first)
              << ",\"aPort\":" << a->second.second
              << ",\"b\":" << JsonQuote(b->second.first)
              << ",\"bPort\":" << b->second.second
              << ",\"up\":" << (l->enabled ? "true" : "false")
              << ",\"delay\":" << l->delay
              << "}";
        }
        o << "]}";
        return o.str();
    }

    std::string CaptureLine(CommandContext &ctx, const std::string &line)
    {
        std::ostringstream out;
        std::streambuf *old = std::cout.rdbuf(out.rdbuf());
        try
        {
            RunScriptLine(ctx, line);
        }
        catch(const std::exception &e)
        {
            out << "error: " << e.what() << "\n";
        }
        std::cout.rdbuf(old);
        return out.str();
    }

    std::string ReadFile(const std::string &path)
    {
        std::ifstream f(path, std::ios::binary);
        if(!f) return std::string();
        std::ostringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }

    std::string Mime(const std::string &path)
    {
        auto ends = [&](const char *suf) {
            std::string s(suf);
            return path.size() >= s.size() &&
                   path.compare(path.size() - s.size(), s.size(), s) == 0;
        };
        if(ends(".html")) return "text/html; charset=utf-8";
        if(ends(".css"))  return "text/css; charset=utf-8";
        if(ends(".js"))   return "application/javascript; charset=utf-8";
        if(ends(".svg"))  return "image/svg+xml";
        return "application/octet-stream";
    }

    void SendAll(socket_t fd, const std::string &s)
    {
        std::size_t off = 0;
        while(off < s.size())
        {
            iolen_t w = send(fd, s.data() + off, int(s.size() - off), 0);
            if(w <= 0) break;
            off += std::size_t(w);
        }
    }

    void Respond(socket_t fd, int code, const char *status,
                 const std::string &ctype, const std::string &body)
    {
        std::ostringstream h;
        h << "HTTP/1.1 " << code << " " << status << "\r\n"
          << "Content-Type: " << ctype << "\r\n"
          << "Content-Length: " << body.size() << "\r\n"
          << "Cache-Control: no-store\r\n"
          << "Connection: close\r\n\r\n";
        SendAll(fd, h.str() + body);
    }

    std::size_t ContentLength(const std::string &head)
    {
        std::string lower;
        lower.reserve(head.size());
        for(char c : head) lower += char(std::tolower(static_cast<unsigned char>(c)));

        std::size_t pos = lower.find("content-length:");
        if(pos == std::string::npos) return 0;
        pos += std::strlen("content-length:");
        while(pos < head.size() && head[pos] == ' ') ++pos;

        std::size_t v = 0;
        while(pos < head.size() && std::isdigit(static_cast<unsigned char>(head[pos])))
        {
            v = v * 10 + std::size_t(head[pos] - '0');
            ++pos;
        }
        return v;
    }

    bool ServeStatic(socket_t fd, const std::string &path)
    {
        std::string rel = (path == "/" || path.empty()) ? "index.html" : path.substr(1);
        if(rel.find("..") != std::string::npos) return false;

        const char *prefixes[] = { "web/", "../web/" };
        for(const char *pre : prefixes)
        {
            std::string body = ReadFile(std::string(pre) + rel);
            if(!body.empty())
            {
                Respond(fd, 200, "OK", Mime(rel), body);
                return true;
            }
        }
        return false;
    }

    void HandleClient(socket_t fd, CommandContext &ctx)
    {
        std::string req;
        char buf[4096];

        while(req.find("\r\n\r\n") == std::string::npos)
        {
            iolen_t n = recv(fd, buf, sizeof(buf), 0);
            if(n <= 0) { CloseSock(fd); return; }
            req.append(buf, std::size_t(n));
        }

        std::size_t hdrEnd = req.find("\r\n\r\n");
        std::string head = req.substr(0, hdrEnd);
        std::string body = req.substr(hdrEnd + 4);

        std::size_t need = ContentLength(head);
        while(body.size() < need)
        {
            iolen_t n = recv(fd, buf, sizeof(buf), 0);
            if(n <= 0) break;
            body.append(buf, std::size_t(n));
        }

        std::string method, path;
        {
            std::istringstream ls(head);
            ls >> method >> path;
        }

        if(path == "/api/state" && method == "GET")
        {
            Respond(fd, 200, "OK", "application/json", StateJson(*ctx.engine, *ctx.topo));
        }
        else if(path == "/api/cmd" && method == "POST")
        {
            std::string line = body;
            std::string output = CaptureLine(ctx, line);
            std::string j = "{\"output\":" + JsonQuote(output) +
                            ",\"state\":" + StateJson(*ctx.engine, *ctx.topo) + "}";
            Respond(fd, 200, "OK", "application/json", j);
        }
        else if(path == "/api/run" && method == "POST")
        {
            std::string dur = body.empty() ? std::string("1000") : body;
            std::string output = CaptureLine(ctx, "run " + dur);
            std::string j = "{\"output\":" + JsonQuote(output) +
                            ",\"state\":" + StateJson(*ctx.engine, *ctx.topo) + "}";
            Respond(fd, 200, "OK", "application/json", j);
        }
        else if(path == "/api/step" && method == "POST")
        {
            std::string n = body.empty() ? std::string("1") : body;
            std::string output = CaptureLine(ctx, "step " + n);
            std::string j = "{\"output\":" + JsonQuote(output) +
                            ",\"state\":" + StateJson(*ctx.engine, *ctx.topo) + "}";
            Respond(fd, 200, "OK", "application/json", j);
        }
        else if(method == "GET" && (path == "/" || path.find("/api/") != 0))
        {
            if(!ServeStatic(fd, path))
                Respond(fd, 404, "Not Found", "text/plain", "not found");
        }
        else
        {
            Respond(fd, 404, "Not Found", "text/plain", "not found");
        }

        CloseSock(fd);
    }
}

void RunWebServer(Engine &engine, Topology &topo, int port)
{
    if(!StartSockets())
    {
        std::cerr << "error: socket initialization failed\n";
        return;
    }

    socket_t server = socket(AF_INET, SOCK_STREAM, 0);
    if(server == kInvalidSocket)
    {
        std::cerr << "error: cannot create socket\n";
        return;
    }

    int yes = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char *>(&yes), int(sizeof(yes)));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if(bind(server, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        std::cerr << "error: cannot bind 127.0.0.1:" << port << "\n";
        CloseSock(server);
        return;
    }
    if(listen(server, 16) < 0)
    {
        std::cerr << "error: cannot listen\n";
        CloseSock(server);
        return;
    }

    std::cout << YANAS_NAME << " " << YANAS_VERSION
              << " web UI: http://127.0.0.1:" << port << "/\n"
              << "press Ctrl-C to stop\n";

    CommandContext ctx;
    ctx.engine = &engine;
    ctx.topo = &topo;

    for(;;)
    {
        socket_t client = accept(server, nullptr, nullptr);
        if(client == kInvalidSocket) continue;
        HandleClient(client, ctx);
    }
}
