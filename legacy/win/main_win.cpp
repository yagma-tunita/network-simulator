#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>

#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <sstream>
#include <iostream>
#include <vector>
#include <map>
#include <utility>
#include <stdexcept>
#include <cstddef>

#include "../app/Version.hpp"
#include "../engine/Engine.hpp"
#include "../topo/Topology.hpp"
#include "../topo/CommandRunner.hpp"
#include "../topo/JsonConfig.hpp"
#include "../script/LuaScript.hpp"
#include "../device/Device.hpp"
#include "../device/Port.hpp"
#include "../device/Switch.hpp"
#include "../device/Router.hpp"
#include "../device/EndDevice.hpp"
#include "../link/Link.hpp"
#include "../core/Ipv4.hpp"
#include "../core/Ipv4Subnet.hpp"
#include "../core/Mac.hpp"

namespace
{
    Engine g_engine;
    Topology g_topo;
    CommandContext g_ctx;
    HINSTANCE g_inst = nullptr;

    HWND g_main = nullptr;
    HWND g_canvas = nullptr;
    HWND g_inspector = nullptr;
    HWND g_console = nullptr;
    HWND g_input = nullptr;
    HWND g_status = nullptr;

    HWND g_btnHost = nullptr, g_btnSwitch = nullptr, g_btnRouter = nullptr;
    HWND g_btnPort = nullptr, g_btnConnect = nullptr, g_btnRun = nullptr;
    HWND g_btnStep = nullptr, g_btnPing = nullptr, g_btnStp = nullptr;
    HWND g_btnSave = nullptr, g_btnRefresh = nullptr;
    HWND g_btnNew = nullptr, g_btnOpen = nullptr;
    HWND g_btnSend = nullptr;

    std::string g_currentFile;

    HFONT g_fontUI = nullptr, g_fontMono = nullptr, g_fontSmall = nullptr;

    std::string g_selected;
    int g_headerH = 44;
    std::vector<std::pair<std::string, RECT>> g_nodeRects;
    std::map<std::string, POINT> g_pos;
    bool g_dragging = false;
    std::string g_dragName;
    int g_dragOffX = 0, g_dragOffY = 0;

    const int ID_HOST = 101, ID_SWITCH = 102, ID_ROUTER = 103, ID_PORT = 104;
    const int ID_CONNECT = 105, ID_RUN = 106, ID_STEP = 107, ID_PING = 108;
    const int ID_STP = 109, ID_SAVE = 110, ID_REFRESH = 112;
    const int ID_SEND = 113, ID_NEW = 114, ID_OPEN = 115;
    const int IDM_EXIT = 201, IDM_ABOUT = 202;
    const int IDM_NEW = 203, IDM_OPEN = 204, IDM_SAVE = 205, IDM_SAVEAS = 206;
    const int IDM_RUNLUA = 207;

    const char *KindOf(const Device *d)
    {
        if(dynamic_cast<const Router *>(d)) return "router";
        if(dynamic_cast<const Switch *>(d)) return "switch";
        return "end";
    }

    const char *StateName(const Port *p)
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

    COLORREF KindColor(const Device *d)
    {
        if(dynamic_cast<const Router *>(d)) return RGB(178, 106, 0);
        if(dynamic_cast<const Switch *>(d)) return RGB(46, 125, 50);
        return RGB(48, 90, 158);
    }

    std::string NextName(const std::string &base)
    {
        int i = 1;
        for(;;)
        {
            std::string n = base + std::to_string(i);
            if(g_topo.devices.find(n) == g_topo.devices.end()) return n;
            ++i;
        }
    }

    void AppendLog(const std::string &text)
    {
        if(!g_console || text.empty()) return;
        int len = GetWindowTextLengthA(g_console);
        SendMessageA(g_console, EM_SETSEL, (WPARAM)len, (LPARAM)len);
        std::string s = text;
        if(s.back() != '\n') s += "\r\n";
        else s += "\r\n";
        SendMessageA(g_console, EM_REPLACESEL, FALSE, (LPARAM)s.c_str());
    }

    std::string RunCaptured(const std::string &line)
    {
        std::ostringstream out;
        std::streambuf *old = std::cout.rdbuf(out.rdbuf());
        try
        {
            RunScriptLine(g_ctx, line);
        }
        catch(const std::exception &e)
        {
            out << "error: " << e.what() << "\n";
        }
        std::cout.rdbuf(old);
        return out.str();
    }

    void UpdateInspector();
    void UpdateStatus();
    void RefreshAll();
    void RecalcLayout();
    void Prefill(const std::string &s);

    void RunLine(const std::string &line)
    {
        if(line.empty()) return;
        AppendLog("> " + line);
        std::string out = RunCaptured(line);
        if(!out.empty()) AppendLog(out);
        RefreshAll();
    }

    void UpdateInspector()
    {
        std::string text;
        auto it = g_topo.devices.find(g_selected);
        if(it != g_topo.devices.end())
        {
            const Device *d = it->second.get();
            text += g_selected + "  [" + std::string(KindOf(d)) + "]\r\n";
            for(std::size_t i = 0; i < d->portList.size(); ++i)
            {
                const Port *p = d->portList[i];
                text += "p" + std::to_string(i) + "  ";
                text += p->hasIp ? (p->ip.ToString() + "/" + std::to_string(p->subnet.prefix)) : "(L2)";
                text += "  vlan=" + std::to_string(p->vlan) + (p->tagged ? " T" : "");
                text += "  " + std::string(StateName(p));
                text += "  rx=" + std::to_string(p->rx) + " tx=" + std::to_string(p->tx);
                text += " drop=" + std::to_string(p->drop) + "\r\n";
            }
            if(d->portList.empty()) text += "(no ports)\r\n";
        }
        else
        {
            text = "Select a device on the canvas.";
        }
        SetWindowTextA(g_inspector, text.c_str());
    }

    void UpdateStatus()
    {
        char buf[256];
        std::snprintf(buf, sizeof(buf), "t=%llu   %u devices   %u links   %s",
                      (unsigned long long)g_engine.Now(),
                      (unsigned)g_topo.devices.size(),
                      (unsigned)g_topo.links.size(),
                      g_selected.empty() ? "-" : g_selected.c_str());
        SetWindowTextA(g_status, buf);
    }

    void RefreshAll()
    {
        UpdateStatus();
        UpdateInspector();
        if(g_canvas) InvalidateRect(g_canvas, nullptr, TRUE);
        if(g_main) InvalidateRect(g_main, nullptr, TRUE);
    }

    void Prefill(const std::string &s)
    {
        SetWindowTextA(g_input, s.c_str());
        SetFocus(g_input);
        int n = (int)s.size();
        SendMessageA(g_input, EM_SETSEL, (WPARAM)n, (LPARAM)n);
    }

    void DrawStar(HDC hdc, int cx, int cy, int R, int r)
    {
        const double PI = 3.14159265358979323846;
        POINT pts[12];
        for(int i = 0; i < 12; ++i)
        {
            double a = -PI / 2.0 + i * PI / 6.0;
            int rad = (i % 2 == 0) ? R : r;
            pts[i].x = cx + (int)(std::cos(a) * rad);
            pts[i].y = cy + (int)(std::sin(a) * rad);
        }
        HBRUSH br = CreateSolidBrush(RGB(200, 30, 30));
        HPEN pen = CreatePen(PS_SOLID, 2, RGB(110, 10, 10));
        HGDIOBJ ob = SelectObject(hdc, br);
        HGDIOBJ op = SelectObject(hdc, pen);
        Polygon(hdc, pts, 12);
        SelectObject(hdc, ob);
        SelectObject(hdc, op);
        DeleteObject(br);
        DeleteObject(pen);
    }

    struct NodePos
    {
        std::string name;
        int x, y;
    };

    void EnsureLayout()
    {
        int n = (int)g_topo.devices.size();
        int cols = (int)std::ceil(std::sqrt((double)n));
        if(cols < 1) cols = 1;
        int i = 0;
        for(const auto &kv : g_topo.devices)
        {
            if(g_pos.find(kv.first) == g_pos.end())
            {
                POINT pt;
                pt.x = 110 + (i % cols) * 190;
                pt.y = 90 + (i / cols) * 150;
                g_pos[kv.first] = pt;
            }
            ++i;
        }
        for(auto it = g_pos.begin(); it != g_pos.end(); )
        {
            if(g_topo.devices.find(it->first) == g_topo.devices.end()) it = g_pos.erase(it);
            else ++it;
        }
    }

    void LayoutNodes(std::vector<NodePos> &out)
    {
        EnsureLayout();
        out.clear();
        for(const auto &kv : g_topo.devices)
        {
            auto it = g_pos.find(kv.first);
            if(it == g_pos.end()) continue;
            NodePos np;
            np.name = kv.first;
            np.x = it->second.x;
            np.y = it->second.y;
            out.push_back(np);
        }
    }

    std::string HitTest(int x, int y)
    {
        EnsureLayout();
        for(const auto &kv : g_topo.devices)
        {
            auto it = g_pos.find(kv.first);
            if(it == g_pos.end()) continue;
            int cx = it->second.x, cy = it->second.y;
            if(x >= cx - 40 && x <= cx + 40 && y >= cy - 26 && y <= cy + 26)
                return kv.first;
        }
        return std::string();
    }

    bool BlockedPort(const Port *p)
    {
        const Switch *sw = dynamic_cast<const Switch *>(p->owner);
        return sw && sw->stpEnabled && p->stpState == StpPortState::Blocking;
    }

    void UpdateTitle()
    {
        std::string name = g_currentFile.empty() ? std::string("Untitled") : g_currentFile;
        std::string t = std::string(YANAS_NAME) + " - " + name;
        SetWindowTextA(g_main, t.c_str());
    }

    void ClearSession()
    {
        g_engine.Reset();
        g_topo.Clear();
        g_ctx.pcap.reset();
        g_ctx.engine = &g_engine;
        g_ctx.topo = &g_topo;
        g_selected.clear();
        g_pos.clear();
        g_dragging = false;
        g_dragName.clear();
    }

    void ApplyLayout(const LayoutMap &layout)
    {
        g_pos.clear();
        for(const auto &kv : layout)
        {
            POINT p;
            p.x = kv.second.first;
            p.y = kv.second.second;
            g_pos[kv.first] = p;
        }
        EnsureLayout();
    }

    std::string OpenFileDialog()
    {
        char buf[MAX_PATH];
        buf[0] = 0;
        OPENFILENAMEA ofn;
        std::memset(&ofn, 0, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_main;
        ofn.lpstrFilter = "yanas net scene (*.yn)\0*.yn\0All files (*.*)\0*.*\0";
        ofn.lpstrFile = buf;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrDefExt = "yn";
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
        if(!GetOpenFileNameA(&ofn)) return std::string();
        return std::string(buf);
    }

    std::string SaveFileDialog()
    {
        char buf[MAX_PATH];
        buf[0] = 0;
        if(!g_currentFile.empty())
        {
            std::strncpy(buf, g_currentFile.c_str(), MAX_PATH - 1);
            buf[MAX_PATH - 1] = 0;
        }
        OPENFILENAMEA ofn;
        std::memset(&ofn, 0, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_main;
        ofn.lpstrFilter = "yanas net scene (*.yn)\0*.yn\0All files (*.*)\0*.*\0";
        ofn.lpstrFile = buf;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrDefExt = "yn";
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
        if(!GetSaveFileNameA(&ofn)) return std::string();
        return std::string(buf);
    }

    std::string OpenLuaDialog()
    {
        char buf[MAX_PATH];
        buf[0] = 0;
        OPENFILENAMEA ofn;
        std::memset(&ofn, 0, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_main;
        ofn.lpstrFilter = "Lua script (*.lua)\0*.lua\0All files (*.*)\0*.*\0";
        ofn.lpstrFile = buf;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrDefExt = "lua";
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
        if(!GetOpenFileNameA(&ofn)) return std::string();
        return std::string(buf);
    }

    void DoSave();

    void DoSaveAs()
    {
        std::string path = SaveFileDialog();
        if(path.empty()) return;
        g_currentFile = path;
        DoSave();
    }

    void DoSave()
    {
        EnsureLayout();
        if(g_currentFile.empty()) { DoSaveAs(); return; }

        LayoutMap layout;
        for(const auto &kv : g_pos)
            layout[kv.first] = std::make_pair(kv.second.x, kv.second.y);

        std::string err;
        if(!SaveTopologyJson(g_topo, g_currentFile, layout, err))
        {
            MessageBoxA(g_main, err.c_str(), "Save failed", MB_OK | MB_ICONERROR);
            return;
        }
        AppendLog("Saved " + g_currentFile);
        UpdateTitle();
    }

    void DoNew()
    {
        ClearSession();
        g_currentFile.clear();
        UpdateTitle();
        AppendLog("New scene.");
        RefreshAll();
    }

    void DoOpen()
    {
        std::string path = OpenFileDialog();
        if(path.empty()) return;

        std::vector<std::string> cmds;
        LayoutMap layout;
        std::string err;
        if(!ParseConfigJson(path, cmds, layout, err))
        {
            MessageBoxA(g_main, err.c_str(), "Open failed", MB_OK | MB_ICONERROR);
            return;
        }

        ClearSession();
        for(const std::string &line : cmds)
            RunCaptured(line);

        ApplyLayout(layout);
        g_currentFile = path;
        UpdateTitle();
        AppendLog("Opened " + path);
        RefreshAll();
    }

    void DrawTopology(HDC hdc)
    {
        RECT rc;
        GetClientRect(g_canvas, &rc);

        HBRUSH bg = CreateSolidBrush(RGB(238, 243, 247));
        FillRect(hdc, &rc, bg);
        DeleteObject(bg);

        HPEN grid = CreatePen(PS_SOLID, 1, RGB(216, 226, 234));
        HGDIOBJ og = SelectObject(hdc, grid);
        for(int x = 0; x < rc.right; x += 40) { MoveToEx(hdc, x, 0, nullptr); LineTo(hdc, x, rc.bottom); }
        for(int y = 0; y < rc.bottom; y += 40) { MoveToEx(hdc, 0, y, nullptr); LineTo(hdc, rc.right, y); }
        SelectObject(hdc, og);
        DeleteObject(grid);

        std::vector<NodePos> nodes;
        LayoutNodes(nodes);
        std::map<std::string, NodePos> pos;
        for(const NodePos &np : nodes) pos[np.name] = np;

        std::map<const Port *, std::string> pmap;
        for(const auto &kv : g_topo.devices)
        {
            const Device *d = kv.second.get();
            for(Port *p : d->portList) pmap[p] = kv.first;
        }

        for(const auto &lp : g_topo.links)
        {
            const Link *l = lp.get();
            auto ia = pmap.find(l->A);
            auto ib = pmap.find(l->B);
            if(ia == pmap.end() || ib == pmap.end()) continue;
            auto pa = pos.find(ia->second);
            auto pb = pos.find(ib->second);
            if(pa == pos.end() || pb == pos.end()) continue;

            bool down = !l->enabled;
            bool blocked = BlockedPort(l->A) || BlockedPort(l->B);
            COLORREF col = down ? RGB(198, 40, 40)
                                : (blocked ? RGB(224, 160, 0) : RGB(89, 99, 110));
            HPEN pen = CreatePen((down || blocked) ? PS_DASH : PS_SOLID, (down || blocked) ? 1 : 3, col);
            HGDIOBJ op = SelectObject(hdc, pen);
            MoveToEx(hdc, pa->second.x, pa->second.y, nullptr);
            LineTo(hdc, pb->second.x, pb->second.y);
            SelectObject(hdc, op);
            DeleteObject(pen);

            int mx = (pa->second.x + pb->second.x) / 2;
            int my = (pa->second.y + pb->second.y) / 2;
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(51, 65, 77));
            SelectObject(hdc, g_fontSmall);
            std::string lbl = (down ? "down " : "") + std::to_string(l->delay);
            TextOutA(hdc, mx + 4, my - 14, lbl.c_str(), (int)lbl.size());
        }

        g_nodeRects.clear();
        SetBkMode(hdc, TRANSPARENT);

        for(const auto &kv : g_topo.devices)
        {
            auto it = pos.find(kv.first);
            if(it == pos.end()) continue;
            int x = it->second.x;
            int y = it->second.y;

            RECT r;
            r.left = x - 40; r.top = y - 26; r.right = x + 40; r.bottom = y + 26;

            HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
            FillRect(hdc, &r, white);
            DeleteObject(white);

            RECT hdr;
            hdr.left = r.left; hdr.top = r.top; hdr.right = r.right; hdr.bottom = r.top + 15;
            HBRUSH hb = CreateSolidBrush(KindColor(kv.second.get()));
            FillRect(hdc, &hdr, hb);
            DeleteObject(hb);

            bool sel = (kv.first == g_selected);
            HPEN pen = CreatePen(PS_SOLID, sel ? 3 : 1, sel ? RGB(200, 30, 30) : RGB(40, 50, 60));
            HGDIOBJ op = SelectObject(hdc, pen);
            HGDIOBJ ob = SelectObject(hdc, GetStockObject(NULL_BRUSH));
            Rectangle(hdc, r.left, r.top, r.right, r.bottom);
            SelectObject(hdc, ob);
            SelectObject(hdc, op);
            DeleteObject(pen);

            SetTextColor(hdc, RGB(255, 255, 255));
            SelectObject(hdc, g_fontSmall);
            std::string kind = KindOf(kv.second.get());
            TextOutA(hdc, r.left + 4, r.top + 1, kind.c_str(), (int)kind.size());

            SetTextColor(hdc, RGB(16, 32, 46));
            SelectObject(hdc, g_fontUI);
            TextOutA(hdc, r.left + 5, r.top + 17, kv.first.c_str(), (int)kv.first.size());

            const Device *d = kv.second.get();
            if(!d->portList.empty() && d->portList[0]->hasIp)
            {
                const Port *p0 = d->portList[0];
                std::string ip = p0->ip.ToString() + "/" + std::to_string(p0->subnet.prefix);
                SelectObject(hdc, g_fontSmall);
                SetTextColor(hdc, RGB(69, 90, 100));
                TextOutA(hdc, r.left + 5, r.top + 31, ip.c_str(), (int)ip.size());
            }

            g_nodeRects.push_back({ kv.first, r });
        }
    }

    void PlaceButtons(int width)
    {
        HWND btns[] = { g_btnNew, g_btnOpen, g_btnSave,
                        g_btnHost, g_btnSwitch, g_btnRouter, g_btnPort, g_btnConnect,
                        g_btnRun, g_btnStep, g_btnPing, g_btnStp, g_btnRefresh };
        int n = (int)(sizeof(btns) / sizeof(btns[0]));
        int x = 200, y = 8;
        int bw = 84, bh = 26;
        for(int i = 0; i < n; ++i)
        {
            if(x + bw > width - 8)
            {
                x = 8;
                y += bh + 4;
            }
            MoveWindow(btns[i], x, y, bw, bh, TRUE);
            x += bw + 4;
        }
        g_headerH = y + bh + 8;
        if(g_headerH < 44) g_headerH = 44;
    }

    void RecalcLayout()
    {
        RECT rc;
        GetClientRect(g_main, &rc);
        int W = rc.right, H = rc.bottom;

        PlaceButtons(W);

        int statusY = H - 24;
        int inputY = statusY - 30;
        int consoleTop = inputY - 150;
        if(consoleTop < g_headerH + 60) consoleTop = g_headerH + 60;

        int sideW = 250;
        MoveWindow(g_inspector, 8, g_headerH, sideW, consoleTop - g_headerH - 8, TRUE);
        MoveWindow(g_canvas, 8 + sideW + 8, g_headerH,
                   W - (8 + sideW + 8) - 8, consoleTop - g_headerH - 8, TRUE);
        MoveWindow(g_console, 8, consoleTop, W - 16, inputY - consoleTop - 4, TRUE);
        MoveWindow(g_input, 8, inputY, W - 16 - 92, 24, TRUE);
        MoveWindow(g_btnSend, W - 8 - 84, inputY, 84, 24, TRUE);
        MoveWindow(g_status, 8, statusY, W - 16, 20, TRUE);
    }

    LRESULT CALLBACK CanvasProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
    {
        switch(msg)
        {
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            DrawTopology(hdc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_LBUTTONDOWN:
        {
            int x = (short)LOWORD(lp);
            int y = (short)HIWORD(lp);
            std::string name = HitTest(x, y);
            if(!name.empty())
            {
                g_selected = name;
                auto it = g_pos.find(name);
                if(it != g_pos.end())
                {
                    g_dragging = true;
                    g_dragName = name;
                    g_dragOffX = x - it->second.x;
                    g_dragOffY = y - it->second.y;
                    SetCapture(hwnd);
                    SetFocus(hwnd);
                }
                UpdateInspector();
                UpdateStatus();
                InvalidateRect(hwnd, nullptr, TRUE);
            }
            return 0;
        }
        case WM_MOUSEMOVE:
        {
            if(g_dragging)
            {
                int x = (short)LOWORD(lp);
                int y = (short)HIWORD(lp);
                auto it = g_pos.find(g_dragName);
                if(it != g_pos.end())
                {
                    RECT rc;
                    GetClientRect(hwnd, &rc);
                    int nx = x - g_dragOffX;
                    int ny = y - g_dragOffY;
                    if(nx < 50) nx = 50;
                    if(nx > rc.right - 50) nx = rc.right - 50;
                    if(ny < 40) ny = 40;
                    if(ny > rc.bottom - 40) ny = rc.bottom - 40;
                    it->second.x = nx;
                    it->second.y = ny;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
            }
            return 0;
        }
        case WM_LBUTTONUP:
        {
            if(g_dragging)
            {
                g_dragging = false;
                g_dragName.clear();
                ReleaseCapture();
                InvalidateRect(hwnd, nullptr, TRUE);
            }
            return 0;
        }
        case WM_CAPTURECHANGED:
            g_dragging = false;
            return 0;
        }
        return DefWindowProcA(hwnd, msg, wp, lp);
    }

    LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
    {
        switch(msg)
        {
        case WM_CREATE:
        {
            g_main = hwnd;

            g_fontUI = CreateFontA(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                   DEFAULT_PITCH | FF_SWISS, "Tahoma");
            g_fontSmall = CreateFontA(-11, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                                      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                      DEFAULT_PITCH | FF_SWISS, "Tahoma");
            g_fontMono = CreateFontA(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                                     OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                     FIXED_PITCH | FF_MODERN, "Consolas");

            auto mkBtn = [&](const char *text, int id) -> HWND {
                return CreateWindowExA(0, "BUTTON", text,
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 84, 26, hwnd, (HMENU)(INT_PTR)id, g_inst, nullptr);
            };

            g_btnNew = mkBtn("New", ID_NEW);
            g_btnOpen = mkBtn("Open", ID_OPEN);
            g_btnSave = mkBtn("Save", ID_SAVE);
            g_btnHost = mkBtn("+ Host", ID_HOST);
            g_btnSwitch = mkBtn("+ Switch", ID_SWITCH);
            g_btnRouter = mkBtn("+ Router", ID_ROUTER);
            g_btnPort = mkBtn("+ Port", ID_PORT);
            g_btnConnect = mkBtn("Connect", ID_CONNECT);
            g_btnRun = mkBtn("Run", ID_RUN);
            g_btnStep = mkBtn("Step", ID_STEP);
            g_btnPing = mkBtn("Ping", ID_PING);
            g_btnStp = mkBtn("STP", ID_STP);
            g_btnRefresh = mkBtn("Refresh", ID_REFRESH);

            HWND btns[] = { g_btnNew, g_btnOpen, g_btnSave, g_btnHost, g_btnSwitch,
                            g_btnRouter, g_btnPort, g_btnConnect, g_btnRun, g_btnStep,
                            g_btnPing, g_btnStp, g_btnRefresh };
            for(HWND b : btns) SendMessageA(b, WM_SETFONT, (WPARAM)g_fontUI, TRUE);
            SetWindowLongA(g_btnRun, GWL_STYLE, GetWindowLongA(g_btnRun, GWL_STYLE) | BS_DEFPUSHBUTTON);

            g_inspector = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                0, 0, 10, 10, hwnd, nullptr, g_inst, nullptr);
            SendMessageA(g_inspector, WM_SETFONT, (WPARAM)g_fontMono, TRUE);

            WNDCLASSA cc;
            std::memset(&cc, 0, sizeof(cc));
            cc.lpfnWndProc = CanvasProc;
            cc.hInstance = g_inst;
            cc.lpszClassName = "YanasCanvas";
            cc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
            RegisterClassA(&cc);

            g_canvas = CreateWindowExA(WS_EX_CLIENTEDGE, "YanasCanvas", "",
                WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, hwnd, nullptr, g_inst, nullptr);

            g_console = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                0, 0, 10, 10, hwnd, nullptr, g_inst, nullptr);
            SendMessageA(g_console, WM_SETFONT, (WPARAM)g_fontMono, TRUE);

            g_input = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                0, 0, 10, 24, hwnd, (HMENU)999, g_inst, nullptr);
            SendMessageA(g_input, WM_SETFONT, (WPARAM)g_fontMono, TRUE);

            g_btnSend = CreateWindowExA(0, "BUTTON", "Send",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 84, 24, hwnd, (HMENU)(INT_PTR)ID_SEND, g_inst, nullptr);
            SendMessageA(g_btnSend, WM_SETFONT, (WPARAM)g_fontUI, TRUE);

            g_status = CreateWindowExA(WS_EX_CLIENTEDGE, "STATIC", "Ready",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                0, 0, 10, 20, hwnd, nullptr, g_inst, nullptr);
            SendMessageA(g_status, WM_SETFONT, (WPARAM)g_fontSmall, TRUE);

            HMENU mb = CreateMenu();
            HMENU file = CreatePopupMenu();
            AppendMenuA(file, MF_STRING, IDM_NEW, "&New");
            AppendMenuA(file, MF_STRING, IDM_OPEN, "&Open...");
            AppendMenuA(file, MF_STRING, IDM_SAVE, "&Save");
            AppendMenuA(file, MF_STRING, IDM_SAVEAS, "Save &As...");
            AppendMenuA(file, MF_STRING, IDM_RUNLUA, "Run &Lua Script...");
            AppendMenuA(file, MF_SEPARATOR, 0, nullptr);
            AppendMenuA(file, MF_STRING, IDM_EXIT, "E&xit");
            AppendMenuA(mb, MF_POPUP, (UINT_PTR)file, "&File");
            HMENU help = CreatePopupMenu();
            AppendMenuA(help, MF_STRING, IDM_ABOUT, "&About");
            AppendMenuA(mb, MF_POPUP, (UINT_PTR)help, "&Help");
            SetMenu(hwnd, mb);
            UpdateTitle();

            AppendLog(std::string(YANAS_NAME) + " " + YANAS_VERSION + " ready.");
            AppendLog("Add devices, ports, connect, then Run. Use the command line for full control.");
            RefreshAll();
            return 0;
        }
        case WM_SIZE:
            RecalcLayout();
            return 0;
        case WM_ERASEBKGND:
        {
            HDC hdc = (HDC)wp;
            RECT rc;
            GetClientRect(hwnd, &rc);
            HBRUSH b = CreateSolidBrush(RGB(192, 192, 192));
            FillRect(hdc, &rc, b);
            DeleteObject(b);
            return 1;
        }
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            DrawStar(hdc, 24, 22, 15, 5);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(20, 20, 20));
            SelectObject(hdc, g_fontUI);
            std::string title = std::string(YANAS_NAME) + "  " + YANAS_VERSION;
            TextOutA(hdc, 46, 14, title.c_str(), (int)title.size());
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_COMMAND:
        {
            int id = LOWORD(wp);
            switch(id)
            {
            case ID_HOST:    RunLine("add-device " + NextName("PC") + " end"); break;
            case ID_SWITCH:  RunLine("add-device " + NextName("SW") + " switch"); break;
            case ID_ROUTER:  RunLine("add-device " + NextName("R") + " router"); break;
            case ID_PORT:    Prefill("add-port "); break;
            case ID_CONNECT: Prefill("connect "); break;
            case ID_RUN:     RunLine("run 200"); break;
            case ID_STEP:    RunLine("step 1"); break;
            case ID_PING:    Prefill("ping "); break;
            case ID_STP:     Prefill("set-stp "); break;
            case ID_SAVE:
            case IDM_SAVE:   DoSave(); break;
            case ID_NEW:
            case IDM_NEW:    DoNew(); break;
            case ID_OPEN:
            case IDM_OPEN:   DoOpen(); break;
            case IDM_SAVEAS: DoSaveAs(); break;
            case IDM_RUNLUA:
            {
                std::string path = OpenLuaDialog();
                if(!path.empty())
                {
                    std::ostringstream out;
                    std::streambuf *old = std::cout.rdbuf(out.rdbuf());
                    std::string err;
                    bool ok = RunLuaFile(g_engine, g_topo, path, err);
                    std::cout.rdbuf(old);
                    AppendLog("> run-lua " + path);
                    std::string captured = out.str();
                    if(!captured.empty()) AppendLog(captured);
                    if(!ok) AppendLog("lua: " + err);
                    RefreshAll();
                }
                break;
            }
            case ID_REFRESH: RefreshAll(); break;
            case ID_SEND:
            {
                char buf[2048];
                GetWindowTextA(g_input, buf, sizeof(buf));
                SetWindowTextA(g_input, "");
                RunLine(std::string(buf));
                break;
            }
            case IDM_EXIT:
                DestroyWindow(hwnd);
                break;
            case IDM_ABOUT:
                MessageBoxA(hwnd,
                    "yanas net " YANAS_VERSION "\r\nDeterministic network simulator",
                    "About yanas net", MB_OK | MB_ICONINFORMATION);
                break;
            }
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProcA(hwnd, msg, wp, lp);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow)
{
    g_inst = hInstance;
    g_topo.SetEngine(&g_engine);
    g_ctx.engine = &g_engine;
    g_ctx.topo = &g_topo;

    WNDCLASSA wc;
    std::memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = MainProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "YanasMain";
    wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconA(hInstance, MAKEINTRESOURCEA(1));
    wc.hbrBackground = CreateSolidBrush(RGB(192, 192, 192));
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(0, "YanasMain", "yanas net",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1200, 820,
        nullptr, nullptr, hInstance, nullptr);
    if(!hwnd) return 0;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while(GetMessageA(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}
