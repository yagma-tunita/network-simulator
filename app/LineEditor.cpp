#include "LineEditor.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstddef>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#else
#include <unistd.h>
#include <termios.h>
#endif

namespace
{
    std::vector<std::string> g_history;
    LineEditor::Completer g_completer;
    const std::size_t kMaxHistory = 500;

    std::string LongestCommonPrefix(const std::vector<std::string> &v)
    {
        if(v.empty()) return std::string();
        std::string p = v[0];
        for(std::size_t k = 1; k < v.size(); ++k)
        {
            std::size_t i = 0;
            while(i < p.size() && i < v[k].size() && p[i] == v[k][i]) ++i;
            p.resize(i);
        }
        return p;
    }

    void Render(const std::string &prompt, const std::string &buf, std::size_t pos)
    {
        std::cout << "\r\x1b[K" << prompt << buf;
        if(pos < buf.size())
            std::cout << "\x1b[" << (buf.size() - pos) << "D";
        std::cout << std::flush;
    }

    void DoCompletion(const std::string &prompt, std::string &buf, std::size_t &pos)
    {
        if(!g_completer) return;
        std::vector<std::string> cands = g_completer(buf);
        if(cands.size() == 1)
        {
            buf = cands[0];
            pos = buf.size();
            Render(prompt, buf, pos);
        }
        else if(cands.size() > 1)
        {
            std::string common = LongestCommonPrefix(cands);
            if(common.size() > buf.size())
            {
                buf = common;
                pos = buf.size();
            }
            Render(prompt, buf, pos);
            std::cout << "\r\n";
            for(const std::string &s : cands) std::cout << s << "  ";
            std::cout << "\r\n";
            Render(prompt, buf, pos);
        }
    }

#ifdef _WIN32

    bool EnableVt()
    {
        HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if(!GetConsoleMode(out, &mode)) return false;
        return SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
    }

    struct WinRaw
    {
        HANDLE in = INVALID_HANDLE_VALUE;
        DWORD oldMode = 0;
        bool active = false;

        WinRaw()
        {
            in = GetStdHandle(STD_INPUT_HANDLE);
            if(!GetConsoleMode(in, &oldMode)) return;
            DWORD m = oldMode;
            m &= ~(DWORD)(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE);
            m |= ENABLE_EXTENDED_FLAGS;
            if(SetConsoleMode(in, m)) active = true;
        }

        ~WinRaw()
        {
            if(active) SetConsoleMode(in, oldMode);
        }
    };

    int CtrlCode(WORD vk)
    {
        if(vk >= 'A' && vk <= 'Z') return int(vk - 'A' + 1);
        return 0;
    }

    void AppendWChar(std::string &buf, std::size_t &pos, wchar_t wc)
    {
        char tmp[8];
        int n = WideCharToMultiByte(CP_UTF8, 0, &wc, 1, tmp, sizeof(tmp), nullptr, nullptr);
        if(n <= 0) return;
        buf.insert(buf.begin() + std::ptrdiff_t(pos), tmp, tmp + n);
        pos += std::size_t(n);
    }

    bool ReadLineImpl(const std::string &prompt, std::string &out)
    {
        HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        if(!GetConsoleMode(in, &mode) || !EnableVt())
        {
            std::cout << prompt << std::flush;
            return bool(std::getline(std::cin, out));
        }

        WinRaw raw;
        if(!raw.active)
        {
            std::cout << prompt << std::flush;
            return bool(std::getline(std::cin, out));
        }

        std::string buf;
        std::size_t pos = 0;
        int histIdx = int(g_history.size());
        Render(prompt, buf, pos);

        for(;;)
        {
            INPUT_RECORD rec;
            DWORD n = 0;
            if(!ReadConsoleInputW(in, &rec, 1, &n))
            {
                std::cout << "\r\n";
                return false;
            }
            if(rec.EventType != KEY_EVENT) continue;
            const KEY_EVENT_RECORD &k = rec.Event.KeyEvent;
            if(!k.bKeyDown) continue;

            WORD vk = k.wVirtualKeyCode;
            DWORD ctrl = k.dwControlKeyState;
            bool hasCtrl = (ctrl & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;
            bool hasAlt = (ctrl & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED)) != 0;
            int rep = k.wRepeatCount > 0 ? int(k.wRepeatCount) : 1;

            for(int r = 0; r < rep; ++r)
            {
                wchar_t wc = k.uChar.UnicodeChar;

                if(vk == VK_RETURN || wc == L'\r' || wc == L'\n')
                {
                    std::cout << "\r\n";
                    out = buf;
                    return true;
                }

                int cc = hasCtrl ? CtrlCode(vk) : 0;
                if(wc == 3 || cc == 3)
                {
                    std::cout << "^C\r\n";
                    out.clear();
                    return true;
                }
                if(wc == 4 || cc == 4)
                {
                    if(buf.empty()) { std::cout << "\r\n"; return false; }
                    if(pos < buf.size()) { buf.erase(pos, 1); Render(prompt, buf, pos); }
                    continue;
                }
                if(wc == 1 || cc == 1) { pos = 0; Render(prompt, buf, pos); continue; }
                if(wc == 5 || cc == 5) { pos = buf.size(); Render(prompt, buf, pos); continue; }
                if(wc == 11 || cc == 11) { buf.erase(pos); Render(prompt, buf, pos); continue; }
                if(wc == 21 || cc == 21) { buf.erase(0, pos); pos = 0; Render(prompt, buf, pos); continue; }

                if(wc == 9 || vk == VK_TAB) { DoCompletion(prompt, buf, pos); continue; }
                if(vk == VK_BACK || wc == 8)
                {
                    if(pos > 0) { buf.erase(pos - 1, 1); --pos; Render(prompt, buf, pos); }
                    continue;
                }
                if(vk == VK_LEFT) { if(pos > 0) --pos; Render(prompt, buf, pos); continue; }
                if(vk == VK_RIGHT) { if(pos < buf.size()) ++pos; Render(prompt, buf, pos); continue; }
                if(vk == VK_HOME) { pos = 0; Render(prompt, buf, pos); continue; }
                if(vk == VK_END) { pos = buf.size(); Render(prompt, buf, pos); continue; }
                if(vk == VK_DELETE)
                {
                    if(pos < buf.size()) { buf.erase(pos, 1); Render(prompt, buf, pos); }
                    continue;
                }
                if(vk == VK_UP)
                {
                    if(histIdx > 0)
                    {
                        --histIdx;
                        buf = g_history[std::size_t(histIdx)];
                        pos = buf.size();
                    }
                    Render(prompt, buf, pos);
                    continue;
                }
                if(vk == VK_DOWN)
                {
                    if(histIdx + 1 < int(g_history.size()))
                    {
                        ++histIdx;
                        buf = g_history[std::size_t(histIdx)];
                    }
                    else
                    {
                        histIdx = int(g_history.size());
                        buf.clear();
                    }
                    pos = buf.size();
                    Render(prompt, buf, pos);
                    continue;
                }

                if(!hasCtrl && !hasAlt && wc >= 32)
                {
                    AppendWChar(buf, pos, wc);
                    Render(prompt, buf, pos);
                }
            }
        }
    }

#else

    struct RawMode
    {
        termios old;
        bool active = false;

        RawMode()
        {
            if(tcgetattr(STDIN_FILENO, &old) != 0) return;
            termios raw = old;
            raw.c_lflag &= ~(tcflag_t)(ICANON | ECHO | ISIG);
            raw.c_iflag &= ~(tcflag_t)(IXON | ICRNL);
            raw.c_cc[VMIN] = 1;
            raw.c_cc[VTIME] = 0;
            if(tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) active = true;
        }

        ~RawMode()
        {
            if(active) tcsetattr(STDIN_FILENO, TCSANOW, &old);
        }
    };

    bool ReadByte(unsigned char &c)
    {
        ssize_t n = read(STDIN_FILENO, &c, 1);
        return n == 1;
    }

    bool ReadLineImpl(const std::string &prompt, std::string &out)
    {
        if(!isatty(STDIN_FILENO))
        {
            std::cout << prompt << std::flush;
            return bool(std::getline(std::cin, out));
        }

        RawMode raw;
        if(!raw.active)
        {
            std::cout << prompt << std::flush;
            return bool(std::getline(std::cin, out));
        }

        std::string buf;
        std::size_t pos = 0;
        int histIdx = int(g_history.size());
        Render(prompt, buf, pos);

        for(;;)
        {
            unsigned char c = 0;
            if(!ReadByte(c)) { std::cout << "\n"; return false; }

            if(c == '\r' || c == '\n')
            {
                std::cout << "\r\n";
                out = buf;
                return true;
            }
            if(c == 3)
            {
                std::cout << "^C\r\n";
                out.clear();
                return true;
            }
            if(c == 4)
            {
                if(buf.empty()) { std::cout << "\r\n"; return false; }
                if(pos < buf.size()) { buf.erase(pos, 1); Render(prompt, buf, pos); }
                continue;
            }
            if(c == 127 || c == 8)
            {
                if(pos > 0) { buf.erase(pos - 1, 1); --pos; Render(prompt, buf, pos); }
                continue;
            }
            if(c == 1) { pos = 0; Render(prompt, buf, pos); continue; }
            if(c == 5) { pos = buf.size(); Render(prompt, buf, pos); continue; }
            if(c == 11) { buf.erase(pos); Render(prompt, buf, pos); continue; }
            if(c == 21) { buf.erase(0, pos); pos = 0; Render(prompt, buf, pos); continue; }
            if(c == 9) { DoCompletion(prompt, buf, pos); continue; }
            if(c == 27)
            {
                unsigned char a = 0, b = 0;
                if(!ReadByte(a)) continue;
                if(a != '[')
                {
                    if(a == 'b') { pos = 0; }
                    else if(a == 'f') { pos = buf.size(); }
                    Render(prompt, buf, pos);
                    continue;
                }
                if(!ReadByte(b)) continue;

                if(b == 'A')
                {
                    if(histIdx > 0)
                    {
                        --histIdx;
                        buf = g_history[std::size_t(histIdx)];
                        pos = buf.size();
                    }
                }
                else if(b == 'B')
                {
                    if(histIdx + 1 < int(g_history.size()))
                    {
                        ++histIdx;
                        buf = g_history[std::size_t(histIdx)];
                    }
                    else
                    {
                        histIdx = int(g_history.size());
                        buf.clear();
                    }
                    pos = buf.size();
                }
                else if(b == 'C') { if(pos < buf.size()) ++pos; }
                else if(b == 'D') { if(pos > 0) --pos; }
                else if(b == 'H') { pos = 0; }
                else if(b == 'F') { pos = buf.size(); }
                else if(b == '3')
                {
                    unsigned char tilde = 0;
                    if(ReadByte(tilde) && tilde == '~' && pos < buf.size())
                        buf.erase(pos, 1);
                }
                Render(prompt, buf, pos);
                continue;
            }
            if(c >= 32 && c < 127)
            {
                buf.insert(buf.begin() + std::ptrdiff_t(pos), char(c));
                ++pos;
                Render(prompt, buf, pos);
            }
        }
    }

#endif
}

namespace LineEditor
{
    void SetCompleter(Completer fn)
    {
        g_completer = std::move(fn);
    }

    bool ReadLine(const std::string &prompt, std::string &out)
    {
        return ReadLineImpl(prompt, out);
    }

    void AddHistory(const std::string &line)
    {
        if(line.empty()) return;
        if(!g_history.empty() && g_history.back() == line) return;
        g_history.push_back(line);
        if(g_history.size() > kMaxHistory)
            g_history.erase(g_history.begin(), g_history.begin() + std::ptrdiff_t(g_history.size() - kMaxHistory));
    }

    void LoadHistory(const std::string &path)
    {
        std::ifstream in(path);
        if(!in) return;
        std::string line;
        while(std::getline(in, line))
        {
            if(!line.empty()) g_history.push_back(line);
        }
        if(g_history.size() > kMaxHistory)
            g_history.erase(g_history.begin(), g_history.begin() + std::ptrdiff_t(g_history.size() - kMaxHistory));
    }

    void SaveHistory(const std::string &path)
    {
        std::ofstream out(path);
        if(!out) return;
        std::size_t start = 0;
        if(g_history.size() > kMaxHistory) start = g_history.size() - kMaxHistory;
        for(std::size_t i = start; i < g_history.size(); ++i)
            out << g_history[i] << "\n";
    }
}
