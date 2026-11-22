# legacy/

Archived, **not built**. These front ends were moved here when the product
narrowed to a terminal-first tool for technical users.

- `legacy/win/main_win.cpp` — the earlier native Win32 desktop GUI.
- `legacy/web/` — the earlier classic-style local web UI (HTML/CSS/JS assets).
- `legacy/webserver/` — the loopback JSON API server (POSIX/Winsock).
- `legacy/packaging/yanas-net.iss` — a GUI-oriented Inno Setup script.
- `legacy/tests/web_test.sh` — the web endpoint smoke test.

Nothing here is compiled, tested, or shipped. The current product is the terminal
CLI (`netsim` / `netsim.exe`) plus bundled Lua, described in the top-level README.
