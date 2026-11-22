# Changelog

All notable changes to yanas net are recorded here.

## 0.1.0 — 2026-11-22

Initial product build.

- Deterministic event engine with a logical clock (`Engine`, `EventQueue`,
  `Scheduler`), header-dependency-tracked Makefile build.
- Layer-2: Ethernet frames, ARP, MAC-learning switches, VLAN access ports and
  802.1Q trunks with real TPID/TCI encoding, STP (Hello/Max-Age, forward-delay
  states, link-flap reconvergence) and an RSTP-style rapid mode.
- Layer-3: IPv4 packets, longest-prefix routing, TTL, next-hop ARP, host
  gateways, and ICMP echo / Time Exceeded / Destination Unreachable with RTT and
  ping timeout.
- Tooling: interactive CLI, `.txt` scenarios, Lua 5.4 scripting (`exec`/`run`/
  `log`), JSON topology `save`/`load`, pcap frame capture, `trace`, `bench`,
  per-port `rx/tx/drop` counters.
- CLI productization: `--help/--version/--features`, stable exit codes
  (0/1/2), `file:line: error:` script diagnostics, `--quiet`, `--keep-going`,
  `-i/--interactive`, direct `.yn` scene loading, `demo`/`new` commands, man page
  (`docs/netsim.1`), and `make install`.
- Lua is secure by default: a restricted sandbox (no `os`/`io`/`package`/`debug`;
  no `dofile`/`load`/`loadfile`/`require`) with a 50M-instruction budget and a
  4 MiB script-size limit; `--no-lua` disables it entirely.
- Product: a self-contained native Win32 desktop app (`win/`, no browser) with a
  draggable topology canvas, toolbar, inspector, and console, plus a red
  six-pointed-star logo; File > New / Open / Save / Save As with `.yn` scenes
  (JSON content including canvas `layout`); optional loopback JSON endpoint
  (`./netsim --serve`) for headless use; `VERSION`, proprietary `LICENSE`,
  `CHANGELOG.md`, `make dist`.
- Quality: `-Werror`, ASan/UBSan unit tests, deterministic parser fuzzing,
  scenario + web smoke tests, gcc/clang CI, `.clang-tidy`.
