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
- Lua is bundled: Lua 5.4.6 sources live in `third_party/lua/` and are compiled
  statically into the CLI (safe subset; no external Lua install). The MIT notice
  ships with the product (`THIRD_PARTY_NOTICES.md`).
- Terminal-only product: interactive CLI plus `.txt`/`.lua`/`.yn` inputs,
  `state` JSON snapshots, and Ctrl-C to interrupt a running simulation. Editing
  commands: `remove-device`, `remove-port`, `disconnect`, `rename-device`,
  `set-ip`. (Earlier GUI/web front ends are archived under `legacy/` and not built.)
- Windows CLI `netsim.exe` with bundled Lua, a six-pointed-star icon, version
  resource, and DPI-aware manifest; `packaging/build-win.ps1` builds a portable
  CLI ZIP and `packaging/sign.ps1` signs it; a Windows CI job builds and uploads
  `netsim.exe`.
- `VERSION`, proprietary `LICENSE`, `THIRD_PARTY_NOTICES.md`, `CHANGELOG.md`,
  `make dist` / `make install`.
- Quality: `-Werror`, ASan/UBSan unit tests, deterministic parser fuzzing,
  scenario + CLI tests, gcc/clang CI, `.clang-tidy`.
