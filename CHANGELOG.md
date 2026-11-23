# Changelog

All notable changes to yanas net are recorded here.

## 0.1.0 — 2026-11-22

Initial product build.

- License: GNU GPLv3 or later (replaces the earlier proprietary placeholder);
  added `COPYRIGHT` and `SOURCE-CODE.md`, and binary distributions ship a source
  archive for GPL compliance.
- Open-source assets: `examples/` (thirteen runnable scenarios),
  `docs/USER_GUIDE.md` (student guide), `CONTRIBUTING.md`, and `SECURITY.md`.
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
- Diagnostics and visualization: `devices`, `links`, `ports`, `routes`,
  `arp-table`, `mac-table`, `traceroute`, and `export dot|svg`.
- UDP datagrams with a per-host echo service (`udp-echo`, `udp-send`).
- Real TCP service and client (`tcp-listen`/`tcp-connect`): handshake, data,
  out-of-order reassembly, RTO retransmission, FIN/TIME_WAIT, and slow-start/
  congestion-avoidance; packet-level tests incl. loss-driven retransmission.
- Deprecated `tcp-lite` teaching transport (not TCP).
- DHCP server/client (`dhcp-server`/`dhcp-client`; pool, gateway and DNS option)
  and a DNS A-record server plus resolver (`dns-server`/`dns-record`/`dns-query`).
- Router NAT: source PAT for TCP/UDP/ICMP (with TCP checksum recomputation) and
  inbound port forwarding (`nat`, `nat-port`, `nat-table`).
- RIP v2-lite dynamic routing (`rip`, `rip-status`): periodic broadcast updates,
  split horizon, infinity metric, and learned-route timeouts.
- OSPFv2 single-area core (`ospf`, `ospf-status`): RFC 2328 packet types and
  checksums, Hello/neighbor state machine, DR/BDR, LSDB with DD/LSR/LSU/LSAck,
  aging/refresh, Dijkstra SPF, and simple-password auth (`ospf-auth`).
  Multi-area and MD5 authentication are still planned.
- TCP now negotiates MSS and window scaling in SYN/SYN-ACK and applies scaled
  windows.
- TCP reliability: RTT/RTTVAR-based RTO (RFC 6298 style), oldest-unacked
  retransmission, RST handling, and basic zero-window probing.
- TCP SACK: SACK-permitted negotiation, receiver SACK blocks for out-of-order
  data, and sender retransmission of the first unsacked hole.
- OSPF: LSA retransmission with LSAck clearing, DD/LSR retransmission, and
  Full-state DD recovery under loss; `ospf_loss` scenario.
- Optional Go stress runner (`tools/ynstress`) for parallel scenario repetition.
- Windows test runner (`tests/run_tests.ps1`) plus cross-platform test paths.
- The earlier experimental "OSPF-lite" was removed; OSPF is being rebuilt to
  RFC 2328 and is not exposed until the real implementation lands.
- Link impairment (`set-link ... loss|dup|jitter|clear`) for reliability testing.
- TCP wire groundwork: options and the ones-complement checksum with pseudo-header.
- Per-router ACLs (`acl ... in|out allow|deny ...`) and `help <command>`.
- Terminal `map` and a `generate tree <depth> <fanout>` scale generator.
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
- `VERSION`, GNU GPLv3 `LICENSE` (`COPYRIGHT`), `THIRD_PARTY_NOTICES.md`, `CHANGELOG.md`,
  `make dist` / `make install`.
- Hard resource caps: devices 4096, ports 65536 (1024/device), links 65536,
  event queue 5,000,000 (run halts), pcap 2,000,000 frames / 256 MiB, scripts
  16 MiB / 1,000,000 lines, scenes 100,000 commands.
- Interactive line editing: history (saved to `~/.yanas_history`), Tab completion
  (commands and device names), Home/End, Ctrl-A/E/U/K; Windows falls back to line
  input.
- Structured output: `--json` NDJSON (per-command records + final `summary` with
  `state`) and `--log <file>`.
- `make check`: coverage gate (~55%, floor 54%), bounded-memory soak, throughput
  floor; CI adds a `check` job and macOS.
- Quality: `-Werror` (toggle with `WERROR=0`), ASan/UBSan unit tests, deterministic
  parser fuzzing, scenario + CLI tests, gcc/clang CI, `.clang-tidy`.
