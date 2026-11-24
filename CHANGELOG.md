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
- DHCP relay (`dhcp-relay`) with giaddr rewriting and unicast server replies;
  DNS CNAME and multiple-A records (`dns-cname`).
- DHCP lease lifecycle: renew at 50% by unicast, rebind at 87.5% by broadcast,
  expiry clears the client address; server ACKs renewals to `ciaddr`.
- Router NAT: source PAT for TCP/UDP/ICMP (with TCP checksum recomputation) and
  inbound port forwarding (`nat`, `nat-port`, `nat-table`).
- RIP v2-lite dynamic routing (`rip`, `rip-status`): periodic broadcast updates,
  split horizon, infinity metric, and learned-route timeouts.
- OSPFv2 (`ospf`, `ospf-status`): RFC 2328 packet types and checksums,
  Hello/neighbor state machine, DR/BDR, per-area LSDB with DD/LSR/LSU/LSAck,
  aging/refresh, Dijkstra SPF, ABR multi-area Type 3 summaries, interface
  cost/passive policy, and simple-password or MD5 auth (`ospf-auth`).
  LSA 4/5 and NSSA remain planned.
- TCP now negotiates MSS and window scaling in SYN/SYN-ACK and applies scaled
  windows.
- TCP reliability: RTT/RTTVAR-based RTO (RFC 6298 style), oldest-unacked
  retransmission, RST handling, and basic zero-window probing.
- TCP SACK: SACK-permitted negotiation, receiver SACK blocks for out-of-order
  data, and sender retransmission of the first unsacked hole.
- TCP connection lifecycle: RST is returned for unmatched segments (unless the
  deprecated tcp-lite service owns the port), and closed connections are pruned.
- TCP keepalive (`tcp-keepalive <device> on|off`): idle probes with configurable
  defaults, peer ACK handling, and keepalive-timeout abort.
- TCP window updates are processed independently of ACK progress, zero-window
  persist probes retry until the window opens, and simultaneous open/close are
  supported.
- TCP observability/resources: `tcp-status` (state, RTO, cwnd, window, unacked,
  retransmits, counters), 256-connection per-host cap, and dropped/reset counters.
- TCP timestamps: SYN/ACK negotiation, TSecr echoing and timestamp-based RTT
  sampling; deterministic per-endpoint ISN generation; validated RST acceptance.
- TCP flow behavior: delayed ACK (every second in-order segment or 2 ticks) and
  Nagle (hold small writes while data is unacknowledged).
- TCP SACK recovery/DSACK: recovery point tracking, hole retransmission on
  partial ACK/additional duplicates, and DSACK detection/counters.
- TCP SYN backlog and stateless cookies: configurable backlog (`tcp-backlog`),
  cookie SYN-ACK when half-open capacity is exhausted, cookie validation on ACK,
  and accepted/sent cookie counters.
- Build/tests no longer delete `build/`; coverage builds into `build/cov/`.
- IPv4 header checksum is generated and verified on every packet.
- Go tools split into `cmd/` + `internal/` packages; added `ynpcap` PCAP
  conformance analyzer (IPv4/TCP/OSPF checksums, handshake, SYN options, OSPF
  MD5 digest verification with `-ospf-key`) and `make gotest`.
- OSPF MD5 authentication (`ospf-auth ... md5 <key-id> <key>`), including digest
  generation/verification and per-neighbor crypto sequence replay checks.
- OSPF interface policy: `ospf-cost`, `ospf-passive` (passive suppresses
  Hellos and advertises a stub link), and `ospf-area` per-interface areas.
- OSPF multi-area: per-area LSDB/SPF, ABR Type 3 summaries, and a three-router
  area 1 -> area 0 -> area 2 ping scenario.
- OSPF Type 5 external routes: `ospf-external <router> <ip/prefix> [metric]`,
  domain-wide LSA flooding, external route installation, and `external=` status.
- OSPF Type 4 ASBR summaries: ABRs advertise ASBR reachability into other areas,
  and external routes are installed via the Type 4/ASBR path.
- OSPF external withdrawal (`ospf-external ... clear`): stale Type 5 LSAs are
  flushed with MaxAge and external routes are removed.
- OSPF cryptographic auth now supports SHA-1 and SHA-256 HMAC (RFC 5709) in
  addition to MD5, with 16/20/32-byte digests and per-algorithm verification.
- OSPF NSSA (`ospf-area-type ... nssa`): Type 7 external LSAs inside the area,
  ABR Type 7-to-Type 5 translation, NSSA default summary, Type 5 suppression,
  and Type 7 withdrawal.
- CI now runs Go tool tests and the Windows PowerShell scenario suite; `make
  check` includes Go tests before coverage/soak/perf.
- OSPF stub areas (`ospf-area-type`): external LSAs are suppressed, the ABR
  advertises a default summary, and area-only routers do not install external
  routes.
- TCP PAWS: stale timestamp segments are discarded while RST is still accepted.
- TCP keepalive parameters are configurable (`on idle interval count`), DSACK
  restores cwnd after a spurious recovery, and RST acceptance is window-validated.
- OSPF: LSA retransmission with LSAck clearing, DD/LSR retransmission, and
  Full-state DD recovery under loss; `ospf_loss` scenario.
- Optional Go stress runner (`tools/ynstress`) for parallel scenario repetition.
- Windows test runner (`tests/run_tests.ps1`) plus cross-platform test paths.
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
