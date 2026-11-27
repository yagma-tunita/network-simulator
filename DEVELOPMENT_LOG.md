# Development Log

A chronological record of how the network simulator was built, the design
decisions made along the way, and notable bugs that were found and fixed.
Entries are grouped by development phase in the order they were implemented.
Dates use the format `YYYY-MM-DD`.

---

## Phase 0 — Environment setup (2026-11-20)

- Toolchain: Ubuntu on WSL with `g++` 13.3, C++17.
- Configured VS Code IntelliSense (`c_cpp_properties.json`) to use the Linux
  compiler and its system include paths.
- Adopted a per-module layout under `core/`, `device/`, `engine/`, with each
  module split into `.hpp` (declarations) and `.cpp` (definitions).

## Phase 1 — IPv4 addresses (2026-11-20)

- Added `Ipv4` as a 32-bit value type (`uint32_t value`).
- Parsing: iterate the string, accumulate each octet with `temp = temp*10 + digit`,
  shift each octet into place (`value |= octet << offset`), and validate:
  digits only, at most three per octet, octet `<= 255`, exactly four octets.
- Introduced the `TryParse(...) -> bool` + throwing-constructor pattern so
  untrusted input can be handled without exceptions.
- Added `ToString`, `operator==`, `operator<`, `operator&`, `Any`, `Broadcast`.

Notable fixes:
- Early parser summed digits instead of accumulating (`temp += digit`) and used
  a `uint8_t` for shifted intermediates, which truncated. Corrected to
  `temp = temp*10 + digit` and 32-bit shifts.
- Shift amounts could go negative on malformed input; guarded the octet count.
- `hexVal`-style "returns -1 on failure" results must be stored in a signed `int`,
  otherwise `v < 0` is always false for unsigned types.

## Phase 2 — IPv4 subnets (CIDR) (2026-11-20)

- Added `Ipv4Subnet` storing a canonical network address plus a prefix length.
- `Mask()` converts prefix → mask via `0xFFFFFFFF << (32 - prefix)`, with a
  special case for `prefix == 0` to avoid a shift-by-32 (undefined behavior).
- `Broadcast()` = `network | ~mask`; `Contains(ip)` = `(ip & mask) == network`.
- `TryParse` splits on `/`, parses the address with `Ipv4::TryParse`, parses the
  prefix (0..32) manually, and normalizes the network.
- The `(Ipv4, prefix)` constructor validates the prefix and normalizes the
  network so host bits are always zero.

## Phase 3 — MAC addresses (2026-11-20)

- Added `Mac` as a 6-byte value type (`uint8_t bytes[6]`).
- Hex helpers `hexVal` / `hexChar`; parser collects 12 nibbles into 6 bytes and
  rejects invalid characters / wrong counts.
- Added `==`, `!=`, `<` (lexicographic over bytes), `Zero`, `Broadcast`,
  `ToString` (lowercase, colon-separated).

Notable fixes:
- `operator<` initially returned true if *any* byte was smaller; corrected to
  compare at the **first differing byte** (proper lexicographic order for map
  keys).
- `uint8_t` hex values hid negative sentinels; switched the accumulator to `int`.

## Phase 4 — Ethernet frames (2026-11-20)

- Added `EthernetFrame` with `dst`, `src`, `type` (EtherType), and a byte-vector
  `payload`; constants `kIPv4 = 0x0800`, `kARP = 0x0806`.
- Added `operator==` (including payload), `IsBroadcast`, and a debug `ToString`.

## Phase 5 — ARP (2026-11-20)

- Added `ARP` (`op`, `senderMac`, `senderIp`, `targetMac`, `targetIp`).
- Implemented a standard 28-byte wire format with a big-endian codec
  (`ToBytes` / static `TryFromBytes`).
- Added `MakeRequest` / `MakeReply` factories (requests carry an all-zero target
  MAC) and `IsRequest` / `IsReply`.

Notable fixes:
- `ToString` printed `senderIp` where `targetIp` was intended, and omitted a
  space after `"ARP"`; both corrected.

## Phase 6 — Connectivity: Port, Link, Device base (2026-11-20)

- `Port`: holds `mac`, optional `ip` / `subnet`, a `Link*`, and a `Device*`
  owner. `Send` forwards to the link; `Receive` forwards to the device.
- `Link`: point-to-point; `Transmit(from, frame)` forwards to the *other*
  endpoint; constructing a link wires the ports' back-references.
- Introduced an abstract `Device` base with `portList`, `AddPort`, a pure virtual
  `OnFrame`, and a virtual destructor; `Port::owner` became `Device*`.

Notable fixes:
- Circular includes between `Port`, `Link`, and `Device` were resolved with
  forward declarations in headers and full includes only in `.cpp` files.
- Include paths corrected from `./core/...` to `../core/...`.
- Aligned the `OnFrame` parameter to `const EthernetFrame&` so it overrides the
  base and matches `Port::Receive`.

## Phase 7 — End devices (hosts) (2026-11-20)

- `EndDevice` derives from `Device`, keeps an ARP cache (`std::map<Ipv4, Mac>`).
- `OnFrame`: drop frames not addressed to this port and not broadcast; dispatch
  ARP messages.
- `HandleArp`: decode payload, answer requests targeting the port's IP, and
  record `senderIp -> senderMac` on replies.
- `SendArpRequest`: choose an egress port whose subnet contains the target IP,
  build a request, and send it as an Ethernet broadcast.

Notable fixes:
- The frame filter inverted the broadcast check (dropping all broadcasts);
  corrected to `!(port->mac == frame.dst) && !frame.IsBroadcast()`.

## Phase 8 — Switch (2026-11-20)

- `Switch` derives from `Device`, keeps a MAC table (`map<Mac, Entry>`).
- `OnFrame`: learn the source MAC, flood group-addressed frames, forward known
  unicast, flood unknown unicast; drop frames whose egress equals the ingress.
- `Flood(except, frame)`: send out every port except the one the frame came from.

Notable fixes:
- An early version flooded based on the *source* address; corrected to flood
  based on the *destination* being a group address.
- Missing `Flood` implementation caused a linker error; added.

## Phase 9 — MAC-table aging (2026-11-20)

- Extended the MAC table entry to `{ Port* port; uint64_t lastSeen; }`.
- Added a header-only logical clock `SimClock` (`Now` / `Advance` / `Reset`) so
  time is deterministic and independent of wall-clock time.
- `OnFrame` calls `AgeOut(now)` first; learning refreshes `lastSeen`.
- `AgeOut` erases entries where `now - lastSeen > kAgingTimeout` (using safe
  erase-while-iterating).

## Phase 10 — IPv4 packets (2026-11-20)

- Added `IpPacket` (`ttl`, `protocol`, `srcIp`, `dstIp`, `payload`), with
  `kDefaultTtl = 64` and `kHeaderSize = 20`.
- `ToBytes` emits a 20-byte header (version/IHL `0x45`, total length, TTL,
  protocol, addresses) followed by the payload.
- `TryFromBytes` validates length and version, then reads fields by offset.
- Added `DecTtl` (guards against underflow at TTL 0), `operator==`, `ToString`.

## Phase 11 — Shared codec refactor (2026-11-20)

- The big-endian helpers were duplicated (ARP and, soon, IpPacket). Extracted a
  header-only `core/ByteIO.hpp` (`AppendU8/U16/Ipv4/Mac`, `ReadU8/U16/Ipv4/Mac`)
  and refactored `ARP` to use it.
- Kept single-use helpers (e.g., `hexVal`/`hexChar`, `MaskU32`) local to their
  modules to avoid unnecessary abstraction.

## Phase 12 — Repository and publishing (2026-11-20)

- Initialized Git in the project root, added a C++ `.gitignore` (from the
  official `github/gitignore` template).
- Cleaned up two mistakes: a stray empty repository created in the home
  directory, and a mistakenly published nested repository — then connected the
  project root to the GitHub remote and pushed `main`.
- Added a `.gitattributes` (`* text=auto eol=lf`) to normalize line endings to
  LF, and adopted the official GitHub C++ `.gitignore` template.
- Wrote `README.md` (project documentation) and this `DEVELOPMENT_LOG.md`.

## Phase 13 — Router module (in progress) (2026-11-20)

- Added `device/Router.hpp` / `Router.cpp` with:
  - `struct Route { Ipv4Subnet dst; Ipv4 nextHop; bool direct = false; }`.
  - `struct Router : Device` holding an ARP cache (`std::map<Ipv4, Mac>`) and a
    routing table (`std::vector<Route>`).
- Implemented `Router::IsMyIp(Ipv4)`: returns true if any own port has `hasIp`
  set and a matching IP.
- Declared `OnFrame(Port*, const EthernetFrame&) override` (not yet implemented).
- Planned helpers (to be declared/implemented): `HandleArp`, `SendArpRequest`,
  `Lookup`, `AddRoute`, `FindRoute` (longest-prefix match), `PortForNextHop`.

Notable fixes / lessons:
- Include paths in `Router.hpp` corrected from `./core/...` to `../core/...`.
- `Route::direct` initialized to `false` to avoid an indeterminate bool.
- Declaring (without defining) the `OnFrame` override makes `Router` concrete, but
  linking a program that instantiates it fails with
  `undefined reference to vtable for Router` until `OnFrame` is actually defined.
  A temporary stub `OnFrame` was used — only inside a throwaway test — to
  validate `IsMyIp`.

## Phase 14 — Router refactor, shared ARP, and comment-free sources (2026-11-20)

- Extracted a shared `ArpAgent` (`device/ArpAgent.hpp/.cpp`) that owns the ARP
  cache and request/reply handling. `EndDevice` and `Router` now compose it,
  removing the duplicated `HandleArp` / `Lookup` / `SendArpRequest` code.
- Completed `Router::OnFrame`: ARP dispatch plus IPv4 forwarding — TTL
  decrement, longest-prefix lookup, egress-port selection, next-hop ARP
  resolution, MAC-header rewrite, and transmit.
- Implemented router helpers: `IsMyIp`, `AddRoute` (two overloads), `FindRoute`
  (longest-prefix match), and `PortForNextHop`.
- Made `Device::AddPort` virtual; `Router` overrides it to auto-register a
  `direct` route for each IP-configured port (connected routes), so directly
  attached subnets are reachable without manual configuration.
- Robustness: null-pointer guards in `OnFrame` and `ArpAgent::HandleArp`;
  `Lookup` made `const`; consistent `const&` parameters.

Conventions:
- Source files are comment-free (all `.cpp` / `.hpp`). All documentation lives in
  `README.md` and this log; code carries no comments.

## Phase 15 — Router pending queue, shared Aging, ARP cache aging (2026-11-20)

- Router: added a per-next-hop pending-packet queue (`map<Ipv4, vector<Pending>>`)
  with `FlushPending`. When the next-hop MAC is unknown, `OnFrame` now holds the
  packet and sends an ARP request instead of dropping it; when the reply is
  learned, `FlushPending` transmits the held packets.
- Extracted a header-only generic aging helper `core/Aging.hpp`
  (`AgeOutEntries(table, now, timeout)`), erasing map entries whose
  `now - lastSeen > timeout`. `now` is passed in (no engine dependency).
- `ArpAgent`: time-based cache aging via `SimClock`. Entries now hold
  `mac + lastSeen`; `Learn` upserts and refreshes; `Lookup` drops expired entries
  and refreshes `lastSeen` on a hit; `HandleArp` calls `AgeOut` first.
- `Switch`: `AgeOut` now delegates to the shared `AgeOutEntries`.
- Docs: README updated for `Aging`, ARP cache aging, and the pending queue.

## Phase 16 — Codebase review and hardening (2026-11-20)

- Reviewed every source file against a commercial-quality bar and applied
  targeted, non-cosmetic fixes:
  - `Ipv4Subnet`: replaced `std::isdigit` (undefined behavior for negative
    `char`) with an explicit `'0'..'9'` range check; removed the unused
    `<cctype>` include.
  - `IpPacket`: `TryFromBytes` now validates the 16-bit total-length field and
    slices the payload to it; `ToBytes` throws `std::length_error` if the payload
    would overflow the total-length field. Added `<cstddef>` for `size_t`.
  - `Mac`: added `IsGroup()` (I/G bit); `Switch` now uses it instead of raw
    `& 0x01` bit twiddling.
  - `Device`: deleted its copy operations to prevent slicing of the polymorphic
    base (devices are held by pointer).
  - `Aging`: use `++it` instead of `it++`.
  - Self-sufficient includes: `<cstddef>` in `IpPacket.hpp`, `<map>` in
    `Router.hpp`.
- Verified: all core + device sources compile with `-Wall -Wextra`, zero warnings.
- Docs: README updated (Mac::IsGroup, IpPacket length validation, non-copyable
  Device, review notes).

## Phase 17 — Per-engine clock (A2), removing the global SimClock (2026-11-20)

- Adopted the "A2" clock model: each simulation owns its time. Deleted the global
  `engine/SimClock.hpp`.
- Added `engine/Clock.hpp`: `Clock` interface (`virtual uint64_t Now() const`).
- `Device` holds a `Clock*` and a virtual `SetClock(Clock*)`; `EndDevice` and
  `Router` override it to propagate the clock to their `ArpAgent`.
- `ArpAgent` holds a `Clock*` (`SetClock` / `Now()`); `Switch` reads time from its
  device clock. No module reads a global clock anymore.
- Enables scenario-level parallelism: independent engines can run one per
  thread/process, while the core event loop stays single-threaded and
  deterministic.
- Docs: README updated (Clock / Event / EventQueue / Scheduler, engine-owned time,
  scenario-level parallelism).

## Phase 18 — Event-driven delivery and hot-path optimization (2026-11-20)

- Frames now travel as `FramePtr` (`std::shared_ptr<const EthernetFrame>`) across
  `Device::OnFrame`, `Port::Send`/`Receive`, `Link::Transmit`, and `FrameDelivery`.
  Devices build frames with `make_shared<const EthernetFrame>`; forwarding and
  flooding share one immutable frame, eliminating whole-frame/payload copies on
  the hot path.
- `Link` is event-driven: `Transmit` schedules a `FrameDelivery` via
  `Scheduler::ScheduleAfter(delay, ...)`, with a synchronous fallback when no
  scheduler is attached.
- `engine/Engine` completed: `Engine : Scheduler, Clock` owns the event queue and
  the clock; `Step`/`Run`/`RunUntil`/`Reset`, `ScheduleAt`/`ScheduleAfter`;
  deterministic `(time, seq)` ordering.
- Switch MAC-table aging throttled: sweeps at most every `kSweepInterval` instead
  of on every frame (O(table) per frame removed).
- `ARP::ToBytes` / `IpPacket::ToBytes` reserve their buffer; `Ipv4Subnet::Contains`
  uses a direct mask computation (no temporary `Ipv4`).
- Deferred: Engine-level event allocator/pool (needs real load to tune).
- Verified: all core + device + engine sources compile with `-Wall -Wextra`,
  zero warnings. Docs: README updated (FramePtr, event-driven flow, Engine done,
  status).

## Phase 19 — Topology builder, CLI, and end-to-end run (2026-11-20)

- Moved `Link` from `device/` to `link/` (folder now matches its concern); fixed
  includes in `Port.cpp` and `Topology.cpp`.
- Added `topo/Topology` — owns devices/ports/links (`unique_ptr`), name index,
  builder API (`AddEndDevice/Switch/Router`, `AddPort`, `Connect`, `AddRoute`);
  injects the engine clock into devices and the scheduler/delay into links.
  Constructor and destructor are out-of-line so the header stays light
  (forward-declared device types).
- Added `topo/TopoCommand` — tokenizer + command interpreter shared by both input
  modes (`add-device`, `add-port`, `connect`, `add-route`, `arp`).
- Added `app/main.cpp` — `netsim` entry point: interactive prompt and
  `.txt` script import (blank lines / `#` comments skipped), plus `run`/`step`/
  `lookup`/`help`/`quit`.
- Verified end-to-end: an ARP request/reply across a two-host link completes over
  the event-driven pipeline (`now=2`) and PC1 learns PC2's MAC
  (`lookup PC1 192.168.1.2` → `aa:aa:aa:aa:aa:02`).
- Docs: README structure/Link path/build/run added; status updated.

## Phase 20 — Build system, tracing, VLAN, and ICMP ping (2026-11-20)

- Added a `Makefile` (`make` → `./netsim`, `make clean`); removed `Makefile` from
  `.gitignore` (it is hand-written, not CMake-generated) and ignored the `netsim`
  binary.
- Event tracing: `Engine` has an optional `std::function` trace hook invoked in
  `Step`; the CLI exposes `trace on|off`.
- VLAN (port-based): `Port` gained a `vlan` field; the switch keys its MAC table by
  `(vlan, mac)` and floods/forwards only among ports in the same VLAN. The CLI
  exposes `set-vlan <dev:idx> <vid>`.
- ICMP: added `core/IcmpMessage` (echo request/reply codec) and
  `IpPacket::kIcmp`; `EndDevice` now parses IPv4, answers echo requests (replying
  to the frame's source MAC), and can `SendPing`. CLI exposes `ping <device> <ip>`.
- Verified: `make` builds clean; VLAN-10 switch scenario forwards correctly; a
  host-to-host ping completes over the event pipeline and prints
  `ping reply from 192.168.1.2 seq=1`.
- Deferred: Engine event allocator/pool (measurement-driven; not added speculatively).

## Phase 21 — Regression test suite (2026-11-20)

- Decision: keep the event pool deferred (speculative, needs profiling) and instead
  add the regression protection a commercial product needs.
- Added `tests/`: scene `.txt` files plus `.want` expected-substring files, and
  `tests/run_tests.sh` which builds with `make`, runs each scenario through
  `netsim`, checks the expected output, and cleans up.
- Scenarios: ARP resolution (direct link), ICMP ping, and VLAN isolation (a VLAN-20
  host is unreachable from a VLAN-10 ARP).
- Verified: `bash tests/run_tests.sh` → PASS arp / ping / vlan.
- Docs: README structure (tests/, Makefile), Testing section, status updated.

## Phase 22 — Host gateway, cross-subnet ping, CMake, and event benchmark (2026-11-22)

- Host default gateway: `EndDevice` gained `SetGateway`/`hasGateway`; `SendPing`
  resolves the next hop (the gateway for off-subnet targets) and ARPs for the
  gateway's MAC. New `set-gateway` CLI command.
- Router ARP integration: the router resolves the next-hop MAC through the shared
  `ArpAgent` and flushes queued IP packets once it is known, so a host can ping
  across subnets through a router.
- Added `tests/route.txt` / `route.want`: PC1 in 192.168.1.0/24 pings PC2 in
  192.168.2.0/24 through a router; expects `ping reply from 192.168.2.1`.
- Added `CMakeLists.txt` as an alternative build. Could not be verified here:
  `cmake` is not installed in this environment (the Makefile remains verified).
- Added a `bench [n]` command that schedules and runs `n` no-op events and reports
  events/second. Measured ~5.9M events/s single-threaded, so the event pool is
  **not** needed; that deferred task is closed as unnecessary for realistic loads.
- Verified: `bash tests/run_tests.sh` → PASS arp / ping / route / vlan.
- Docs: README features, build, commands, testing, structure, and status updated.

## Phase 23 — 802.1Q trunk tagging with real frames (2026-11-22)

- Decision: implement VLAN tagging at the frame level (real 802.1Q), not as a
  link-side simulation hack, so the wire format matches IEEE 802.1Q.
- `EthernetFrame`: optional tag `hasVlanTag` / `vlanId` (12-bit VID) / `vlanPcp`
  (3-bit PCP) / `vlanDei`; `type` now holds the inner EtherType. Added `Tci()`,
  `VlanId()`, `WithVlan()`, `WithoutVlan()`, and real `ToBytes()` / `TryFromBytes()`
  that emit and parse `[dst][src][0x8100][TCI][EtherType][payload]`.
- `Port`: added `tagged`; `vlan` is the PVID / native VLAN.
- `Switch`: classifies ingress by port mode (access → PVID, trunk → tag's VID or
  the native VLAN), learns per `{vid, mac}`, and `Emit`s per egress port: a trunk
  pushes a tag, an access port pops it and only forwards when its PVID matches.
- CLI: `set-trunk <dev:idx> [native-vid]`; `set-vlan` now also marks the port
  access (`tagged = false`).
- Added `tests/trunk.txt` / `trunk.want`: PC1 and PC2 sit on different switches in
  VLAN 10, joined by a trunk; ping succeeds across the tagged link.
- Verified: `bash tests/run_tests.sh` → PASS arp / ping / route / trunk / vlan; a
  temp program confirmed the 802.1Q byte layout and `ToBytes`/`TryFromBytes`
  round-trip (tagged and untagged, plus short-buffer rejection).
- Docs: README covers access vs trunk, the frame tag fields, and the commands.

## Phase 24 — Commercial quality gate and bounded resources (2026-11-22)

- First step of the commercial-simulator push: a real safety net plus hard
  resource bounds, all verified locally.
- `Makefile`: default `-Werror`; new targets `unit`, `fuzz`, `san`, and `test`
  (unit + fuzz under `-fsanitize=address,undefined` with leak detection, then the
  scenario suite). Sanitizer binaries live in `build/` (cleaned by `make clean`).
- `tests/unit/unit_tests.cpp`: 66 checks across `Ipv4`, `Ipv4Subnet`, `Mac`,
  `ARP`, `IpPacket`, `IcmpMessage`, and `EthernetFrame` (tagged/untagged codec,
  malformed-input rejection, TTL clamp).
- `tests/fuzz_parsers.cpp`: deterministic (fixed-seed) fuzzing of every byte
  parser; ASan/UBSan-clean over 200k iterations.
- `tests/run_tests.sh`: also fails a scenario when the output contains a `fatal:`
  line, and prints the full output on failure.
- Resource bounds: `Router::pending` gained a per-destination cap
  (`kMaxPendingPerDest = 32`) and an age-out (`kPendingTimeout = 300`) with a
  `droppedPending` counter; `bench` clamps `n` to 50M.
- Verified: `make test` → 66/66 unit checks, 200k fuzz iterations clean (ASan +
  UBSan + leak detection), all 5 scenarios PASS.
- Docs: README build/testing/structure/status updated with the gate and roadmap.

## Phase 25 — Spanning Tree (STP) and loop-free L2 (2026-11-22)

- Chosen loop-protection approach: classic 802.1D STP (per-switch, opt-in) rather
  than a sim-only hop limit, so redundant topologies behave like a real switch.
- Added `device/StpBpdu.{hpp,cpp}`: a 35-byte Configuration BPDU codec (root id,
  root path cost, sender bridge/port id, timers). BPDUs ride a private EtherType
  `0x8E01` on the existing frame path.
- `Port`: added STP fields (`stpCost`, `stpState`, `stpRole`, per-port best BPDU).
- `Switch`: bridge id (priority + lowest-port MAC), event-driven BPDU exchange,
  root election, root/designated/alternate roles, and forwarding gating
  (`OnFrame`/`Emit` drop data on Blocking ports; BPDUs are handled before
  learning). STP is off by default, so non-STP scenes are unchanged.
- CLI: `set-stp <switch> on|off`, `set-bridge <switch> <priority>`,
  `stp-status <switch>`.
- Tests: `tests/stp.txt` (redundant triangle; ping succeeds and `run` converges —
  a storm would never drain the event queue) and `tests/stp_status.txt` (asserts
  `p0 blocking` on SW3). Added a `StpBpdu` round-trip unit test and a guarded
  `timeout` in `run_tests.sh`.
- Verified: `make test` → 71/71 unit checks, 200k fuzz iterations clean, all 7
  scenarios PASS (arp, ping, route, stp, stp_status, trunk, vlan).
- Scope note: convergence is event-driven; periodic Hello/Max-Age timers,
  Listening/Learning forward-delay, and RSTP are deferred to the next sub-step.
- Docs: README features, STP section, commands, Switch API, testing, status updated.

## Phase 26 — ICMP, host auto-ARP, and STP forward delay (2026-11-22)

- Injected a `Scheduler` into `Device` (wired by `Topology`) so hosts and switches
  can schedule timers.
- `EndDevice`: automatic ARP resolution with a bounded pending queue
  (`kMaxPending = 64`); per-ping outstanding table with RTT and a one-shot timeout
  (`kPingTimeout = 50`); handles ICMP Time Exceeded and Destination Unreachable and
  cancels the matching ping by parsing the embedded original IP+ICMP header.
- `Router`: generates ICMP Time Exceeded (TTL <= 1) and Destination Unreachable
  (no route / no egress), and replies to pings addressed to its own interfaces.
- CLI: `ping <device> <target-ip> [ttl]`.
- `Switch`/STP: port state machine Blocking -> Listening -> Learning -> Forwarding
  with per-port forward-delay timers (`kForwardDelay = 15`); a Learning port learns
  but does not forward; `stp-status` prints the live state.
- Tests: `auto_ping`, `ping_timeout`, `ttl`, `unreachable`; the existing `stp` and
  `stp_status` scenarios still pass.
- Verified: 71 unit checks, fuzz clean, 11 scenarios PASS.

## Phase 27 — Lua scripting, CI, and shared command runner (2026-11-22)

- Extracted the CLI interpreter into `topo/CommandRunner`, shared by the
  interactive/file CLI and the Lua bridge.
- Added `script/LuaScript` against the real Lua 5.4 C API: globals `exec(line)`,
  `run()`, and `log(...)`; `.lua` scene files are detected by extension, and
  `--features` reports whether Lua is compiled in.
- `Makefile`: Lua is auto-detected via `pkg-config lua5.4` (`LUA=auto|0|1`, with
  `LUA_CFLAGS` / `LUA_LIBS` overrides and `-DHAVE_LUA`).
- Added `.github/workflows/ci.yml` (gcc/clang matrix; installs `liblua5.4-dev`
  and runs `make test`) and `.clang-tidy`.
- Tests: `tests/lua_ping.lua` (Lua loop + `exec` + `run`); the runner also runs
  `.lua` scenes when Lua is built (feature check) and applies a timeout.
- Verified both build modes: Lua off (`--features` = `core`) and Lua on
  (`--features` = `core lua`), full `make test` -> 71 unit, fuzz clean, 11 `.txt`
  scenarios + `lua_ping.lua` PASS. Local Lua verification used headers extracted
  from `liblua5.4-dev` (CI installs the package normally).
- Scope: STP Hello/Max-Age aging, link-flap reconvergence, and RSTP remain
  (documented in README as planned).

## Phase 28 — Link flap reconvergence, port counters, and tidy (2026-11-22)

- `Link` gained an up/down state (`SetUp`, `IsUp`); transmissions are no-ops when
  down. Devices get `OnLinkUp` / `OnLinkDown` hooks; `Switch` overrides them to
  clear the affected BPDU state, flush the MAC table, re-run the election, and
  re-send BPDUs.
- CLI: `set-link <dev:idx> down|up`.
- Port counters `rx` / `tx` / `drop` (`tx` in `Link::Transmit`, `rx` in
  `Port::Receive`, drops for STP-blocked ingress/egress, VLAN filtering, and
  router drops). CLI: `stats <device>`.
- `Makefile`: `make tidy` (clang-tidy per translation unit); CI gains an advisory
  tidy job.
- Tests: `tests/reconverge.txt` (triangle; flap the active SW1-SW3 link and a
  second ping still succeeds over the alternate path) and `tests/stats.txt`
  (asserts `p0 rx=2 tx=2 drop=0`).
- Verified: 71 unit checks, fuzz clean, 13 `.txt` scenarios + `lua_ping.lua` PASS
  (Lua build).
- Remaining (documented): STP Hello/Max-Age aging, RSTP, pcap export, JSON/YAML
  config, and enforcing clang-tidy.

## Phase 29 — Timers, RSTP mode, pcap, JSON config, and build deps (2026-11-22)

- Bounded time: `run [duration]` advances at most `duration` (default 1000) or
  until the queue is empty; the implicit final drain was removed so periodic
  timers cannot hang a script. `run 50` sets an explicit window.
- STP: periodic Hello BPDUs (`kHello = 2`) now re-arm a `stp-hello` event; keepalive
  BPDUs refresh per-port timestamps and Max-Age (`kMaxAge = 20`) expires stale
  neighbor info. Recompute re-runs when an entry ages out.
- RSTP-style rapid mode: `set-stp-mode <switch> rstp` uses version-2 BPDUs and
  immediate forwarding (no Listener/Learner delay). This is a rapid subset, not
  the full 802.1w proposal/agreement state machine.
- pcap: `Scheduler` gained `TapFrame`/`Now`; `Link::Transmit` taps every frame into
  a `PcapWriter` (standard pcap global header + per-packet records). CLI:
  `pcap <file>` / `pcap off` (prints the captured count).
- JSON config: `topo/JsonConfig` writes/parses a small schema (devices, ports,
  links, stp, routes, gateways) and `load` replays it as commands. CLI: `save` and
  `load`. Fixed a dangling `std::string` reference in the parser (bound `ss.str()`
  temporary) found while testing load.
- Makefile: added `-MMD -MP` header dependency tracking (`.d` files), fixing a
  stale-object vtable crash that appeared only on incremental builds.
- Tests added: `rstp.txt`, `pcap.txt`, `save.txt`, `config_load.txt` (plus
  `tests/config.json`); manual save->load round-trip verified.
- Verified: `make test` (Lua build) -> 71 unit checks, 200k fuzz clean, 16 `.txt`
  scenarios + `lua_ping.lua` PASS.
- Remaining (documented): full 802.1w proposal/agreement; clang-tidy is advisory;
  drop-reason breakdown.

## Phase 30 — Product shell "yanas net" (2026-11-22)

- Branding: name `yanas net`, a red regular-hexagon logo (SVG, rotated 15°),
  version 0.1.0 (`app/Version.hpp`, `VERSION`), plus `--version` and an interactive
  startup banner.
- Embedded local web UI: `./netsim --serve [port]` (loopback only) serves a
  classic desktop-style single-page UI (`web/index.html`, `style.css`, `app.js`,
  `logo.svg`) and a JSON API: `/api/state`, `/api/cmd`, `/api/run`, `/api/step`.
  The server reuses the shared command interpreter and captures stdout into JSON
  responses. Lua is not exposed over HTTP, so the browser cannot execute arbitrary
  code.
- UI: topology canvas (auto-layout; links colored for down / STP-blocked), toolbar
  (add host/switch/router, add port, connect, run/step, ping, STP, save/load),
  live inspector (ports, IP/VLAN, STP state, rx/tx/drop), and a command console.
- Industrial scaffolding: proprietary `LICENSE` placeholder, `CHANGELOG.md`,
  `VERSION`, `make dist` (tarball with binary + web + docs); `dist/` is ignored.
- Tests: `tests/web_test.sh` starts the server and checks static assets + API;
  wired into `run_tests.sh` and CI. Verified all scenarios + web smoke under the
  Lua build (71 unit, fuzz clean).
- Note: this is the product shell/foundation. A fully mature product still needs a
  native installer, a security review/audit, a user manual, and deeper UI/QA; the
  web server is POSIX (WSL/Linux/macOS) — a native Windows (Winsock) port and full
  802.1w remain follow-ups.

## Phase 31 — Native desktop app and logo correction (2026-11-22)

- Product direction corrected: the primary UI is a self-contained native **Win32**
  desktop application (`win/main_win.cpp`, built to `yanasnet.exe` with MinGW-w64
  via `Makefile.win`); it does not depend on a browser or any GUI framework.
- The app embeds `Engine` + `Topology` + `CommandRunner` in-process and draws the
  topology with GDI (grid; links colored for down / STP-blocked; devices by kind;
  selection highlight). Toolbar: add host/switch/router, add port, connect, run,
  step, ping, STP, save, load. Live inspector (ports/IP/VLAN/STP/counters),
  command console (captures stdout), status bar, classic gray desktop styling.
- Logo corrected to a red **six-pointed star** (hexagram), drawn with 12-vertex GDI
  polygons in the app and updated in `web/logo.svg`.
- The loopback JSON/web UI is retained only as an optional POSIX headless/CI
  endpoint (`--serve`); it is no longer the product UI.
- Build/verify: `mingw32-make -f Makefile.win` -> `yanasnet.exe` (458 KB);
  launched with `Start-Process`, ran without crashing for the smoke window, then
  stopped. Core still covered by `make test` (71 unit, fuzz, scenarios, web
  endpoint).
- Next for "mature industrial": code-sign the executable, an installer
  (MSI/Inno), an embedded application icon/manifest, a user manual, and coverage
  gates.

## Phase 32 — Draggable topology nodes (2026-11-22)

- Canvas nodes are now draggable: mouse-down hit-tests and starts a drag
  (`SetCapture`), mouse-move updates the node position with clamping to the canvas,
  mouse-up ends it; links are redrawn from the updated positions.
- Positions live in a name→point map: new devices are auto-placed on a grid while
  moved devices keep their position across refresh/run/commands (stale entries are
  pruned). The drag offset keeps the grab point under the cursor.
- Rebuilt `yanasnet.exe` (MinGW-w64) and smoke-launched (ran 2 s, then stopped).
- Follow-up for a fully industrial build: persist canvas positions in the JSON
  scene format, plus executable icon/manifest, installer, and code signing.

## Phase 33 — Scene files `.yn` and New/Open/Save (2026-11-22)

- Added `Topology::Clear()` so the desktop app can reinitialize. `ClearSession()`
  resets the engine (`Engine::Reset`), clears the topology/queue, pcap, selection,
  and node positions.
- `JsonConfig`: scene save/parse now carries a `layout` array (device → x, y);
  signatures take a `LayoutMap`. The `.yn` file is JSON content (devices, ports,
  links, stp, routes, gateways, layout). `save`/`load` commands updated; the CLI
  ignores layout, the GUI applies it.
- Desktop app File workflow: `New`, `Open...`, `Save`, `Save As...` via the Win32
  common dialogs (`GetOpenFileNameA`/`GetSaveFileNameA`, filter `*.yn`, default
  extension `yn`). `Save` writes the current path (prompting if untitled), `Open`
  reinitializes then replays the scene, and the window title shows the file name.
  Toolbar gains New/Open/Save.
- Migrated the sample scene to `tests/config.yn` (with layout); updated
  `config_load`/`save` scenarios and docs.
- Verified: `make test` (Lua build) all green; rebuilt `yanasnet.exe` (MinGW-w64,
  now links `comdlg32`) and smoke-launched it.
- Remaining for "mature industrial": executable icon/manifest, installer, and code
  signing; positions are saved in `.yn` but there is no undo/dirty-prompt yet.

## Phase 34 — Product-grade CLI (2026-11-22)

- Reworked the CLI entry point into a real product surface: `--help/--version/
  --features`, documented options, and stable exit codes (0 success, 1 runtime/
  script error, 2 usage error).
- File dispatch by extension: `.yn`/`.json` load a scene directly, `.lua` runs a
  Lua script, anything else is a line-command script. `-i/--interactive` enters the
  prompt after loading; `-q/--quiet` suppresses status lines; `--keep-going`
  continues after errors; `--no-lua` hardens against untrusted Lua.
- Script errors now report `file:line: error: ...` (scene commands report the
  command index) and stop at the first error by default.
- `CommandContext` gained `quiet`; `run`/`step`/`trace` honor it. Added `new`
  (reset) and `demo` (sample 2-host + switch ping) commands for onboarding.
- Added `docs/netsim.1` (man page), `make install` (binary + man, honoring
  `PREFIX`/`DESTDIR`), and `docs/` in `make dist`.
- Added `tests/cli_test.sh` (version/help/usage-exit/scene/error-line/quiet),
  wired into `run_tests.sh`/CI. Verified: all unit/fuzz/scenario/web/CLI checks
  pass; `make install DESTDIR=/tmp/...` and `make dist` produce the expected tree.
- Note: the terminal build is now product-grade for technical/automation users
  (stable contract, diagnostics, docs). "Commercial" still also implies support,
  legal, signing, and marketing, which are non-code workstreams.

## Phase 35 — Secure-by-default Lua sandbox (2026-11-22)

- Lua files still run directly, but now in a restricted environment by default:
  only base (minus `dofile`/`load`/`loadfile`/`require`), `string`, `table`,
  `math`, `utf8`, and `coroutine` are opened; `os`, `io`, `package`, and `debug`
  are not loaded, removing the previous arbitrary-code-execution paths.
- Added a per-run instruction budget (50M instructions) via `lua_sethook`
  (`LUA_MASKCOUNT`) and a 4 MiB script-size limit, so runaway/infinite scripts and
  oversized inputs terminate quickly. `--no-lua` still disables Lua entirely.
- Tests: `tests/lua_sandbox.lua` (asserts `os` and `require` are unavailable →
  `sandbox ok`) and `tests/lua_budget.lua` (infinite loop → `instruction budget`,
  exits non-zero in <1 s). Both run in the scenario suite under the Lua build.
- Verified: full gate green (71 unit, fuzz, 17 `.txt` + 3 Lua scenarios, web, CLI).
- Note: this is a capability sandbox for a local simulator, not a hardened
  multi-tenant container; the command set still intentionally allows scene file
  save/load and pcap output.

## Phase 36 — Bundled, statically linked Lua (2026-11-22)

- Vendored Lua 5.4.6 under `third_party/lua/` as a safe subset: core VM + auxlib +
  base/table/string/math/utf8/coroutine. `liolib`, `loslib`, `loadlib`, `ldblib`,
  and `linit` are excluded, so `os`/`io`/`package`/`debug` are not even compiled
  (stronger than runtime blocking).
- Builds link Lua statically: the POSIX `Makefile` compiles the C sources with
  `$(CC)` into `liblua.a` and always defines `HAVE_LUA`; `CMakeLists.txt` builds a
  `yanas_lua` static library; `Makefile.win` compiles the same sources with MinGW
  `gcc` and links `yanasnet.exe`. The system/`pkg-config` Lua dependency is gone
  and CI no longer installs `liblua5.4-dev`.
- Desktop app: File > Run Lua Script... runs a sandboxed scenario and routes its
  output to the console.
- Licensing: added `third_party/lua/LICENSE` and `THIRD_PARTY_NOTICES.md` (MIT);
  `make dist` includes `third_party` and the notice.
- Verified: WSL `make test` green with bundled Lua; `ldd netsim` shows no `liblua`
  (static); Windows `yanasnet.exe` rebuilt with Lua and smoke-launched.
- Note: users need no Lua environment at all.

## Phase 37 — Windows CLI, resources, packaging, and Windows CI (2026-11-22)

- Ported the embedded JSON server from POSIX sockets to a portable layer: POSIX on
  Unix and Winsock2 on Windows (`socket_t`, `StartSockets`, `CloseSock`, `-lws2_32`).
  `netsim.exe --serve` now works on Windows (verified: HTTP 200 from
  `http://127.0.0.1:18081/api/state`).
- Built a second Windows executable: `netsim.exe` (console CLI, bundled Lua,
  `--serve`) alongside `yanasnet.exe` (GUI). Both link the same vendored Lua.
- Windows resources: generated `win/yanas.ico` (16/32/48 six-pointed star),
  `win/yanas.manifest` (DPI aware), and `win/yanas.rc` (icon + VERSIONINFO); the
  GUI loads the icon from the resource. Version info verified via
  `(Get-Item yanasnet.exe).VersionInfo`.
- Packaging/signing: `packaging/build-win.ps1` (both exes + portable ZIP),
  `packaging/yanas-net.iss` (Inno Setup), `packaging/sign.ps1` (signtool), and a
  Windows CI job (MSYS2/MinGW builds both executables and uploads artifacts).
- Build hygiene: POSIX Lua objects now live under `build/lua/` to avoid mixing
  MinGW COFF objects with ELF builds; `make dist` excludes `*.o/*.a` and includes
  `packaging/`, `win/` resources, and both Windows executables when present.
- Verified: WSL `make test` fully green with bundled Lua and the portable server;
  Windows `netsim.exe` (`--version/--features/lua_sandbox/config.yn/--no-lua`) and
  `yanasnet.exe` smoke-launched; portable ZIP contents checked.
- Note: Inno Setup compilation and actual code signing require the external tools
  and a certificate (not available here); the scripts are provided.

## Phase 38 — Terminal-only pivot and CLI editing (2026-11-22)

- Product focus narrowed to the terminal for technical users. The native GUI and
  the loopback web/JSON front end were moved to `legacy/` (kept for reference, not
  built) and removed from the build, CI, docs, and packaging. The Windows console
  CLI (`netsim.exe`) remains; the portable ZIP is CLI-only.
- New editing commands: `remove-device`, `remove-port`, `disconnect`,
  `rename-device`, `set-ip`. `Topology` gained the corresponding operations
  (removing a port also removes its link; router connected routes are rebuilt).
- `state` command prints a JSON snapshot (devices, ports/IP/VLAN/STP state,
  counters, links, time) for automation, replacing the web `/api/state` use case.
- Ctrl-C now interrupts a running simulation cleanly: `Engine` has a
  `shouldStop` hook checked in `Run`/`RunUntil`; the CLI installs a `SIGINT`
  handler, prints `interrupted; now=...`, and keeps the process responsive.
- Build/CI/packaging: Makefile/CMake/`Makefile.win` build only `netsim`(exe);
  Windows resources (icon/version/manifest) remain on the CLI; CI's Windows job
  builds `netsim.exe`; `packaging/build-win.ps1` produces a CLI ZIP.
- Tests: CLI regression extended with `edit-state` (rename + set-ip + absence of
  the old name) and `remove-disconnect` checks. Ctrl-C verified with a busy
  three-switch STP scenario under `timeout -s INT` (`interrupted`).
- Verified: WSL `make test` green (71 unit, fuzz, 17 scenarios + 3 Lua + CLI),
  Ctrl-C interruption, Windows `netsim.exe` build and smoke.

## Phase 39 — Caps, line editing, JSON output, and quality gates (2026-11-22)

- Hard resource caps: `Topology` limits devices (4096), ports (65536, 1024/device),
  and links (65536); `Engine` caps the event queue (5,000,000) and sets `halted`
  (the `run` command reports it); `PcapWriter` caps frames (2M) and bytes (256 MiB,
  reports on `pcap off`); scripts are limited to 16 MiB / 1M lines and scenes to
  100k commands.
- Interactive line editor (`app/LineEditor`): POSIX termios and native Windows
  console implementations with history (`↑`/`↓`), Tab completion (commands + device
  names), Home/End, Ctrl-A/E/U/K, history persisted to `~/.yanas_history`; non-TTY
  falls back to `std::getline`. Windows uses `ReadConsoleInputW` + VT rendering, so
  it works in PowerShell/cmd.
- Structured output: `--json` emits NDJSON (one `{line,cmd,ok,output,error}` per
  command plus a final `{summary,state}`); `--log <file>` mirrors it to a file.
  `StateSnapshot` is exposed from the command layer; Lua `print` now routes through
  the captured stream.
- Quality gates: `make check` = `make test` + `tests/coverage.sh` (gcov aggregate,
  measured ~58%, threshold 55%), `tests/soak.sh` (256 MiB `ulimit -v`, STP
  reconvergence), and `tests/perf.sh` (bench throughput floor 200k events/s).
  `bench` now schedules in chunks to keep memory bounded.
- Build/CI: `WERROR=0` toggle; portable `find -delete` cleanup; CI adds a `check`
  job (coverage/soak/perf) and a macOS job; `make dist` now ships the full source
  tree (core/device/link/engine/topo/app/script/tests, `.github`, etc.).
- Unit tests extended to 137 checks (topology/event caps, engine ordering/trace,
  JSON round-trip, ICMP errors, pcap caps, end-to-end host and router ping).
- Verified locally: `make check` green (137 unit, fuzz, scenarios, CLI; coverage
  ~58%; soak ok; perf ~11M events/s); Windows `netsim.exe` rebuilt and `--json`
  / piped fallback verified.

## Phase 40 — Open source under GPLv3 and project assets (2026-11-22)

- License switched from the proprietary placeholder to the **GNU GPL v3.0 or
  later**: `LICENSE` is now the GPLv3 text, `COPYRIGHT` was added, and
  `SOURCE-CODE.md` documents source availability. Bundled Lua (MIT) is
  GPL-compatible; its notice remains in `THIRD_PARTY_NOTICES.md`.
- Binary distributions now include corresponding source: `make dist` produces the
  source tarball, and `packaging/build-win.ps1` builds a source ZIP and embeds it
  in the Windows CLI ZIP (GPLv3 section 6).
- Added open-source project assets: `examples/` (two hosts, switch/VLAN, router,
  STP, Lua, `.yn` scene), `docs/USER_GUIDE.md` (operator walkthrough),
  `CONTRIBUTING.md`, `SECURITY.md`, and `docs/logo.svg`.
- Tests: `tests/examples.sh` runs every example and is wired into
  `tests/run_tests.sh`/CI, so the examples stay runnable.
- Docs: README license/examples/structure/status updated; man page gains a LICENSE
  section.

## Phase 41 — Diagnostics, traceroute, and topology export (2026-11-22)

- `traceroute`: `EndDevice` sends sequential ICMP echo probes with TTL 1..N,
  reusing the ARP/TTL/ICMP paths. Time Exceeded replies print each hop, timeouts
  print `*`, and an echo reply prints the target and stops. Implemented with a
  one-shot `trace-next` event between probes.
- Diagnostics: `devices`, `links`, `ports <dev>`, `routes <router>`,
  `arp-table <dev>`, `mac-table <switch>` (ages from the logical clock).
- `export dot|svg`: new `topo/Export` writes a Graphviz DOT file or a self-contained
  SVG topology diagram, so the network can be visualized without a GUI.
- Tab completion now completes `dev:idx` port references and `export dot|svg`.
- Tests: `tests/traceroute.txt`, `tests/show.txt`; `cli_test.sh` checks the show
  commands and verifies the DOT/SVG files; `examples/07_traceroute.txt`.
- Verified: `make test` green (144 unit checks, fuzz, 20 scenarios + 3 Lua + CLI +
  7 examples); `make check` coverage 55.6% (floor 55%), soak and perf pass; Windows
  `netsim.exe` rebuilt and `traceroute` / `show` / `export` verified.

## Phase 42 — UDP, terminal map, and scale generator (2026-11-22)

- UDP: added `core/UdpDatagram` (8-byte header + payload) and `IpPacket::kUdp`.
  Hosts can run an echo service (`udp-echo <dev> on|off [port]`) and send datagrams
  (`udp-send <dev> <ip> <dport> <text...>`); replies reuse the ARP/pending path.
- Terminal usability: `map` prints an adjacency map (device kind, ports, links).
- Scale: `generate tree <depth> <fanout>` builds a switch tree with one host per
  leaf (capped for /24 and device limits); `tests/scale.txt` pings across a
  3x3x3 tree (40 switches, 27 hosts).
- Tests: `tests/udp.txt`, `tests/scale.txt`, `examples/08_udp.txt`, plus UDP,
  UDP-echo, and command-layer unit tests (155 checks).
- Docs: README/user guide/man updated for UDP, map, and tree generation.
- Note: this is the first protocol-breadth slice; TCP, DHCP/DNS, ACL/NAT, dynamic
  routing, IPv6, and parallel scenario batches remain follow-ups.

## Phase 43 — Simplified TCP, ACLs, and per-command help (2026-11-22)

- TCP: added `core/TcpSegment` (20-byte header + flags/payload) and
  `IpPacket::kTcp`. Hosts can run a TCP echo service (`tcp-echo`) and a client
  (`tcp-echo-client`) that performs SYN/SYN-ACK/ACK, sends data, receives the echo,
  and closes with FIN. This is a simplified TCP (no retransmission/windowing).
- ACLs: `Router` supports ordered inbound/outbound rules (`acl <router> in|out
  allow|deny <src/p> <dst/p> <any|icmp|tcp|udp>`), evaluated per packet; denied
  packets are dropped and counted.
- UX: `help <command>` prints detailed usage.
- Tests: `tests/tcp.txt`, `tests/acl.txt`, CLI `command-help` check, and unit tests
  for `TcpSegment`, TCP echo end-to-end, and ACL deny (167 checks).
- Docs: README/user guide/man/CHANGELOG updated.
- Remaining roadmap: DHCP/DNS, NAT, dynamic routing (RIP/OSPF-lite), IPv4
  fragmentation, IPv6, full RSTP, `--jobs` parallel scenarios, and the `src/`
  restructure + CMake presets.

## Phase 44 — Retract the "TCP" claim, add impairment and TCP wire groundwork (2026-11-22)

- The simplified transport is now explicitly `tcp-lite` (commands, output, docs)
  and is **not** advertised as TCP. Calling it TCP was misleading; a reliability-
  focused product must not do that.
- Link impairment: `set-link <dev:idx> loss|dup|jitter|clear ...` with a per-link
  deterministic RNG; `tests/loss.txt` (100% loss → ping timeout) and
  `tests/impair_clear.txt` (restore → ping succeeds).
- TCP wire groundwork: `TcpSegment` now carries options and computes/verifies the
  real ones-complement checksum over the IPv4 pseudo-header
  (`ToBytes(src,dst)`, `TryFromBytes(...,src,dst)`).
- Tests: `tests/tcp_lite.txt`; checksum/options unit tests; loss/impair scenarios.
- Next: a real RFC 9293 TCP stack (state machine, retransmission, flow/congestion
  control, options) built internally and exposed only after it passes loss/reorder
  tests; then DHCP/DNS, NAT, dynamic routing, IPv6, full RSTP, and scale/engineering.

## Phase 45 — Real TCP core (internal) (2026-11-22)

- Added `netstack/TcpConnection`: state machine (Closed/Listening/SYN-SENT/
  SYN-RCVD/ESTABLISHED/FIN-WAIT-1/2/CLOSE-WAIT/CLOSING/LAST-ACK/TIME-WAIT) with
  sequence/ack handling, send/receive, out-of-order reassembly, RTO timer with
  exponential backoff and retransmission, and FIN/TIME_WAIT.
- Deliberately **not exposed** in the CLI: `tcp-lite` remains the only user-facing
  transport (clearly experimental, not TCP) until the core passes more tests.
- Tests: two `TcpConnection`s driven over a simulated wire under `Engine` —
  handshake, data transfer, graceful close, and loss-driven retransmission
  (`totalRetransmits > 0`); 175 unit checks. Coverage now includes `netstack`
  (54.7%, floor 54).
- Next: options (MSS/window scale/SACK), congestion control (slow start/CA/fast
  retransmit), zero-window probes, keepalive, then expose `tcp-*` after loss/reorder
  tests; then DHCP/DNS, NAT, dynamic routing, IPv6, full RSTP, scale/engineering.

## Phase 46 — Real TCP exposed in the CLI (2026-11-23)

- Wired `netstack/TcpConnection` into `EndDevice`: hosts now own a deque of TCP
  connections. `HandleIp` tries `HandleTcpStack` first (real TCP) and falls back
  to the deprecated `tcp-lite` path only when no TCP connection/listener matches.
- New commands: `tcp-listen <device> on|off [port]` (real TCP echo service) and
  `tcp-connect <device> <ip> <port> [text...]` (client; sends text after the
  handshake and prints `tcp reply from <ip>:<port> "<text>"`).
- Outgoing segments go through the normal IPv4 path: routing, next-hop ARP with
  pending queue, then Ethernet. Works over a single link and through routers.
- Connection setup uses per-host ephemeral ports (`nextTcpLocalPort`, starting at
  40000); server connections bind the listening port and learn the peer from SYN.
- Tests: three new scenarios — `tcp.txt` (direct link), `tcp_router.txt` (host →
  router → host), `tcp_loss.txt` (30% loss drives retransmission). All 28 `.txt`
  scenarios, 3 Lua scenarios, 12 CLI checks, and 9 examples pass; 175 unit checks.
- `tcp-lite-*` remains available (and deprecated) as a legacy/contrast transport.
- Next: TCP refinements (MSS/WS/SACK, zero-window probes, keepalive), then
  DHCP/DNS, NAT, dynamic routing, IPv6, full RSTP, scale/engineering.

## Phase 47 — DHCP and DNS (2026-11-23)

- Added `core/DhcpMessage` (BOOTP/DHCP subset): fixed header, magic cookie, and
  options 53/54/50/51/1/3/6 with strict bounds checking.
- Added `core/DnsMessage`: header, uncompressed name encoding, compression-pointer
  decoding, A questions/answers, and NXDOMAIN support.
- `EndDevice` now runs a DHCP server (pool scan, per-MAC lease reuse, broadcast
  OFFER/ACK, DNS option) and a DHCP client (DISCOVER/OFFER/REQUEST/ACK, then
  applies IP/prefix, gateway and DNS). UDP is intercepted for ports 67/68 before
  the destination-IP check so a host without an address can bootstrap.
- DNS: `dns-server` enables A-record answers from a case-insensitive table;
  `dns-query` resolves via an explicit server or the DHCP-provided DNS server.
- Commands: `dhcp-server`, `dhcp-client`, `dns-server`, `dns-record`, `dns-query`
  (help, usage and Tab completion updated).
- Tests: new scenarios `dhcp.txt`, `dhcp_dns.txt`, `dns.txt`, `dns_nx.txt`
  (32 `.txt` total); DHCP/DNS codec unit tests raise the unit count to **206**.
- Next: NAT, dynamic routing (RIP/OSPF-lite), IPv6, full RSTP, scale/engineering.

## Phase 48 — Router NAT (2026-11-23)

- Added source NAT/PAT to `Router`: an inside/outside port pair; outbound TCP,
  UDP and ICMP echo traffic is rewritten to the outside address with a unique
  translated port/id, and return traffic is translated back.
- TCP payloads are decoded and re-encoded so the pseudo-header checksum stays
  valid after address/port edits; UDP uses its zero-checksum encoding; ICMP echo
  ids are remapped and restored.
- Inbound port forwarding (`nat-port`) performs DNAT to an inside host and
  creates the reverse mapping, so the outside client sees replies from the
  public address/port. Translation table is capped (`kMaxNat`).
- Commands: `nat <router> on <inside-dev:idx> <outside-dev:idx> | off`,
  `nat-port <router> tcp|udp <public-port> <inside-ip> <inside-port>`, and
  `nat-table <router>` (mappings and forwards); help/completion updated.
- Tests: `nat_tcp`, `nat_udp`, `nat_ping`, `nat_forward`, `nat_table` scenarios
  (37 `.txt` total); coverage 55.6%. Example `11_nat.txt`.
- Next: dynamic routing (RIP/OSPF-lite), IPv6, full RSTP, scale/engineering.

## Phase 49 — RIP v2-lite dynamic routing (2026-11-23)

- Added `core/RipMessage` (command/version header plus 20-byte IPv4/mask/metric
  entries) with strict size and version validation; metrics beyond 16 clamp to
  infinity.
- `Router` runs RIP on UDP 520 over link-local Ethernet/IP broadcast (TTL 1),
  intercepted before normal forwarding so broadcasts never transit the router.
  Updates are sent every 30 time units and immediately when RIP is enabled.
- Learned routes are stored in the route table with `metric`, `dynamic`,
  `learnedFromPort` and `expiresAt`; split horizon skips routes on the source
  port, and dynamic routes expire after 180 units.
- Route selection now breaks equal-prefix ties by metric, so connected/static
  routes (metric 0) win over learned ones.
- Commands: `rip <router> on|off` and `rip-status <router>` (connected, static
  and learned routes with next hop and metric); help/completion updated.
- Tests: `rip.txt` (ping across two routers after convergence) and
  `rip_status.txt` (learned 192.168.2.0/24 via 10.0.0.2 metric 2); RIP codec
  unit tests bring the unit count to **218**; 39 scenarios. Coverage 55.3%.
  Example `12_rip.txt`.
- Next: OSPF-lite, IPv6, full RSTP, scale/engineering.

## Phase 50 — Real OSPFv2 single-area core (2026-11-23)

- Removed the experimental "OSPF-lite" implementation (UDP 89 hop flooding) and
  its commands/tests; it was not RFC 2328 and is no longer exposed as OSPF.
- Added `core/OspfPacket`: RFC 2328 packet header (version/type/length, router
  and area IDs, checksum, authentication), Hello, Database Description, Link
  State Request/Update/Ack, Router-LSA and Network-LSA codecs, packet checksum
  and Fletcher LSA checksum, with strict length/field validation.
- Tests: 31 new checks (266 unit checks total) covering all packet types, LSA
  round-trips, checksum failure detection, malformed lengths and simple-password
  authentication fields.
- Next: per-interface state, Hello timers, neighbor FSM, DR/BDR election, LSDB
  aging/sequence, DD/LSR/LSU exchange, SPF, and the `ospf`/`ospf-status` CLI.
- Step 2: real adjacency path implemented: IP protocol 89 with AllSPFRouters
  multicast (224.0.0.5 / 01:00:5e:00:00:05), Hello timers 10/40, neighbor
  Init/2-Way states, dead-neighbor expiry, and DR/BDR election with a Wait
  timer. `ospf`/`ospf-status` now expose interfaces, DR/BDR and neighbors.
- Tests: `ospf_hello` and `ospf_dr` scenarios confirm 2-Way adjacency and
  BDR/DR assignment; unit count remains 266.
- Step 3: DD/LSR/LSU/LSAck exchange, Router-LSA and Network-LSA origination and
  flooding, LSDB keyed by (type, LS ID, advertising router), and Dijkstra SPF
  with next-hop resolution and route installation. DD uses a compact two-phase
  exchange; LSA sequence numbers only advance on topology change.
- Tests: `ospf` (three-router chain ping), `ospf_full`, `ospf_status`
  (`192.168.3.0/24 via 10.0.0.2 metric 3`) plus `ospf_hello`/`ospf_dr`.
- Added LSDB aging: ages advance every Hello tick, self-originated LSAs refresh
  at 1800s, other LSAs are removed at MaxAge, and same-sequence lower-age LSAs
  refresh peers. Added `ospf-auth <router> none|simple <password>` and an
  auth scenario.
- Windows-first verification: added `tests/run_tests.ps1`, made pcap/save
  scenarios use relative paths, and ran every scenario, Lua test, and example
  against `netsim.exe` in PowerShell (all pass).
- Remaining before calling OSPF complete: multi-area/ABR, LSA types 3-5, MD5
  authentication, and DD/LSU retransmission.
- Next: those OSPF gaps, then IPv6 and full RSTP.

## Phase 51 — Centralized build artifacts (2026-11-23)

- POSIX build now writes all objects and dependency files under
  `build/obj/<layer>/` instead of next to sources; Lua objects/archive remain
  under `build/lua/` and `build/liblua.a`.
- `make clean` removes `build/` and also sweeps any legacy `*.o`/`*.d` left in
  source or `third_party/` directories.
- `Makefile.win` now writes Lua objects to `build/win/lua/` and the resource to
  `build/win/yanas_res.o`; `clean` removes those and any legacy copies.
- `tests/coverage.sh` links and runs gcov against `build/obj/*`, and builds with
  `-j` (default 4) so coverage builds finish reliably on `/mnt/c`.
- Verified: POSIX and MinGW builds leave no `.o`/`.d` outside `build/`;
  coverage passes at 54.9% (threshold 54%); unit and scenario suites pass.

## Phase 52 — TCP/OSPF hardening and Go stress tooling (2026-11-23)

- TCP: SYN/SYN-ACK now carry MSS and window-scale options; MSS is negotiated
  (clamped 536..1460) and send/receive windows are scaled after the handshake.
- TCP reliability: SRTT/RTTVAR RTO estimation (clamped 20..500, Karn rule),
  retransmission of the oldest unacked segment instead of only the last one,
  RST abort handling, partial-ACK trimming, and basic zero-window probes.
- TCP SACK: SACK-permitted in SYN, receiver SACK blocks (up to 3 coalesced
  ranges) on out-of-order/duplicate ACKs, and sender selection of the first
  unsacked hole at the third duplicate ACK.
- TCP lifecycle: unmatched TCP segments now receive an RST (preserving the
  deprecated tcp-lite fallback), clients report resets, and closed connection
  slots are pruned before new connections are created.
- TCP keepalive: optional per-host (`tcp-keepalive`), 300/75/3 idle/interval/
  probe defaults, probe ACK handling, activity tracking, and timeout abort with
  a client/server notification. New `tcp_keepalive` scenario.
- TCP edge cases: zero-window updates are applied even without ACK progress,
  window reopening resumes transmission, persist probes keep retrying, and
  simultaneous open/close transition correctly (unit coverage added).
- TCP operational hardening: per-host 256-connection cap with RST refusal,
  dropped/reset/accepted counters, and `tcp-status` showing state, RTO, cwnd,
  window, unacked bytes and retransmissions. New `tcp_status` scenario.
- TCP timestamps (RFC 7323-style): SYN/ACK negotiation, TSecr echo,
  timestamp-based RTT sampling, deterministic per-endpoint ISN generation, and
  receive-window validation for RST acceptance.
- TCP flow behavior: delayed ACK (second in-order segment or a 2-tick timer,
  immediate for out-of-order/control) and Nagle (small writes wait for an ACK
  while data is outstanding).
- TCP SACK recovery/DSACK: recovery point, one retransmission per detected hole,
  cwnd inflation during recovery, exit on full ACK, and receiver DSACK blocks
  with sender DSACK counters exposed by `tcp-status`.
- TCP SYN backlog/cookies: per-listener backlog (`tcp-backlog`), stateless
  cookie SYN-ACK when half-open space is full, cookie validation with a
  time-bucket secret, and accepted/sent cookie counters. New `tcp_backlog`
  scenario exercises two simultaneous clients with backlog 1.
- Build workflow: `make test`/runners no longer clean `build/`; coverage builds
  in `build/cov/` and leaves the normal build intact.
- OSPF: added per-neighbor LSA retransmission queues cleared by LSAck, DD/LSR
  retransmission timers, and Full-state DD recovery so a lost final DD no longer
  deadlocks the exchange. New `ospf_loss` scenario converges under 30% loss.
- Tooling: added `tools/ynstress` (Go) to run all scenarios in parallel and
  repeat them, checking `.want` output and timing. Go is used only for tooling;
  the simulator hot path stays C++17.
- Tests: 304 unit checks (TCP MSS/WS/SACK/DSACK/timestamps/delayed-ACK/Nagle/
  recovery), 51 scenarios including `ospf_loss`, `tcp_reset`, `tcp_keepalive`,
  `tcp_status` and `tcp_backlog`; PowerShell runner and Go stress run
  (`-repeat 3`) pass; coverage 58.4% (floor 54%).
- Scope discipline: no speculative configuration or proto-feature is added;
  every change must alter observable behaviour and come with a unit or scenario
  test. Go stays in tooling; the deterministic hot path remains C++17.

## Phase 53 — Modular Go tooling and PCAP conformance (2026-11-24)

- Go tools are split into `cmd/` entry points and `internal/` packages:
  `ynstress` (scenario discovery, parallel runner) and `ynpcap` (pcap reader,
  Ethernet/VLAN, IPv4, TCP, OSPF decoders, conformance checks). `make gotest`
  runs their Go tests.
- Added `ynpcap`: validates IPv4/TCP/OSPF checksums, TCP handshake flow and SYN
  options (MSS/WS/SACK/timestamps), OSPF version/type/checksum and LSA checksums;
  exits non-zero on issues.
- IPv4 header checksum is now generated and verified; NAT and forwarding
  recompute it through `IpPacket::ToBytes`.
- Integration check: a 218-frame capture containing OSPF and TCP reported
  `tcp_segments=14 tcp_flows=1 ospf=192 ospf_lsas=10`, all four SYN options
  present, and `issues=0`.
- Tests: 305 unit checks, 51 scenarios, Go `go test ./...` for both tools,
  PowerShell runner and Go stress pass; coverage last measured 58.4%.

## Phase 54 — Live bridge experiment (archived) (2026-11-24)

- Archived to `legacy/live-bridge/`; it is not built, packaged, or part of the
  offline product. The active simulator no longer exposes `--live` or
  `Port::bridge`.
- Original experiment: added `Port::bridge` and `netsim --live` with
  length-prefixed frames, wall-clock stepping, and a modular Go `ynbridge`
  (frame/netsim/bridge/tap) for Linux TAP.
- Real-stack verification (archived): a root TAP run assigned `10.0.0.254/24`,
  pinged the simulated host `10.0.0.1`, completed a 64 KiB Linux TCP echo,
  opened 8 concurrent connections, and confirmed a closed port returns RST;
  `legacy/live-bridge/live_tap.sh` preserves the test.
- Archived `ynbridge` supports bridge impairment (`-loss`, `-dup`, `-seed`) and
  signal shutdown; these are not part of the shipped offline build.
- Tests: 307 unit checks, 51 scenarios, Go tests for active tools, PowerShell
  and Go stress pass; coverage 58.4%.

## Phase 55 — OSPF MD5 authentication (2026-11-24)

- Added `core/Md5` (RFC 1321) with known-vector tests.
- OSPF packets support AuthType 2: checksum is zero, the 64-bit auth field
  carries Key ID/Auth Data Len/sequence, and a 16-byte MD5 digest (over the OSPF
  packet plus the 16-byte key) is appended after the OSPF length.
- Router authentication uses a per-router key ID, 16-byte key and monotonic
  crypto sequence; received MD5 packets verify the digest and reject replayed
  or older sequence numbers per neighbor.
- CLI: `ospf-auth <router> md5 <key-id> <16-byte-key>` (help/completion updated).
- `ynpcap` understands OSPF MD5 packets (auth field, digest presence) and no
  longer flags AuthType 2 as unsupported.
- Tests: `ospf_md5` scenario reaches Full; MD5/OSPF unit vectors; 319 unit
  checks, 52 scenarios; an MD5 OSPF PCAP verifies with `ynpcap -ospf-key`
  (bad key reported), 30 frames/5 LSAs/0 issues; coverage 58.1%.

## Phase 56 — OSPF interface policy and TCP PAWS (2026-11-24)

- OSPF interfaces carry a cost; Router-LSA transit/stub metrics use it, so SPF
  paths and `ospf-status` metrics reflect the configured cost.
- `ospf-cost <router> <dev:idx> <1-65535>` changes an interface cost.
- `ospf-passive <router> <dev:idx> on|off` suppresses Hellos, drops OSPF input on
  the interface and advertises the connected subnet as a stub. Both commands
  persist across OSPF re-enable and update existing interfaces.
- TCP PAWS: segments whose timestamp is older than the recent peer timestamp are
  dropped (RST exempt), preventing stale timestamp replay.
- Tests: `ospf_cost` (route metric 7), `ospf_passive` (`passive=on`, no
  adjacency); 324 unit checks, 54 scenarios; PowerShell and Go stress pass.

## Phase 57 — OSPF multi-area and ABR summaries (2026-11-24)

- OSPF interfaces carry an area (`ospf-area`); Hello/DD/LSR/LSU validate and use
  that area, and flooding is restricted to the matching area.
- LSDB is per-area (`area -> (type, LS ID, adv router)`), with per-area
  Router/Network LSAs and per-area aging; Router-LSAs only include links in
  their area.
- SPF runs per area. ABRs derive reachable networks per area, originate Type 3
  summary LSAs into other areas (backbone rule enforced when area 0 exists),
  and install summary routes via the advertising ABR.
- New `ospf_multiarea` scenario: area 1 -> area 0 -> area 2 with three routers;
  PC1 pings PC2 across areas, and R1 reports the remote route.
- Tests: 328 unit checks, 55 scenarios; PowerShell and Go stress pass;
  coverage 59.1%.

## Phase 58 — OSPF module split and area isolation (2026-11-24)

- Split all OSPF implementation out of `device/Router.cpp` into
  `device/RouterOspf.cpp` (same `Router` class; no API change). Router.cpp keeps
  Layer-3 forwarding/NAT/RIP; OSPF HELLO/DD/LSR/LSU/LSAck, LSDB, SPF, ABR and
  summaries now live in one focused translation unit.
- `ospf-status` adds `neighbors=N`; `ospf_area_isolation` verifies that routers
  on the same link but different areas never form adjacency (`neighbors=0`).
- Tests: 328 unit checks, 56 scenarios; PowerShell and Go stress pass;
  coverage 57.9%.

## Phase 59 — TCP final hardening (2026-11-24)

- `tcp-keepalive` accepts optional `idle/interval/count` parameters; defaults
  remain 300/75/3 and apply to existing and future connections.
- DSACK now undoes a spurious recovery (`cwnd` restored, recovery cleared)
  instead of only counting the event.
- RST acceptance is window-validated; unit coverage checks that an out-of-window
  RST is ignored and an in-window RST closes the connection.
- Tests: 331 unit checks, 56 scenarios; PowerShell and Go stress pass;
  coverage 57.8%.

## Phase 60 — OSPF Type 5 external routes (2026-11-24)

- Added Type 4/5 LSA codecs (ASBR summary metric, external mask/forwarding/
  metric) with checksum coverage.
- ASBR-style `ospf-external <router> <ip/prefix> [metric]` creates Type 5 LSAs;
  they are flooded domain-wide (all areas) and stored in a separate external
  LSDB with the advertising next hop/interface.
- DD/LSR/LSU/LSAck exchange carries external LSAs; external routes are installed
  after intra-area routes, with external routes never overriding intra-area or
  direct routes.
- `ospf-status` reports the external LSA count. New `ospf_external` scenario
  (R1 learns 172.16.0.0/16 via R2, metric 20).
- Tests: 331 unit checks, 57 scenarios; PowerShell and Go stress pass;
  coverage 58.1%.

## Phase 61 — OSPF Type 4 ASBR summaries (2026-11-24)

- Added Type 4 summary ASBR LSA generation on ABRs and installation of ASBR
  reachability per area (`ospfAsbrReach`).
- External Type 5 routes now require ASBR reachability from Router-LSA/Type 4
  rather than the immediate flooding source; next hop comes from the SPF path.
- New `ospf_external_area` scenario: ASBR in area 0, area-only router in area 1
  learns `172.16.0.0/16` via the ABR (`10.1.0.1`, metric 20).
- Tests: 331 unit checks, 58 scenarios; PowerShell and Go stress pass;
  coverage 58.5%.

## Phase 62 — OSPF stub areas (2026-11-24)

- Added `ospf-area-type <router> <area-id> stub|normal`; stub status is per area
  and persists across OSPF re-enable.
- Stub behavior: Type 5 external LSAs are not flooded into or accepted from the
  area; DD headers omit them; area-only routers do not install external routes.
- The ABR advertises a default Type 3 summary (`0.0.0.0/0`) into the stub area;
  `ospf_stub` verifies the area-only router installs the default via the ABR with
  no external LSAs.
- Tests: 331 unit checks, 59 scenarios; PowerShell and Go stress pass;
  coverage 58.5%.

## Phase 63 — OSPF Type 4/5 codec coverage (2026-11-24)

- Added unit round-trips for Summary-ASBR (Type 4) and External (Type 5) LSAs,
  including mask, forwarding address, metric and external-type bit. Coverage
  is 58.5%; unit count 340, scenarios 59.

## Phase 64 — OSPF summary/external withdrawal (2026-11-24)

- Own Type 3 and Type 4 summaries now track desired keys per area and flush
  stale LSAs with MaxAge when networks/ASBR reachability disappear.
- `ospf-external <router> clear` withdraws all configured external routes;
  Type 5 LSAs are flushed domain-wide, peers age them out, and
  `ospf-status` reports `extroutes=0`.
- `ospf_external_clear` scenario validates withdrawal end to end.
- Tests: 340 unit checks, 60 scenarios; PowerShell and Go stress pass;
  coverage 58.9%.

## Phase 65 — OSPF SHA-1/SHA-256 authentication (2026-11-24)

- Added self-contained SHA-1 and SHA-256 plus the RFC 5709 HMAC construction
  (normalized key, Apad trailer, inner/outer hashes), with known-vector tests.
- OSPF crypto authentication is now algorithm-aware: MD5 (16-byte digest),
  SHA-1 (20), SHA-256 (32); AuthType remains the RFC cryptographic value 2 and
  the auth data length identifies the digest size.
- CLI: `ospf-auth <router> md5|sha1|sha256 <key-id> <key>`; MD5 requires a
  16-byte key, SHA keys are 1..64 bytes.
- New `ospf_sha256` scenario reaches Full with matching SHA-256 keys; ynpcap
  understands 16/20/32-byte crypto trailers (MD5 verification when `-ospf-key`
  and a 16-byte digest are present).
- Tests: 352 unit checks, 61 scenarios; PowerShell and Go tests pass;
  coverage 58.6%.

## Phase 66 — OSPF NSSA (2026-11-24)

- `ospf-area-type ... nssa` marks an NSSA; Type 5 LSAs are suppressed in/out of
  the area like stub, while Type 7 external LSAs are allowed.
- NSSA ASBRs without a normal-area interface originate Type 7 only; ABRs with a
  normal interface translate Type 7 LSAs (P-bit set) to Type 5 for the rest of
  the domain. NSSA ABRs also inject a default Type 3 summary.
- Type 7 LSA codec added (mask/forwarding/metric) and routes installed inside the
  NSSA via ASBR reachability.
- New `ospf_nssa` and `ospf_nssa_translate` scenarios verify Type 7 inside the
  NSSA and translated Type 5 outside.
- Tests: 357 unit checks, 63 scenarios; PowerShell and Go stress pass;
  coverage 58.8%.

## Phase 67 — NSSA withdrawal and CI industrialization (2026-11-24)

- Type 7 external LSAs now withdraw when `ospf-external ... clear` is used:
  stale Type 7s are flushed in the NSSA and translated Type 5s are withdrawn
  from the domain. `ospf_nssa_clear` verifies `extroutes=0`.
- CI: Go tests added to the Linux/macOS/Windows jobs; Windows now runs the
  PowerShell scenario suite. `make check` now includes `gotest` before coverage,
  soak, and perf.
- Verified `make check`: unit/fuzz/scenarios, Go tests, coverage 58.8%, soak,
  and 8.7M events/s perf floor; build artifacts preserved.
- Tests: 357 unit checks, 64 scenarios.

## Phase 68 — DHCP relay and DNS CNAME (2026-11-24)

- Added `dhcp-relay <router> <dev:idx> <server-ip>|off`: client broadcasts are
  rewritten with `giaddr`/hops and unicast to the server; server replies to the
  relay address are forwarded as UDP 67→68 broadcasts on the client-facing port.
- DHCP server replies to a relay use unicast to `giaddr`; direct clients keep
  broadcast behavior.
- DNS: multiple A records per name, CNAME chains (CNAME + resolved A answers),
  and `dns-cname <device> <alias> <target>`. DNS answer codec supports A and
  CNAME RDATA.
- New `dhcp_relay` and `dns_cname` scenarios. Tests: 361 unit checks, 66
  scenarios; PowerShell and Go tests pass; coverage 57.0%.

---

## Phase 69 — DHCP lease lifecycle (2026-11-24)

- Clients parse the lease option, renew at 50% (unicast DHCPREQUEST with
  `ciaddr`), rebind at 87.5% (broadcast), and drop the address at expiry.
- Server ACKs renewals to `ciaddr`; relayed replies still use `giaddr`.
- New `dhcp_renew` and `dhcp_expire` scenarios; scenario runners and ynstress
  now run with `-q` and normalize CRLF for multi-line `.want` files.
- Tests: 361 unit checks, 68 scenarios; PowerShell and Go tests pass;
  coverage 57.2%.

---

## Phase 70 — DHCP server lease database (2026-11-24)

- Server leases now carry an expiry and are reclaimed lazily on Discover/Request;
  offers hold for 60s and ACKs install the configured lease.
- Added `dhcp-lease-time <device> <seconds>` (1..604800) and
  `dhcp-release <device>` (broadcast DHCPRELEASE, relay-compatible).
- Unknown or expired DHCPREQUESTs receive NAK instead of being silently dropped.
- New `dhcp_release` and `dhcp_reclaim` scenarios (release and expiry reclaim
  of a single-address pool).
- Tests: 361 unit checks, 70 scenarios; PowerShell and Go tests pass;
  coverage 57.3%; `make check` green with build artifacts preserved.

---

## Phase 71 — DNS TTL and client cache (2026-11-24)

- DNS server answers now use a configurable TTL (`dns-ttl`, 0..86400s).
- Clients cache positive A results (including CNAME-resolved names) until the
  minimum answer TTL; cache hits print `dns: cached <name> -> <ip>` and avoid
  network traffic. Expired entries are dropped lazily on lookup.
- Added `wait [duration]` for deterministic clock advancement during idle
  scenario periods; wired into help/autocomplete.
- New `dns_cache` scenario covers cache hit, TTL still valid, and expiry.
- Tests: 361 unit checks, 71 scenarios; PowerShell and Go tests pass;
  coverage 57.5%; `make check` green with build artifacts preserved.

---

## Phase 72 — DNS PTR/MX and typed cache (2026-11-24)

- Added PTR answers derived from A records through an `unordered_map`
  reverse index (O(1) average per lookup); MX records via `dns-mx`.
- `dns-query` accepts an optional qtype (`A|PTR|MX`, or 1/12/15) and the cache
  is keyed by (name, qtype), so A/PTR/MX responses coexist without collisions.
- DNS codec encodes/decodes PTR (name RDATA) and MX (preference + exchange).
- New `dns_ptr` and `dns_mx` scenarios; `dns_mx` also covers typed cache hits.
- Unit tests: PTR/MX round-trip and TTL/preference checks (371 checks total).
- Tests: 371 unit checks, 73 scenarios; PowerShell and Go tests pass;
  coverage 58.3%; `make check` green with build artifacts preserved.

---

## Phase 73 — DNS negative caching (2026-11-24)

- DNS codec now round-trips authority records and SOA RDATA (mname/rname,
  serial/refresh/retry/expire/minimum), with a shared record decoder.
- NXDOMAIN replies include an SOA authority record; the TTL and MINIMUM use
  `dns-negative-ttl` (0 disables negative caching).
- Clients cache NXDOMAIN per (name, qtype) for `min(SOA TTL, MINIMUM)` and
  print `dns: cached <name> -> NXDOMAIN` on hits; positive responses clear any
  stale negative entry.
- New `dns_negative_cache` scenario covers hit and expiry; SOA round-trip unit
  checks added (378 checks total).
- Tests: 378 unit checks, 74 scenarios; PowerShell and Go tests pass;
  coverage 58.4%; `make check` green with build artifacts preserved.

---

## Phase 74 — DNS resolver reliability (2026-11-24)

- Clients keep a resolver list (`dns-resolver`, DHCP installs one), retry each
  server according to `dns-retry <timeout> <attempts>`, then fail over to the
  next server. Exhaustion reports `dns: <name> -> timeout`.
- Responses are accepted only from the current server, with matching ID, port,
  question name and qtype; stale/forged responses cannot satisfy a query.
- NODATA is distinguished from NXDOMAIN, printed explicitly, and cached with
  the same SOA-derived negative TTL in a typed negative-cache entry.
- New `dns_failover`, `dns_timeout` and `dns_nodata` scenarios.
- Engine events support cancellation: cancelled timers are dropped without
  advancing the logical clock; a unit test covers the behavior.
- Documentation repositioned from introductory wording to operator and
  engineering terminology.
- Tests: 381 unit checks, 77 scenarios; PowerShell and Go tests pass;
  coverage 58.2%; `make check` green with build artifacts preserved.

---

## Phase 75 — DNS EDNS0, truncation and TCP fallback (2026-11-24)

- DNS messages carry an OPT pseudo-record (EDNS0) with a 1232-byte client UDP
  advertisement; the codec round-trips OPT class/version/flags.
- UDP server truncates responses above the advertised/512-byte limit, sets TC,
  and retains the question (and OPT) for retry. TCP responses are never truncated.
- Clients automatically fall back to DNS-over-TCP on TC, using the real TCP stack;
  the server listens on TCP port 53 alongside UDP 53 and frames messages with
  the standard 2-byte length prefix.
- TCP exchanges use `appRx` stream buffering, validate the response ID/question,
  close after the response, and have an application watchdog.
- New `dns_tcp` scenario: 60 A records force UDP truncation, then TCP returns the
  complete RRset.
- Tests: 384 unit checks, 78 scenarios; PowerShell and Go tests pass;
  coverage 58.1%; `make check` green with build artifacts preserved.

---

## Phase 76 — DNS zones, SOA/NS and delegation (2026-11-24)

- Authoritative zones are declared with `dns-zone`; SOA and NS records are
  configurable (`dns-soa`, `dns-ns`) and queries accept `NS`/`SOA` types.
- Servers in zoned mode answer only within their zones, return NODATA vs
  NXDOMAIN with the zone SOA, and emit referrals for delegated subzones.
- Referrals carry NS authority records and A glue in the additional section;
  clients follow glue up to eight levels and print the referral hop.
- Flat record mode remains the default when no zones are declared, preserving
  existing scenes.
- DNS codec now round-trips NS records and general additional-section records.
- New `dns_zone` scenario covers apex NS/SOA, delegation and glue-based
  resolution through a child authoritative server.
- Tests: 390 unit checks, 79 scenarios; PowerShell and Go tests pass;
  coverage 58.1%; `make check` green with build artifacts preserved.

---

## Phase 77 — DNS wildcards (2026-11-24)

- Wildcard owners (`*.zone`) resolve A, CNAME and MX records for names without
  an exact node; the longest matching wildcard ancestor wins and exact names
  always take precedence.
- Answers use the queried owner name; wildcard CNAMEs are followed to the target.
- Wildcards are zone-scoped in zoned mode and also work in flat mode. Missing
  types under an existing wildcard return NODATA (not NXDOMAIN).
- New `dns_wildcard` scenario covers wildcard A, exact-name precedence, wildcard
  CNAME and wildcard MX, plus NODATA for an absent type.
- Tests: 390 unit checks, 80 scenarios; PowerShell and Go tests pass;
  coverage 58.3%; `make check` green with build artifacts preserved.

---

## Phase 78 — DNS delegation without glue (2026-11-24)

- Referral glue is now limited to in-bailiwick nameserver addresses; an
  out-of-bailiwick NS target is returned without glue.
- Clients resolve a glue-less NS hostname through an internal A query (no user
  output/cache pollution), then restart the original query at the resolved
  address. Loop depth stays bounded and failure reports the original name.
- Added `dns_noglue` scenario with parent/child zones and an out-of-bailiwick NS.
- Tests: 390 unit checks, 81 scenarios; PowerShell and Go tests pass;
  coverage 58.4%; `make check` green with build artifacts preserved.

---

## Phase 79 — DNS cache bounds and TTL clamps (2026-11-24)

- Replaced separate positive/negative maps with one cache using an
  `unordered_map` + intrusive LRU list: O(1) lookup, touch and eviction.
- Positive and negative (NXDOMAIN/NODATA) entries share a configurable capacity
  (`dns-cache-size`, 1..65536); expired entries are removed lazily and capacity
  changes evict from the LRU tail immediately.
- Added TTL clamps (`dns-ttl-bounds <min> <max>`) applied to positive and
  SOA-derived negative TTLs; TTL 0 still disables caching.
- New `dns_cache_lru` and `dns_ttl_bounds` scenarios; tests: 390 unit checks,
  83 scenarios; PowerShell and Go tests pass; coverage 58.5%; `make check`
  green with build artifacts preserved.

---

## Phase 80 — DNS AXFR zone transfer (2026-11-24)

- Added AXFR (type 252) authoritative export over TCP: SOA, apex NS, A, CNAME,
  MX and delegated NS records, bracketed by opening/closing SOA.
- UDP AXFR requests are REFUSED; TCP requests use the existing DNS listener and
  length-prefixed stream framing.
- Clients use `dns-axfr <device> <server-ip> <zone>` and print each transferred
  record plus begin/complete markers; transfers stop at the second SOA.
- New `dns_axfr` scenario covers a complete zone export.
- Tests: 390 unit checks, 84 scenarios; PowerShell and Go tests pass;
  coverage 58.7%; `make check` green with build artifacts preserved.

---

## Phase 81 — AXFR source ACL (2026-11-24)

- AXFR is denied by default; `dns-axfr-allow <device> <ip>...` permits specific
  client addresses, `any` allows all and `none` clears the allow list.
- Unauthorized AXFR requests receive REFUSED over TCP; the client reports failure.
- New `dns_axfr_acl` scenario verifies denied and allowed transfers; the existing
  transfer scenario opts in with `any`.
- Tests: 390 unit checks, 85 scenarios; PowerShell and Go tests pass;
  coverage 58.8%; `make check` green with build artifacts preserved.

---

## Phase 82 — TSIG-authenticated AXFR (2026-11-24)

- Added reusable HMAC-MD5/SHA-1/SHA-256 and TSIG RR encode/decode, signing and
  constant-time verification, including request-MAC chaining for responses.
- AXFR requests are signed when a client key is configured; servers verify key,
  algorithm, original ID and time fudge, optionally require TSIG, and sign each
  response/transfer chunk.
- Added `dns-tsig <device> <key> <secret> [md5|sha1|sha256]` and
  `dns-tsig-require <device> on|off`; bad/unsigned transfers fail.
- New `dns_tsig` scenario covers unsigned, bad-secret and valid transfers.
- Tests: 398 unit checks, 86 scenarios; PowerShell and Go tests pass;
  coverage 57.9%; `make check` green with build artifacts preserved.

---

## Phase 83 — DNS dynamic UPDATE (2026-11-24)

- Added RFC 2136 opcode UPDATE over UDP and TCP, including zone section,
  prerequisite section and update section encoding (`noRdata` RRset deletes).
- Authoritative zones support A/CNAME/MX additions, RRset/type deletes and
  all-record deletes with in-zone validation; prerequisites cover exists/not
  exists and RRset presence.
- Updates are denied by default; `dns-update-allow` provides per-zone source
  ACLs. TSIG signing/verification is reused, with required-TSIG enforcement.
- Added `dns-update-add` and `dns-update-del` client commands with response
  diagnostics (`ok`, `refused`, `notauth`, `formerr`, `prereq`, etc.).
- New `dns_update` and `dns_update_auth` scenarios; tests: 403 unit checks,
  88 scenarios; PowerShell and Go tests pass; coverage 57.8%; `make check`
  green with build artifacts preserved.

---

## Phase 84 — Per-RRset DNS TTLs (2026-11-24)

- Authoritative records now carry per-(name,type) TTLs for A/CNAME/MX/NS;
  static `dns-record`/`dns-cname`/`dns-mx` accept an optional TTL.
- UPDATE additions install the supplied TTL and deletes remove the RRset TTL;
  queries, CNAME chains, wildcard answers, glue and AXFR all use stored TTLs.
- New `dns_update_ttl` scenario proves an update TTL overrides the zone default:
  a 100s dynamic record expires while the zone TTL is 300s.
- Tests: 403 unit checks, 89 scenarios; PowerShell and Go tests pass;
  coverage 58.0%; `make check` green with build artifacts preserved.

---

## Phase 85 — Value-dependent UPDATE prerequisites (2026-11-24)

- Prerequisite processing now supports class IN value-dependent checks for A,
  CNAME and MX: the RRset must exist and contain the exact RDATA; TTL must be 0.
- Missing names return NXDOMAIN; missing RRsets or values return NXRRSET.
- Added `dns-update-check <device> <server-ip> <zone> <name> <ip>` to send an
  A prerequisite-only UPDATE and inspect the result.
- New `dns_update_prereq` scenario covers satisfied, value-mismatch and missing
  name prerequisites.
- Tests: 403 unit checks, 90 scenarios; PowerShell and Go tests pass;
  coverage 58.1%; `make check` green with build artifacts preserved.

---

## Phase 86 — DNS AAAA and IPv6 address values (2026-11-25)

- Added a self-contained IPv6 value type with compressed/full parsing, embedded
  IPv4 support, canonical formatting and malformed-input rejection. This is a
  DNS data-plane type; IPv6 packet routing remains a separate stack effort.
- DNS codec supports AAAA (type 28, 16-byte RDATA); clients query `AAAA`, print
  `AAAA <address>` and cache A/AAAA independently.
- Added `dns-aaaa <device> <name> <ipv6> [ttl]`; AAAA participates in wildcard
  matching, per-RRset TTLs, zone scope and AXFR export.
- New `dns_aaaa` scenario covers exact and wildcard AAAA plus cache hits; AXFR
  scenario now exports AAAA.
- Tests: 423 unit checks, 91 scenarios; PowerShell and Go tests pass;
  coverage 58.5%; `make check` green with build artifacts preserved.

---

## Phase 87 — Primary/secondary zones and NOTIFY (2026-11-25)

- UPDATE now bumps the zone SOA serial and sends NOTIFY to configured targets.
- Added `dns-secondary <device> <zone> <primary-ip>`: creates a secondary zone,
  performs an initial AXFR, and installs the transferred SOA/NS/A/AAAA/CNAME/MX
  records with their RRset TTLs.
- Added `dns-notify-target` and manual `dns-notify`; NOTIFY responses are
  opcode-correct and unauthorized zones are REFUSED.
- Secondary refresh reuses AXFR internally without printing individual records;
  it prints `secondary <zone> updated serial <n>` on each successful refresh.
- New `dns_secondary` scenario: initial sync, UPDATE serial 1→2, NOTIFY, refresh
  and authoritative queries from the secondary.
- Tests: 423 unit checks, 92 scenarios; PowerShell and Go tests pass;
  coverage 58.6%; soak and perf green; build artifacts preserved. (The monolithic
  `make check` hit the previous 850s wrapper limit during the slower coverage
  rebuild; coverage/soak/perf were run separately to completion.)

---

## Phase 88 — Secondary SOA refresh/expire timers (2026-11-25)

- Secondary zones now schedule refresh using the transferred SOA refresh value;
  each periodic refresh is a full AXFR and resets the expiration deadline from
  the SOA expire value.
- Failed refreshes retry at the SOA retry interval. Once the expiration deadline
  passes without a successful refresh, the secondary marks the zone expired and
  answers SERVFAIL until a successful NOTIFY/refresh.
- NOTIFY-triggered transfers and timer-triggered transfers share the same
  generation-guarded timer state; active transfers defer timer starts.
- New `dns_secondary_timer` and `dns_secondary_expire` scenarios cover periodic
  refresh and expiry/SERVFAIL behavior.
- Tests: 423 unit checks, 94 scenarios; PowerShell and Go tests pass;
  coverage 58.8%; soak and perf green; build artifacts preserved.

---

## Phase 89 — IXFR journal and incremental transfer (2026-11-25)

- Authoritative updates now snapshot zone RRsets before/after changes and
  journal bounded (64-entry) deleted/added records keyed by SOA serial.
- Added IXFR server responses over TCP: up-to-date single SOA, serial-chain
  incremental deletes/adds, and AXFR fallback when journal coverage is missing.
- Added the `dns-ixfr <device> <server> <zone> <serial>` diagnostic client over
  TCP with TSIG/ACL reuse and SOA/A/AAAA/CNAME/MX/NS output.
- Secondary refresh remains AXFR for now; integrating IXFR into the secondary
  refresh path is the next step.
- New `dns_ixfr` scenario covers a serial 1→2 incremental transfer and an
  up-to-date serial 2 query.
- Tests: 423 unit checks, 95 scenarios; PowerShell and Go tests pass;
  coverage 59.0%; soak and perf green; build artifacts preserved.

---

## Phase 90 — Secondary IXFR refresh (2026-11-25)

- Secondary refresh now sends IXFR using the current local serial after its
  initial AXFR, applies serial-chain deletes/adds, and reports up-to-date zones.
- AXFR fallback remains automatic when the primary journal cannot cover the
  requested serial; timers and NOTIFY use the same generation-guarded refresh
  path.
- Updated `dns_secondary` and `dns_secondary_timer` expectations for incremental
  refresh/up-to-date diagnostics.
- Tests: 423 unit checks, 95 scenarios; PowerShell and Go tests pass;
  coverage 58.8%; soak and perf green; build artifacts preserved.

---

## Phase 91 — TCP CUBIC congestion control (2026-11-26)

- Added a selectable congestion-control mode on `TcpConnection`: Reno remains
  the default; CUBIC-style loss epochs track W_max/K, use beta=0.7 reduction,
  cubic growth with a Reno-friendly fallback, and retain existing recovery/SACK
  behavior.
- Added `tcp-congestion <device> reno|cubic`; the setting is applied to new
  accepted, active, DNS-over-TCP and transfer connections.
- Added `tcp_cubic` scenario and a loss-path unit test covering CUBIC state
  initialization and retransmission success.
- Tests: 427 unit checks, 96 scenarios; PowerShell and Go tests pass;
  coverage 58.8%; soak and perf green; build artifacts preserved.

---

## Phase 92 — TCP Tail Loss Probe (2026-11-26)

- Added Tail Loss Probe scheduling when unacked data exists in Established:
  PTO uses SRTT + 4·RTTVAR (fallback RTO), clamped before RTO, and is
  generation-guarded/cancelled on ACK/progress, RTO and abort.
- A TLP probe retransmits the highest unacked segment, increments probe/
  retransmit counters, and lets the normal ACK/RTO path complete recovery.
- Added `tcp-tlp <device> on|off`, applied to all new TCP connection paths, with
  a `tcp_tlp` scenario and unit test.
- Tests: 430 unit checks, 97 scenarios; PowerShell and Go tests pass;
  coverage 58.9%; soak and perf green; build artifacts preserved.

---

## Phase 93 — TCP PRR-style recovery pacing (2026-11-26)

- Added recovery pacing with delivered/out accounting and a per-recovery send
  credit; new-data sends are capped by PRR credit while recovery retransmits
  continue independently.
- ACK progress adds proportional credit; recovery exit/RTO/abort reset live
  state, while `prrAcked` retains a monotonic diagnostic counter.
- Added `tcp-prr <device> on|off`, a `tcp_prr` scenario and a loss-path unit test.
- Tests: 433 unit checks, 98 scenarios; PowerShell and Go tests pass;
  coverage 58.9%; soak and perf green; build artifacts preserved.

---

## Phase 94 — Efficiency and code audit (2026-11-26)

- TCP ACK processing now trims/erases unacked segments in place via map node
  extraction instead of rebuilding and copying the whole map on every ACK.
- TCP connections now use stable list storage plus a tuple hash index
  (`localPort`, `remoteIp`, `remotePort`), replacing per-packet O(connections)
  scans; the last-hit fast path remains.
- Removed the per-packet full closed-connection sweep; cleanup now runs on
  accept/cookie/connect/status paths where capacity or reporting matters.
- Switch MAC learning now uses an `unordered_map` with a MAC/VLAN hash; the
  diagnostic `mac-table` output sorts keys to retain deterministic display.
- Router longest-prefix lookup now rebuilds a compact binary prefix trie on
  route-table changes; steady-state forwarding is O(32) instead of O(routes).
- ARP pending sends now use a next-hop counter index instead of scanning the
  pending vector for every UDP/TCP/ICMP send.
- TCP setup is centralized in `NewTcpConnection`, removing repeated scheduler,
  option, callback and keepalive initialization from six creation paths.
- Audit candidates left for later (not implemented): event arena allocation and
  splitting `EndDevice.cpp` by DNS/DHCP domains.
- Tests: 433 unit checks, 98 scenarios; PowerShell and Go tests pass;
  coverage 59.5%; soak and perf green; build artifacts preserved.

---

## Phase 95 — OSPF default origination and redistribution (2026-11-26)

- Added `ospf-default-originate` and `ospf-redistribute` for connected/static
  routes, with metric and Type 1/Type 2 selection.
- External LSA origination now merges manual, default and redistributed routes
  with duplicate suppression; Type 5/Type 7 paths and withdrawals reuse the
  existing external LSDB machinery.
- Added route-change refresh: static route changes while OSPF is enabled
  re-originate externals; defaults/redistribution apply immediately.
- New `ospf_default` (default route ping) and `ospf_redistribute` (learned static
  external route) scenarios.
- Tests: 433 unit checks, 100 scenarios; PowerShell and Go tests pass;
  coverage 59.6%; soak and perf green; build artifacts preserved.

---

## Phase 96 — OSPF area range summaries (2026-11-26)

- Added `ospf-summary <router> <area> <prefix> [not-advertise] | clear`.
- Area ranges aggregate matching component networks into one Type 3 LSA with
  the maximum component metric and suppress the covered component summaries;
  `not-advertise` suppresses both the range and its components.
- Range changes regenerate summaries immediately and withdraw stale LSAs via
  the existing desired/flush path.
- New `ospf_summary` scenario verifies a /23 aggregate and component suppression.
- Tests: 433 unit checks, 101 scenarios; PowerShell and Go tests pass;
  coverage 59.7%; soak and perf green; build artifacts preserved.

---

## Phase 97 — TCP RACK-style loss detection (2026-11-26)

- Track per-segment send timestamps and derive a RACK RTT/reorder window.
- On duplicate ACKs and SACK blocks, retransmit the oldest uncovered hole when
  its send time exceeds the reorder window; retransmissions update timestamps
  and avoid duplicate hole selection.
- Added `tcp-rack <device> on|off`, applied to all new TCP connection paths, with
  a `tcp_rack` scenario and loss-path unit test.
- Tests: 436 unit checks, 102 scenarios; PowerShell and Go tests pass;
  coverage 59.8%; soak and perf green; build artifacts preserved.

---

## Phase 98 — TCP pacing (2026-11-26)

- Added optional pacing based on `cwnd × MSS / SRTT`; paced sends schedule a
  generation-guarded follow-up event instead of emitting the whole cwnd burst.
- Pacing is disabled by default to preserve existing burst behavior; enable with
  `tcp-pacing <device> on`.
- Applies to all new active/passive and DNS-over-TCP connection paths.
- Added `tcp_pacing` scenario and a paced bulk-transfer unit test.
- Tests: 438 unit checks, 103 scenarios; PowerShell and Go tests pass;
  coverage 59.9%; soak and perf green; build artifacts preserved.

---

## Phase 99 — TCP ephemeral port lifecycle (2026-11-26)

- Active TCP connections now allocate local ports from a bounded cursor range
  (`tcp-port-range`, default 40000..65535), skipping ports already used by any
  connection; exhaustion reports `tcp: no local port`.
- Existing default first port remains 40000 for compatibility with diagnostics.
- Added `tcp-port-range` and a dual-connection `tcp_ports` scenario verifying
  collision-free 40000/40001 allocation.
- Tests: 438 unit checks, 104 scenarios; PowerShell and Go tests pass;
  coverage 59.9%; soak and perf green; build artifacts preserved.

---

## Phase 100 — TCP ECN (2026-11-26)

- Added IPv4 ECN bits (Not-ECT/ECT/CE) to the packet codec and equality.
- TCP negotiates ECN using SYN ECE/CWR and SYN-ACK ECE; data uses ECT(0).
- Receivers echo CE using ECE ACKs and clear after CWR; senders reduce
  congestion state once per CE episode and set CWR on the next data segment.
- Added router `ecn-mark <router> <dev:idx> on|off` for deterministic CE marking.
- `tcp-status` now reports `ecn=` and `ce=` per connection.
- New `tcp_ecn` scenario and ECN negotiation unit test.
- Tests: 441 unit checks, 105 scenarios; PowerShell and Go tests pass;
  coverage 59.8%; soak and perf green; build artifacts preserved.

---

## Phase 101 — TCP MSS and link MTU (2026-11-26)

- Link objects now carry an MTU (`set-link ... mtu 576..1500`).
- TCP connections derive an MSS limit from the ingress/egress link MTU and
  clamp the negotiated peer MSS; a 576-byte link yields MSS 536.
- Active, passive and SYN-cookie paths apply the limit; IP fragmentation remains
  outside this increment.
- `tcp-status` now reports `mss=`.
- Added `tcp_mtu` scenario and MTU/MSS verification.
- Tests: 441 unit checks, 106 scenarios; PowerShell and Go tests pass;
  coverage 59.9%; soak and perf green; build artifacts preserved.

---

## Phase 102 — IPv4 fragmentation and reassembly (2026-11-26)

- `IpPacket` now carries identification, the MF flag and fragment offset; the
  codec preserves these fields across encode/decode and equality checks.
- Egress links split IPv4 datagrams larger than the configured link MTU into
  MTU-sized fragments with 8-byte-aligned payloads, a per-link IP ID, and the
  original TTL/ECN and Ethernet/VLAN framing.
- Ingress ports reassemble fragments by source/destination, IP ID and protocol
  using bounded per-port buffers that are pruned after 300 seconds; complete
  datagrams re-enter the normal device receive path.
- Added direct-link and router-transit fragmentation scenarios with a 553-byte
  UDP payload over a 576-byte link; added fragment codec unit checks.
- ICMP Packet Too Big / DF-based PMTU discovery was not modeled in this
  increment; Phase 103 adds DF and ICMP Fragmentation Needed reporting.
- Tests: 449 unit checks, 108 scenarios; PowerShell and Go tests pass;
  coverage 58.9% (floor 54%); soak and perf green; build artifacts preserved.

---

## Phase 103 — DF and ICMP Fragmentation Needed (2026-11-26)

- `IpPacket` now carries the Don't Fragment flag through encode/decode and
  equality checks; link fragmentation is skipped for DF datagrams.
- Routers check the egress link MTU before forwarding: oversized DF datagrams
  are dropped and answered with ICMP Destination Unreachable / Fragmentation
  Needed (code 4) carrying the next-hop MTU and quoting the original packet.
- `IcmpMessage` models the next-hop MTU field for code 4 while preserving the
  existing echo id/sequence encoding.
- `udp-send <dev> <ip> <dport> df <text...>` sets DF, and endpoints print
  `icmp frag needed from <router> mtu=<bytes>` when the report arrives.
- Added `fragment_df` scenario and DF/ICMP codec unit checks. TCP path-MTU
  adaptation (reacting to ICMP reports by reducing MSS/segment size) remains
  future work.
- Tests: 453 unit checks, 109 scenarios; PowerShell and Go tests pass;
  coverage 59.0% (floor 54%); soak and perf green; build artifacts preserved.

---

## Phase 104 — TCP path MTU discovery (2026-11-26)

- TCP data segments set DF. Segment sizing subtracts IP/TCP headers and the
  timestamp option so a full-size segment fits the current path MTU.
- `TcpConnection` tracks `pathMtu`; local egress-MTU changes refresh the path
  MSS before sending, and ICMP Fragmentation Needed reports lower it.
- On a path-MTU decrease, unacked bytes are rewound to `sndUna`, the send
  buffer is re-pumped with the smaller segment size, and stale RTO/TLP/pacing
  state is cleared.
- Endpoints identify the affected connection from the quoted IP/TCP ports in
  the ICMP report and print `icmp frag needed from <router> mtu=<bytes>`.
- Added `tcp-send <device> <text...>` for established connections and
  `pmtu=` in `tcp-status`.
- Added the `tcp_pmtu` scenario (1500-byte send after a 576-byte egress link
  change) and a path-MTU unit test.
- Tests: 461 unit checks, 110 scenarios; PowerShell and Go tests pass;
  coverage 59.1% (floor 54%); soak and perf green; build artifacts preserved.

---

## Phase 105 — Drop-reason observability (2026-11-26)

- Port drop counters now carry fixed-slot reasons: link-down, loss, mtu, acl,
  ttl, no-route, no-egress, arp-pending, fragment, stp, vlan, parse, and
  resource.
- Links, routers, switches, and the fragment reassembler count reasons at the
  existing drop sites without changing forwarding decisions.
- Added `drop-stats <device>`, which prints per-port totals plus non-zero
  reason counts; the total still matches the `stats` `drop=` value.
- Added a combined ACL/MTU scenario (`drop_stats`) and drop-reason unit checks.
- Tests: 466 unit checks, 111 scenarios; PowerShell and Go tests pass;
  coverage 59.1% (floor 54%); soak and perf green; build artifacts preserved.

---

## Phase 106 — TCP scope and status clarification (2026-11-26)

- Documented TCP against the product's actual goal: a deterministic offline
  simulator with byte-accurate behavior, not a live-wire or production stack.
- README now states that live-stack interoperability, TAP bridging, and
  replacing an OS TCP stack are out of scope; the live bridge stays archived.
- Reworked the roadmap item into offline PCAP conformance against reference
  captures (no live networking) and added a simulator-scope TCP status section.
- Clarified the same scope in the operator guide and man page.
- No code or test changes; 466 unit checks and 111 scenarios remain green.

---

## Phase 107 — Offline TCP PCAP conformance gate (2026-11-26)

- `ynpcap` now parses IPv4 DF and ECN codepoints and tracks TCP data segments,
  repeated sequence numbers, SACK blocks, ECN/CE, and DF usage.
- Added MSS-fit validation: a data payload larger than the peer's advertised
  MSS is reported as a conformance issue.
- Added the `tcp_pcap` scenario (lossy handshake/data capture) and the
  `make pcapcheck` gate; `make check` now includes it.
- Added PowerShell `pcapcheck` support to `Makefile.win`.
- Tests: 466 unit checks, 112 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 59.1% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 108 — TCP basic PMTU growth re-probing (2026-11-26)

- TCP connections now track the negotiated `peerMss` separately from the
  path-limited MSS, allowing segment size to grow back after path recovery.
- Added a `pmtuCeiling` from the local egress MTU, a 60-second hold, and a
  growth probe that runs only when new data is queued; the probe raises
  `pathMtu` toward the ceiling and restores `mss` up to `peerMss`.
- A failed growth probe still falls back through ICMP Fragmentation Needed and
  re-segments unacked data at the lower MSS.
- Added the `tcp_pmtu_grow` scenario (shrink to 576, restore to 1500, wait,
  send new data) and path-MTU growth unit checks.
- Tests: 470 unit checks, 113 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 59.1% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 109 — IPv6 host addressing, NDP, and ping6 (2026-11-26)

- Added `Ipv6Packet` (40-byte header codec) and ICMPv6 messages with
  pseudo-header checksums, echo request/reply, and Neighbor Solicitation/
  Advertisement with source/target link-layer options.
- Ports can carry an optional IPv6 address (`set-ip6`), and `ping6` resolves
  the target through Neighbor Discovery and prints ICMPv6 echo replies.
- Ethernet now recognizes the IPv6 EtherType; hosts accept solicited-node
  multicast frames for NDP while keeping existing ARP/IPv4 behavior unchanged.
- Added `ipv6_ping` scenario and IPv6 packet/ICMPv6/NDP codec unit checks.
- Scope is intentionally host-only on one shared or switched segment; IPv6
  routing, extension headers, and IPv6 fragmentation remain future work.
- Tests: 484 unit checks, 114 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.4% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 110 — IPv6 scene persistence and diagnostics (2026-11-26)

- `.yn` save files now include each port's IPv6 address; load replays
  `set-ip6` after creating the port.
- `state` JSON includes `ip6` (or null) per port, and `ports <device>` prints
  an `ip6=` field.
- Added the `ipv6_persist` scenario (save, reset with `new`, load, `ping6`) and
  extended the JSON round-trip unit checks to assert `set-ip6` is emitted.
- Cleanup scripts now remove the IPv6 test scene and capture artifacts.
- Tests: 486 unit checks, 115 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.4% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 111 — IPv6 routing and forwarding (2026-11-26)

- Added `Ipv6Subnet` with 128-bit prefix normalization, containment, ordering,
  and `addr/prefix` parsing.
- Ports now carry an IPv6 prefix (`set-ip6 ...[/prefix]`, default 64); routers
  install connected IPv6 routes automatically when addresses are configured.
- Added IPv6 static routes and gateways (`add-route6`, `set-gateway6`) plus the
  `routes6` diagnostic. IPv6 routes and gateways round-trip through
  `save`/`load`.
- Routers forward IPv6 with longest-prefix lookup, hop-limit decrement, and NDP
  next-hop resolution; pending packets are queued until Neighbor Advertisements
  arrive. Routers also answer NS for their own addresses and ICMPv6 echo.
- Added the `ipv6_route` scenario (PC1 -> R1 -> PC2 with `ping6` and `routes6`)
  and IPv6 subnet unit checks.
- OSPFv3 and IPv6 extension headers/fragmentation remain future work.
- Tests: 492 unit checks, 116 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.3% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 112 — IPv6 diagnostics and error reporting (2026-11-26)

- Added `nd6-table <device>` for host and router IPv6 neighbor caches.
- Routers now return ICMPv6 Destination Unreachable when no IPv6 route/egress
  exists and Time Exceeded when the hop limit reaches zero, quoting the original
  IPv6 packet.
- Endpoints print `icmp6 unreachable from ...` and `icmp6 time exceeded from
  ...`; the IPv6 echo path is unchanged.
- Added `ipv6_unreachable` and extended `ipv6_route` with an `nd6-table` check.
- Tests: 492 unit checks, 117 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.3% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 113 — IPv6 ping timeouts and pending cleanup (2026-11-26)

- Added per-`ping6` outstanding state and a timeout event; unanswered probes
  print `ping6 timeout from <target> seq=<n>`.
- Timeouts/ICMPv6 errors remove matching pending NDP echo entries and
  outstanding probe state.
- ICMPv6 Destination Unreachable / Time Exceeded now parse the quoted echo
  request to cancel the matching probe instead of leaving it to time out.
- Added the `ipv6_timeout` scenario and kept existing IPv6 route/error scenarios.
- Tests: 492 unit checks, 118 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.4% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 114 — IPv6 traceroute (2026-11-26)

- Added `traceroute6 <device> <ipv6> [max-hops]` using hop-limited ICMPv6 Echo
  Requests and per-hop Time Exceeded reports.
- Tracks hop sequence numbers, prints `hop N: <router>`, target with `(target)`,
  and `*` on timeout; schedules the next hop and stops at target/max hops.
- Reused NDP resolution plus pending echo state; timeout and error paths clear
  the matching hop state.
- Added the `ipv6_traceroute` scenario (PC1 -> R1 -> PC2).
- Tests: 492 unit checks, 119 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.4% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 115 — IPv6 ACLs (2026-11-26)

- Added ordered IPv6 ACLs with `acl6 <router> in|out allow|deny <src6/p>
  <dst6/p> <proto|any>`.
- Inbound rules are checked before local/forward processing; outbound rules are
  checked before forwarding. Matching drops increment the `acl` drop reason.
- Protocol selectors accept `any`, `icmp`/`icmpv6` (next header 58), `tcp`, and
  `udp`.
- Added the `ipv6_acl` scenario (deny PC1->PC2 ICMPv6, verify timeout and
  `drop-stats`).
- Tests: 492 unit checks, 120 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.5% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 116 — ACL persistence (2026-11-26)

- `.yn` save files now include ordered IPv4 and IPv6 ACL rules (direction,
  action, source/destination prefixes, protocol).
- `load` replays `acl`/`acl6` commands after ports/routes/gateways, preserving
  rule order for first-match semantics.
- Extended `ipv6_acl` to save, reset, and reload its ACL before probing, and
  added `acl_persist` for IPv4 ACL round-trip.
- Cleanup scripts remove the new saved-scene artifacts.
- Tests: 492 unit checks, 121 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.5% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 117 — IPv6 drop accounting and pending aging (2026-11-26)

- IPv6 router drops now record fixed reasons: parse, acl, no-route, no-egress,
  ttl, and resource (pending-queue exhaustion).
- `AgePending6` prunes queued IPv6 packets older than `kPendingTimeout` and
  increments `droppedPending6`.
- Extended `ipv6_unreachable` to assert `no-route=1` through `drop-stats`.
- Tests: 492 unit checks, 121 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.5% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 118 — NAT persistence (2026-11-26)

- `.yn` save files now include NAT enablement with inside/outside port refs and
  static port-forward entries (`proto`, public port, inside IP/port).
- `load` replays `nat` and `nat-port` after topology/routing/gateway/ACL setup.
- Added `nat_persist` (save, `new`, load, TCP DNAT) and cleanup for the saved
  scene.
- Tests: 492 unit checks, 122 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.6% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 119 — IPv6 state JSON diagnostics (2026-11-26)

- `state` now emits each host/router's `nd6` neighbor cache, IPv6 default
  gateway (when configured), and each router's `routes6` table.
- Added unit checks for the new state fields and preserved existing JSON shape
  for IPv4 fields.
- Tests: 497 unit checks, 122 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.6% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 120 — OSPF router ID configuration (2026-11-27)

- Added `ospf-router-id <router> <id>`; the configured ID overrides the
  highest-interface-IP default for LSAs, neighbor matching, and status.
- Added `ospf_router_id` scenario and retained the existing OSPF suite.
- Tests: 497 unit checks, 123 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.6% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 121 — Switch port mirroring (SPAN) (2026-11-27)

- Added `span <switch> <src-dev:idx> <dst-dev:idx> | off`.
- Frames received on the source port are copied to the monitor port through
  normal egress VLAN/STP handling; the original forwarding path is unchanged.
- Added the `span` scenario (source port 0 -> monitor port 2 with a ping) and
  verified monitor-port counters.
- Tests: 497 unit checks, 124 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.6% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 122 — SPAN persistence (2026-11-27)

- `.yn` save files now include switch SPAN source/destination port refs; load
  replays `span` after ports/links are created.
- Extended the `span` scenario to save, reset with `new`, reload, and verify the
  monitor counter; cleanup removes the saved scene.
- Tests: 497 unit checks, 124 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.6% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 123 — BGP wire codec groundwork (2026-11-27)

- Added `BgpMessage` with the 19-byte BGP header and OPEN, UPDATE, KEEPALIVE,
  and NOTIFICATION encode/decode.
- UPDATE supports IPv4 NLRI and withdrawn prefixes plus ORIGIN, AS_PATH,
  NEXT_HOP, LOCAL_PREF, and MED path attributes; oversized attributes use the
  extended-length flag.
- Added unit checks for all message types, path attributes, prefix parsing, and
  invalid markers. BGP sessions, TCP port 179, route propagation, and best-path
  selection remain future work.
- Tests: 508 unit checks, 124 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 57.9% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 124 — BGP configuration and local RIB (2026-11-27)

- Added BGP control-plane configuration: enable/disable, local AS, router ID,
  neighbors, and local networks.
- Added `bgp-path` offline path injection for deterministic RIB testing and a
  local best-path selector (local-pref, AS-path length, origin, MED, eBGP,
  router ID/peer tie-break).
- Added `bgp-status` with neighbors, path count, and selected RIB.
- Added the `bgp_config` scenario and BGP selection unit checks. BGP-over-TCP
  sessions and UPDATE propagation remain future work.
- Tests: 512 unit checks, 125 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 58.1% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 125 — BGP-over-TCP sessions (2026-11-27)

- Routers now run a minimal TCP/BGP endpoint: listeners on port 179 plus active
  sessions selected deterministically by lower local interface IP.
- OPEN/validation, KEEPALIVE handshake, Established state, and UPDATE exchange
  feed received prefixes into the local BGP RIB/best-path selector.
- `bgp-status` reports OpenSent/OpenConfirm/Established sessions; the
  `bgp_session` scenario verifies a two-router eBGP session and reciprocal RIBs.
- Periodic keepalive/hold timers, withdrawal processing, BGP route installation,
  and policy remain future work. NAT forwarding on non-179 router TCP ports was
  kept unchanged.
- Tests: 512 unit checks, 126 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 57.8% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 126 — BGP route installation and withdrawal (2026-11-27)

- Selected BGP paths are now installed as `bgp` routes in the forwarding table;
  best-path changes replace prior BGP routes and `BgpSelect` is re-run on
  connected-route rebuilds.
- UPDATE withdrawals and peer reset/teardown remove matching paths; duplicate
  advertisements from the same peer replace the old path rather than stacking.
- Existing RIP/OSPF cleanup paths preserve BGP routes.
- Extended `bgp_session` with hosts and a cross-AS ping; the test now verifies
  end-to-end forwarding over BGP-learned routes.
- Tests: 512 unit checks, 126 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 57.7% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 127 — BGP keepalive and hold timers (2026-11-27)

- Established BGP sessions schedule a 30-second KEEPALIVE timer and track the
  last received message; 90 seconds of silence tears the session down and
  withdraws its routes.
- Timer events are generation- and router-guarded so configuration restarts or
  session teardown cannot touch stale session pointers.
- Added the `bgp_hold` scenario (session established, link down, hold expiry,
  RIB/route withdrawal).
- Tests: 512 unit checks, 127 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 57.8% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 128 — Code-health refactor (2026-11-27)

- Moved BGP session/TCP transport out of `Router.cpp` into
  `device/RouterBgp.cpp`; Router.cpp dropped from about 1.47k to 1.15k lines.
- Removed the inactive OSPF virtual-link scaffolding left from an abandoned
  attempt (unused fields, helpers, branches, and virtual-link packet paths).
- Consolidated duplicated solicited-node IPv6 address/MAC helpers into
  `Icmpv6Message` (`NdpSolicitedNode`/`NdpSolicitedMac`).
- No protocol behavior changes; all existing scenarios and unit checks remain
  green. Full-source line count is unchanged in aggregate, but large
  translation units and dead paths are reduced.
- Tests: 512 unit checks, 127 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 57.2% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 129 — Device subfolder decomposition (2026-11-27)

- Moved DNS implementation out of `EndDevice.cpp` into
  `device/end/EndDeviceDns.cpp`; EndDevice.cpp fell from roughly 5.35k to 2.01k
  lines. DNS helpers and retry/secondary events now live beside the DNS code.
- Added `device/end/*.cpp` discovery to Makefile/Makefile.win and coverage
  object/gcov collection; CMake already globbed recursively.
- No protocol behavior changes; all existing scenarios and unit checks remain
  green.
- Tests: 512 unit checks, 127 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 56.3% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 130 — Router implementation subfolder (2026-11-27)

- Moved `RouterOspf.cpp`, `RouterDhcp.cpp`, and `RouterBgp.cpp` under
  `device/router/`; includes, Makefiles, and coverage discovery were updated.
- This groups Router-domain implementations while keeping the shared
  `Router.hpp/.cpp` interface stable. No behavior changes.
- Current largest source units: `EndDeviceDns.cpp` (3.36k), `TopoCommand.cpp`
  (2.32k), `RouterOspf.cpp` (2.04k), `EndDevice.cpp` (2.01k),
  `TcpConnection.cpp` (1.51k).
- Tests: 512 unit checks, 127 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 56.3% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 131 — BGP reconnect and passive relisten (2026-11-27)

- Active BGP sessions now schedule a bounded 30-second reconnect after hold
  expiry/reset; passive listeners relisten on the same local address.
- Reconnect events carry router/session generations so stale events cannot
  touch rebuilt sessions; learned paths are withdrawn immediately on failure.
- Added `bgp_reconnect`: establish, link down, hold expiry, link up, automatic
  session recovery, and successful forwarding over restored BGP routes.
- Tests: 512 unit checks, 128 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 56.3% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 132 — BGP local-preference and MED policy (2026-11-27)

- Added per-neighbor inbound `local-pref` policy and per-prefix outbound MED.
- Received paths retain the wire local-pref so policy changes can be reapplied;
  `bgp-local-pref` re-runs best-path selection immediately.
- Outbound UPDATEs include configured MED attributes.
- Added the two-provider `bgp_localpref` scenario selecting the higher
  local-preference path.
- Tests: 512 unit checks, 129 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 56.1% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Phase 133 — BGP configuration persistence (2026-11-27)

- `.yn` save files now include BGP enablement, local AS/router ID, neighbors,
  networks, inbound local-preference, and outbound MED settings.
- Load replays BGP config before `bgp on`, then starts sessions through the
  normal path.
- Extended `bgp_session` to save, `new`, reload, re-establish the session, and
  verify cross-AS forwarding.
- Tests: 512 unit checks, 129 scenarios; Linux/Windows scenario suites and Go
  tests pass; coverage 56.1% (floor 54%); soak and perf green; build artifacts
  preserved.

---

## Validation approach (2026-11-20)

Each increment was verified with small, focused tests compiled against the
modules:

- Round-trip encode → decode for `ARP` and `IpPacket`, plus rejection of short
  and malformed buffers.
- `Ipv4Subnet` mask/broadcast/`Contains`, including `/0`, `/32`, and `/25` splits.
- MAC parsing/formatting and ordering.
- End-to-end ARP on two hosts across a link (request → reply → cache).
- Switch topology (3 hosts + 1 switch): flooding, learning, unicast forwarding,
  and MAC-table aging with the logical clock.
- `Router::IsMyIp` verified with a temporary test (a stub `OnFrame` was needed to
  satisfy the vtable). Router forwarding, the ARP pending queue, and ARP cache
  aging are implemented; overall end-to-end testing is deferred to the final
  integration phase.

## Lessons / conventions adopted

- Prefer `TryParse(...) -> bool` for untrusted text; throw only from convenience
  constructors.
- Serialize integers big-endian via a single shared codec; keep encoders and
  decoders in sync.
- Headers forward-declare types used only through pointers/references; `.cpp`
  files include the definitions they use.
- Keep interfaces const-correct (`const EthernetFrame&` everywhere it is read).
- Model time with a logical clock so simulation results are reproducible.
- A polymorphic class whose virtual override is declared but not defined links
  with `undefined reference to vtable` the moment it is instantiated; define the
  override (even as a stub) before constructing the object.
