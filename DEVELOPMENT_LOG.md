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
