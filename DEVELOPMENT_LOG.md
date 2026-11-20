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
  satisfy the vtable). Router forwarding (`OnFrame`) is still in progress.

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
