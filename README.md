# yanas net

<img src="docs/logo.svg" alt="yanas net" width="72" align="left">

**yanas net** is a deterministic C++17 network simulator for Layer-2/Layer-3
study and scenarios: IPv4 subnets, Ethernet frames, ARP, VLAN/802.1Q, MAC-learning
switches, spanning tree (STP and an RSTP-style rapid mode), static routing, and
ICMP. It is a **terminal-first, scriptable tool for technical users**: an
interactive CLI plus `.txt`/`.lua`/`.yn` inputs and bundled Lua, all on a
deterministic engine. (Former GUI/web front ends and the live bridge experiment
are archived under `legacy/`.)
It is free software under the GNU GPL v3.0 or later.

`yanas net` is an **offline local tool**: it requires no internet access and
contacts no external services. Install it, run it, and keep all scenes, captures,
and outputs on the local machine.

The engine runs on a logical clock, wire formats are byte-accurate, and the
sources are dependency-free and comment-free (all documentation is here and in
`DEVELOPMENT_LOG.md`). Version: `VERSION` (currently 0.1.0).

---

## Table of contents

1. [Overview](#overview)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Frame flow](#frame-flow)
5. [Project structure](#project-structure)
6. [Core module reference](#core-module-reference)
7. [Device module reference](#device-module-reference)
8. [Engine module reference](#engine-module-reference)
9. [Wire formats](#wire-formats)
10. [Building](#building)
11. [Quick start](#quick-start)
12. [Behavior details](#behavior-details)
13. [Design notes](#design-notes)
14. [Status and roadmap](#status-and-roadmap)

---

## Overview

The simulator models a small network out of discrete objects:

- **Values** (`Ipv4`, `Ipv4Subnet`, `Mac`) describe addresses.
- **Protocol messages** (`EthernetFrame`, `ARP`, `IpPacket`) describe what is
  sent, each with a byte codec.
- **Interfaces** (`Port`) attach a device to a wire.
- **Links** (`Link`) connect exactly two ports and move frames between them.
- **Devices** (`Device` base; `EndDevice`, `Switch`, `Router`) decide what to do
  with a received frame.
- **ArpAgent** is a shared component used by hosts and routers for ARP caching
  and request/reply handling.

The design favors clarity and determinism over raw performance. Source files are
comment-free; all documentation lives in this README and `DEVELOPMENT_LOG.md`.

## Features

- IPv4 addresses with strict parsing/validation and big-endian conversion.
- CIDR subnets: prefix→mask, broadcast, membership test, `a.b.c.d/prefix` parsing.
- MAC addresses: parse/format, ordering, zero and broadcast addresses.
- Ethernet frames with EtherType and an opaque byte payload.
- ARP request/reply with a standard 28-byte wire format and factory helpers.
- IPv4 packets with a 20-byte header, TTL handling, header checksum, and a byte codec.
- Ports and point-to-point links with automatic back-reference wiring.
- Host behavior: ARP resolution and an ARP cache.
- Switch behavior: MAC learning, flooding, unicast forwarding, MAC-table aging.
- Router behavior: longest-prefix routing table, TTL handling, next-hop ARP,
  MAC-header rewrite, and automatic connected routes per configured port.
- Shared ARP agent for hosts and routers (time-based cache aging + request/reply).
- VLAN: port-based isolation on access ports plus 802.1Q trunk tagging across
  switches, carried in a real TPID/TCI header on the frame.
- Spanning Tree (STP): 802.1D-style root election and Blocking/Learning/Forwarding
  port states with forward delay, enabled per switch.
- STP reconvergence on link up/down (with MAC flush) and per-port rx/tx/drop counters.
- STP Hello/Max-Age keepalives and an RSTP-style rapid mode (`set-stp-mode`).
- Frame capture to `.pcap`, JSON topology `save` / `load`, and a bounded `run`.
- ICMP: echo (ping) with RTT + timeout, Time Exceeded, and Destination Unreachable.
- Hosts queue outbound traffic behind automatic ARP resolution and keep a gateway.
- Event-driven, delayed frame delivery with an optional event trace.
- Engine-owned logical time for deterministic, single-threaded simulation.
- Makefile (optional Lua via `LUA=1`/pkg-config) and CMake builds.
- Lua scenario scripting (real Lua 5.4; `exec` / `run` / `log`).
- Editing/automation: `remove-device`/`remove-port`/`disconnect`/`rename-device`/
  `set-ip`, `state` JSON snapshots, and Ctrl-C to interrupt a long run.
- Diagnostics and visualization: `devices`/`links`/`ports`/`routes`/`arp-table`/
  `mac-table`, `traceroute`, and `export dot|svg` (diagram without a GUI).
- UDP datagrams with a configurable per-host echo service (`udp-echo`/`udp-send`).
- Real TCP service and client (`tcp-listen`/`tcp-connect`): three-way handshake,
  sequence/ACK, out-of-order reassembly, RTT-based RTO with oldest-unacked
  retransmission, RST (including resets for unmatched segments), basic
  zero-window probing, tunable keepalive (`tcp-keepalive`), simultaneous
  open/close, PAWS for timestamps, FIN/TIME_WAIT, slow-start/congestion-avoidance,
  MSS negotiation, window scaling, SACK (including DSACK and SACK-based recovery
  with cwnd undo) and TCP timestamps (RTT sampling), with delayed ACK, Nagle and
  validated RST handling.
  Listener backlog is bounded with
  stateless SYN cookies; each host is capped at 256 concurrent connections with
  dropped/reset counters and `tcp-status`.
  `tcp-lite-*` remains as a deprecated teaching transport and is **not** TCP.
- DHCP server/client with relay (`dhcp-server`/`dhcp-client`/`dhcp-relay`),
  configurable pool, gateway and DNS option; leases renew at 50%, rebind at
  87.5%, and expire if no server answers. DNS server/client
  (`dns-server`/`dns-record`/`dns-cname`/`dns-query`) with A, multiple-A,
  CNAME and NXDOMAIN. DHCP can configure the host DNS server.
- Source NAT/PAT and inbound port forwarding on routers (`nat`, `nat-port`,
  `nat-table`): rewrites TCP/UDP/ICMP, recomputes TCP checksums, and supports
  address overloading plus DNAT to inside hosts.
- RIP v2-lite dynamic routing (`rip`, `rip-status`): periodic updates over UDP
  520, split horizon, infinity metric, learned-route timers, and longest-prefix/
  metric route selection.
- OSPFv2 (`ospf`, `ospf-status`): RFC 2328 packets, Hello / neighbor state
  machine, DR/BDR election, per-area LSDB aging/refresh with DD/LSR/LSU/LSAck
  exchange and retransmission, Dijkstra SPF routes, ABR Type 3 summaries,
  Type 4 ASBR summaries, Type 5 external routes (`ospf-external`), stub and
  NSSA areas (`ospf-area-type`) with Type 7 translation, interface cost/passive
  policy, and simple-password, MD5, SHA-1 or SHA-256 authentication (`ospf-auth`).
- Link impairment (`set-link ... loss/dup/jitter/clear`) for reliability testing.
- Per-router ACLs (in/out, allow/deny by source/destination prefix and protocol).
- Terminal topology `map` and a tree generator (`generate tree`) for scale tests.

## Architecture

The project is layered; each layer depends only on lower layers.

```
+--------------------------------------------------------------+
| device layer   Device (abstract; portList, virtual OnFrame)  |
|                ├─ EndDevice   (host: ARP)                    |
|                ├─ Switch      (L2: learning + forwarding)    |
|                └─ Router      (L3: routing + forwarding)     |
|                ArpAgent      (shared ARP: cache + handling)  |
+--------------------------------------------------------------+
| interface      Port  (mac, ip/subnet, link*, owner*)         |
+--------------------------------------------------------------+
| link layer     Link  (point-to-point, two ports)             |
+--------------------------------------------------------------+
| core layer     Ipv4  Ipv4Subnet  Mac                         |
|                EthernetFrame  ARP  IpPacket                  |
|                ByteIO (big-endian codec)  Aging (map aging)   |
+--------------------------------------------------------------+
| engine layer   Clock (time iface)  Engine (queue + time)     |
+--------------------------------------------------------------+
```

Object relationships:

- A `Device` owns one or more `Port` objects (`std::vector<Port*> portList`).
- Each `Port` points to at most one `Link` (`Port::link`) and back to its owning
  device (`Port::owner`, a `Device*`).
- A `Link` connects exactly two `Port`s (`Link::A`, `Link::B`).
- Header files use forward declarations for types only referenced by pointer, so
  the `Port` / `Link` / `Device` relationship is not a circular-include problem.

## Frame flow

Transmission is an event-driven, delayed pipeline. Frames travel as `FramePtr`
(`std::shared_ptr<const EthernetFrame>`), so forwarding and flooding share one
immutable frame instead of copying payloads.

```
1. A device builds a frame: make_shared<const EthernetFrame>(...).
2. device -> port->Send(FramePtr)
3. Port::Send       -> link->Transmit(this, FramePtr)
4. Link::Transmit   -> scheduler->ScheduleAfter(delay, FrameDelivery{peer, FramePtr})
                       (no scheduler set -> synchronous fallback: peer->Receive)
5. Engine advances the clock to the event time, then FrameDelivery::Execute
6. Port::Receive    -> owner->OnFrame(this, FramePtr)   (virtual dispatch)
7. Device::OnFrame  -> inspect frame->type and handle (ARP, IPv4)
```

Because `Port::Receive` calls `owner->OnFrame`, and `owner` is a `Device*`, a
single `Port` implementation can serve a host, a switch, or a router. The port
does no protocol logic; it only moves frames between the device and the link.

## Project structure

```
Internet/
├── .vscode/                 # VS Code IntelliSense configuration
├── app/
│   └── main.cpp             # CLI: interactive + file-driven simulation
├── core/                    # protocol data types
│   ├── ByteIO.hpp           # big-endian read/write helpers (header-only)
│   ├── Aging.hpp            # generic map-entry aging helper (header-only)
│   ├── Ipv4.hpp / .cpp
│   ├── Ipv4Subnet.hpp / .cpp
│   ├── Mac.hpp / .cpp
│   ├── EthernetFrame.hpp / .cpp
│   ├── ARP.hpp / .cpp
│   ├── IpPacket.hpp / .cpp
│   ├── UdpDatagram.hpp / .cpp
│   ├── TcpSegment.hpp / .cpp
│   ├── DhcpMessage.hpp / .cpp
│   └── DnsMessage.hpp / .cpp
├── device/                  # networked devices and interfaces
│   ├── Device.hpp / .cpp    # abstract base
│   ├── ArpAgent.hpp / .cpp  # shared ARP cache + request/reply
│   ├── EndDevice.hpp / .cpp # host
│   ├── Switch.hpp / .cpp    # Layer-2 switch (+ STP)
│   ├── StpBpdu.hpp / .cpp   # 802.1D Configuration BPDU codec
│   ├── Router.hpp / .cpp    # Layer-3 router
│   ├── RouterOspf.cpp       # OSPF state/LSDB/SPF/ABR (same Router class)
│   ├── FrameDelivery.hpp / .cpp # frame-delivery event
│   └── Port.hpp / .cpp
├── engine/                  # simulation engine
│   ├── Clock.hpp            # time source interface (header-only)
│   ├── Event.hpp / .cpp     # event base
│   ├── EventQueue.hpp / .cpp# ordered event queue
│   ├── Scheduler.hpp        # narrow scheduling interface
│   └── Engine.hpp / .cpp    # runtime: event queue + time
├── link/                    # link layer
│   └── Link.hpp / .cpp      # point-to-point wire (event-driven, delayed)
├── topo/                    # topology assembly + commands
│   ├── Topology.hpp / .cpp  # model + builder (owns devices/ports/links)
│   ├── TopoCommand.hpp / .cpp   # command parser/interpreter
│   └── CommandRunner.hpp / .cpp # shared line runner (CLI + Lua)
├── netstack/                # real TCP stack (state machine, reliability)
│   └── TcpConnection.hpp / .cpp
├── script/                  # bundled Lua bridge (static)
│   └── LuaScript.hpp / .cpp # exposes exec/run/log to Lua 5.4
├── tests/                   # unit, fuzz, and scenario tests
│   ├── unit/unit_tests.cpp  # codec/addressing unit tests
│   ├── fuzz_parsers.cpp     # deterministic parser fuzzing
│   ├── run_tests.sh         # scenario runner
│   └── *.txt / *.want
├── examples/                # runnable example scenes and scripts
├── docs/                    # man page + user guide
├── legacy/                  # archived GUI/web front ends (not built)
├── Makefile                 # build system (make -> netsim)
├── Makefile.win             # Windows CLI build (MinGW)
├── CMakeLists.txt           # alternative CMake build
├── .github/workflows/ci.yml # CI (gcc/clang + check + macOS + Windows)
├── .clang-tidy              # static-analysis config
├── COPYRIGHT                # GPLv3 copyright notice
├── LICENSE                  # GNU General Public License v3.0
├── SOURCE-CODE.md           # GPL source-availability statement
├── THIRD_PARTY_NOTICES.md   # Lua (MIT) notice
├── CONTRIBUTING.md
├── SECURITY.md
├── .gitignore
├── README.md
└── DEVELOPMENT_LOG.md
```

## Core module reference

### `Ipv4` — `core/Ipv4.hpp`

A 32-bit IPv4 address stored as `uint32_t value`; the most significant byte is
the first octet (192.168.1.2 → `0xC0A80102`).

| Member | Description |
|--------|-------------|
| `uint32_t value` | packed address |
| `Ipv4()` | `0.0.0.0` |
| `Ipv4(uint32_t)` | from raw value |
| `Ipv4(const std::string&)` | parse, throws `std::invalid_argument` on error |
| `Ipv4(uint8_t a, b, c, d)` | from four octets (cast to 32-bit before shifting) |
| `static bool TryParse(const std::string&, Ipv4&)` | non-throwing parse |
| `std::string ToString() const` | dotted decimal |
| `bool operator== / operator<` | comparison (ordering enables `std::map` keys) |
| `Ipv4 operator&(const Ipv4&) const` | bitwise AND (used for subnetting) |
| `static Ipv4 Any()` / `Broadcast()` | `0.0.0.0` / `255.255.255.255` |

Parsing rules: digits only, 1–3 digits per octet, value 0–255, exactly four
octets. `TryParse` never throws; the string constructor calls it and throws on
failure.

### `Ipv4Subnet` — `core/Ipv4Subnet.hpp`

A subnet in canonical form: a **network address** plus a **prefix length**.

| Member | Description |
|--------|-------------|
| `Ipv4 network` | network address (host bits zero) |
| `uint8_t prefix` | 0–32 |
| `Ipv4 Mask() const` | prefix → mask (`/24` → `255.255.255.0`) |
| `Ipv4 Broadcast() const` | `network | ~mask` |
| `bool Contains(const Ipv4&) const` | `(ip & Mask()) == network` |
| `static bool TryParse(const std::string&, Ipv4Subnet&)` | parses `a.b.c.d/prefix` |
| `std::string ToString() const` | `a.b.c.d/prefix` |
| `Ipv4Subnet(const Ipv4&, uint8_t prefix)` | validates prefix and normalizes network |

`Mask()` special-cases `prefix == 0` (a shift by 32 is undefined behavior). The
constructor clears host bits so `Contains` is always meaningful.

### `Mac` — `core/Mac.hpp`

A 48-bit MAC address stored as `uint8_t bytes[6]`.

| Member | Description |
|--------|-------------|
| `uint8_t bytes[6]` | raw octets |
| `static bool TryParse(const std::string&, Mac&)` | accepts `aa:bb:cc:dd:ee:ff`, `-`, or continuous hex |
| `std::string ToString() const` | lowercase, colon-separated |
| `bool operator== / != / <` | byte-wise lexicographic ordering |
| `bool IsGroup() const` | I/G bit test: first octet LSB (group/multicast) |
| `static Mac Zero()` / `Broadcast()` | `00:00:00:00:00:00` / `ff:ff:ff:ff:ff:ff` |

The least-significant bit of the first octet is the I/G bit (1 = group address);
switches use it to decide learning and flooding.

### `EthernetFrame` — `core/EthernetFrame.hpp`

A Layer-2 frame. The payload is opaque bytes so any protocol can ride inside.

| Member | Description |
|--------|-------------|
| `Mac dst`, `Mac src` | destination / source MAC |
| `uint16_t type` | inner EtherType (0x0800 / 0x0806) |
| `std::vector<uint8_t> payload` | carried bytes |
| `bool hasVlanTag`, `uint16_t vlanId`, `uint8_t vlanPcp`, `bool vlanDei` | optional 802.1Q tag (VID / PCP / DEI) |
| `WithVlan(vid, pcp, dei)` / `WithoutVlan()` | return a copy with the tag set / cleared |
| `std::vector<uint8_t> ToBytes() const` | real wire bytes (inserts TPID `0x8100` + TCI when tagged) |
| `static bool TryFromBytes(...)` | parse wire bytes, recognizing the 802.1Q header |
| `static constexpr uint16_t kVlanTpid = 0x8100` | 802.1Q TPID |
| `static constexpr uint16_t kIPv4 = 0x0800` | IPv4 EtherType |
| `static constexpr uint16_t kARP  = 0x0806` | ARP EtherType |
| `bool IsBroadcast() const` | `dst == Mac::Broadcast()` |
| `bool operator== const` | compares all fields incl. tag + payload |
| `std::string ToString() const` | debug form (shows `vlan=<id>` when tagged) |

`FramePtr = std::shared_ptr<const EthernetFrame>` is the shared, immutable handle
passed across the pipeline; forwarding and flooding share one frame.

A tagged frame serializes as `[dst][src][0x8100][TCI][inner EtherType][payload]`
— the real 802.1Q layout; an untagged frame is `[dst][src][EtherType][payload]`.

### VLAN / 802.1Q

- Access port: untagged; a frame's VLAN is the port's PVID (`set-vlan`).
- Trunk port: tagged; egress frames carry an 802.1Q header and the ingress VLAN is
  read from the tag (untagged ingress maps to the native VLAN, `set-trunk <port> [vid]`).
- The switch forwards only within the ingress VLAN and rewrites the tag on egress
  (push on a trunk, pop on an access port). Ports left at VID 0 share one L2 segment.

### Spanning Tree (STP)

- Per-switch, opt-in via `set-stp <switch> on` (off by default so non-STP scenes
  are unchanged).
- Classic 802.1D idea: bridges exchange Configuration BPDUs (`StpBpdu`, a 35-byte
  codec) carrying root ID, root path cost, and sender bridge/port ID. The lowest
  bridge ID wins the root election; every other bridge picks a root port, and the
  ports that would close a loop become Blocking (they neither forward nor learn).
- Bridge ID = `<priority>:<mac>`; priority defaults to 32768
  (`set-bridge <switch> <prio>`); the bridge MAC is the lowest port MAC.
- `stp-status <switch>` prints the root/cost plus each port's forwarding/blocking
  state.
- Ports step Blocking -> Listening -> Learning -> Forwarding through the forward
  delay (per-port timers); `stp-status` shows the live state.
- Link failure/recovery: `set-link <dev:idx> down|up` disables the wire, clears the
  affected BPDU state, flushes the MAC table, and re-runs the election, so the tree
  re-converges over the alternate path.
- Periodic Hello BPDUs refresh the topology; Max-Age expires stale neighbor info.
- `set-stp-mode <switch> rstp` selects a rapid (immediate-forwarding) mode. This is
  an RSTP-style subset (rapid transition + version-2 BPDUs), not full 802.1w
  proposal/agreement.
- BPDUs ride a private EtherType (`0x8E01`) instead of the real LLC/SNAP
  encapsulation.

### `ARP` — `core/ARP.hpp`

An ARP message with a standard 28-byte wire format.

| Member | Description |
|--------|-------------|
| `uint16_t op` | `kRequest = 1`, `kReply = 2` |
| `Mac senderMac`, `Ipv4 senderIp` | requester / responder |
| `Mac targetMac`, `Ipv4 targetIp` | query target |
| `std::vector<uint8_t> ToBytes() const` | serialize (28 bytes) |
| `static bool TryFromBytes(const std::vector<uint8_t>&, ARP&)` | deserialize (validates header) |
| `static ARP MakeRequest(Ipv4 senderIp, Mac senderMac, Ipv4 targetIp)` | target MAC = zero |
| `static ARP MakeReply(Ipv4 senderIp, Mac senderMac, Ipv4 targetIp, Mac targetMac)` | — |
| `bool IsRequest() const` / `IsReply() const` | op checks |
| `std::string ToString() const`, `operator==` | debug / compare |

### `IpPacket` — `core/IpPacket.hpp`

An IPv4 packet with a simplified (but standard-shaped) 20-byte header.

| Member | Description |
|--------|-------------|
| `uint8_t ttl` | time to live (default `kDefaultTtl = 64`) |
| `uint8_t protocol` | upper-layer protocol (TCP 6 / UDP 17 / ICMP 1) |
| `Ipv4 srcIp`, `Ipv4 dstIp` | addresses |
| `std::vector<uint8_t> payload` | carried bytes |
| `static constexpr uint8_t  kDefaultTtl = 64` | default TTL |
| `static constexpr size_t   kHeaderSize = 20` | header size in bytes |
| `std::vector<uint8_t> ToBytes() const` | 20-byte header + payload |
| `static bool TryFromBytes(const std::vector<uint8_t>&, IpPacket&)` | validates length and `0x45` |
| `void DecTtl()` | decrement TTL, guarding underflow at 0 |
| `bool operator== const`, `std::string ToString() const` | compare / debug |

The checksum, identification, flags, and options are not modeled (set to 0);
version/IHL are fixed to `0x45` (IPv4, 20-byte header). This is sufficient for
routing logic and keeps the codec simple. `ToBytes` throws `std::length_error` if
the payload would overflow the 16-bit total length; `TryFromBytes` validates the
total-length field before slicing the payload.

### `ByteIO` — `core/ByteIO.hpp`

Header-only big-endian (network byte order) helpers shared by `ARP` and
`IpPacket`:

```
AppendU8(buf, v)      AppendU16(buf, v)     AppendIpv4(buf, ip)   AppendMac(buf, mac)
ReadU8(buf, off)      ReadU16(buf, off)     ReadIpv4(buf, off)    ReadMac(buf, off)
```

`Read*` functions assume the caller has already validated the buffer length.

### `Aging` — `core/Aging.hpp`

Header-only generic aging helper shared by the switch MAC table and the ARP
cache:

```
template <class Table>
void AgeOutEntries(Table& table, uint64_t now, uint64_t timeout);
```

Erases entries whose `now - entry.lastSeen > timeout`. The mapped value is
expected to have a `uint64_t lastSeen` member; `now` is passed in by the caller
(no dependency on the engine).

## Device module reference

### `Device` — `device/Device.hpp` (abstract base)

| Member | Description |
|--------|-------------|
| `std::vector<Port*> portList` | owned interfaces |
| `virtual void AddPort(Port*)` | register a port (Router overrides to add connected routes) |
| `virtual void OnFrame(Port*, FramePtr) = 0` | per-device handling |
| `virtual ~Device() = default` | polymorphic destruction |
| (copy deleted) | non-copyable polymorphic base (prevents slicing) |

### `ArpAgent` — `device/ArpAgent.hpp` (shared ARP)

Used by both `EndDevice` and `Router`; owns a time-aged cache and request/reply
handling.

| Member | Description |
|--------|-------------|
| `struct Entry { Mac mac; uint64_t lastSeen; }` | one cache entry |
| `static constexpr uint64_t kTimeout = 300` | cache timeout (clock units) |
| `std::map<Ipv4, Entry> cache` | IP → (MAC, lastSeen) |
| `bool Lookup(Ipv4, Mac&)` | query; refreshes `lastSeen`, drops expired entries |
| `void HandleArp(Port*, const EthernetFrame&)` | age, answer requests, learn replies |
| `void SendArpRequest(Ipv4 targetIp, Port* outPort)` | broadcast a request out of a port |
| `void Learn(Ipv4, const Mac&)` | upsert a mapping and refresh `lastSeen` |
| `void AgeOut(uint64_t now)` | evict stale entries (via `AgeOutEntries`) |

### `EndDevice` — `device/EndDevice.hpp` (host)

| Member | Description |
|--------|-------------|
| `ArpAgent arp` | ARP cache + handling |
| `void OnFrame(Port*, FramePtr) override` | filter, then dispatch ARP |
| `void SendArpRequest(Ipv4 targetIp)` | pick egress port, then ARP request |
| `bool Lookup(Ipv4, Mac&)` | query the ARP cache |

### `Router` — `device/Router.hpp` (Layer-3 router)

| Member | Description |
|--------|-------------|
| `struct Route { Ipv4Subnet dst; Ipv4 nextHop; bool direct; }` | one route |
| `ArpAgent arp` | next-hop ARP resolution |
| `std::vector<Route> routeTable` | routing table |
| `void AddPort(Port*) override` | add port; auto-add a direct route when it has an IP |
| `void OnFrame(Port*, FramePtr) override` | ARP + IPv4 forwarding |
| `void AddRoute(Ipv4Subnet, Ipv4 nextHop, bool direct)` / `AddRoute(const Route&)` | add routes |
| `const Route* FindRoute(Ipv4) const` | longest-prefix match |
| `bool IsMyIp(Ipv4) const` | whether an IP belongs to a local port |
| `Port* PortForNextHop(Ipv4)` | egress port whose subnet contains an IP |

### `Switch` — `device/Switch.hpp` (Layer-2 switch)

| Member | Description |
|--------|-------------|
| `struct Entry { Port* port; uint64_t lastSeen; }` | one MAC-table entry |
| `static constexpr uint64_t kAgingTimeout = 300` | aging threshold (clock units) |
| `std::map<std::pair<uint16_t, Mac>, Entry> macTable` | (VLAN, MAC) → port + timestamp |
| `void OnFrame(Port*, FramePtr) override` | STP / learn / flood / forward with port-state gating |
| `void Emit(Port*, uint16_t vid, FramePtr)` | per-port egress: 802.1Q push/pop + STP gate |
| `void Flood(Port* except, uint16_t vlan, FramePtr)` | send within a VLAN except the ingress |
| `void AgeOut(uint64_t now)` | evict stale entries |
| `SetStpEnabled` / `SetBridgePriority` | enable 802.1D STP / set bridge priority |
| `RecomputeStp` / `HandleBpdu` / `SendBpdu` | root election, port roles, BPDU exchange |
| `stpRootMac`, `stpRootCost`, `stpRootPort` | current root view |
| `void PrintStp() const` | dump root + per-port forwarding/blocking |

### `Port` — `device/Port.hpp` (interface)

| Member | Description |
|--------|-------------|
| `Mac mac` | interface MAC |
| `bool hasIp` | whether an L3 address is configured |
| `Ipv4 ip`, `Ipv4Subnet subnet` | L3 address / subnet (when `hasIp`) |
| `Link* link` | attached link (nullptr if unconnected) |
| `Device* owner` | owning device |
| `void Send(FramePtr)` | hand a frame to the link |
| `void Receive(FramePtr)` | hand a received frame to the device |
| `void SetIp(Ipv4, uint8_t prefix)` | configure L3 address + subnet |
| `void Attach(Link*)` | bind to a link |
| `Port(Mac, Device*, Ipv4, uint8_t prefix, Link*)` | full constructor |

Switch ports typically have `hasIp == false`; host/router ports carry an address.

### `Link` — `link/Link.hpp` (point-to-point wire)

| Member | Description |
|--------|-------------|
| `Port* A`, `Port* B` | the two endpoints |
| `Link(Port*, Port*)` | connect, and make both ports point back at this link |
| `void Transmit(Port* from, FramePtr)` | schedule a delayed delivery to the other endpoint |
| `Port* Other(Port* from) const` | the endpoint opposite `from` (or nullptr) |
| `bool IsConnected() const` | both endpoints present |

## Engine module reference

### `Clock` — `engine/Clock.hpp`

A minimal time source: `virtual uint64_t Now() const = 0`. The `Engine` owns the
simulated time and implements `Clock`. Devices are given a `Clock*` via
`Device::SetClock` (and `ArpAgent` via its own `SetClock`), so no global clock is
used; each simulation is self-contained and deterministic.

### `Event` / `EventQueue` / `Scheduler` — `engine/`

- `Event` — abstract event with `time`, `seq`, `Execute(Engine&)`, `Name()`.
- `EventQueue` — `priority_queue<unique_ptr<Event>>` ordered by `(time, seq)`;
  `Push` / `Pop` / `Top` / `Clear` / `Empty` / `Size`.
- `Scheduler` — narrow interface (`ScheduleAfter`) so `Link` can schedule delayed
  deliveries without depending on the whole engine.

### `Engine` — `engine/Engine.hpp`

Owns the event queue and the simulated clock; implements `Scheduler` and `Clock`;
advances the clock as it processes events (single-threaded, deterministic).
Scenario-level parallelism runs one independent engine per thread, never threads
inside one event loop.

## Wire formats

### ARP (28 bytes, big-endian)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0  | 2 | hardware type = `0x0001` (Ethernet) |
| 2  | 2 | protocol type = `0x0800` (IPv4) |
| 4  | 1 | hardware length = `6` |
| 5  | 1 | protocol length = `4` |
| 6  | 2 | operation (`1` request / `2` reply) |
| 8  | 6 | sender MAC |
| 14 | 4 | sender IP |
| 18 | 6 | target MAC |
| 24 | 4 | target IP |

### IPv4 packet header (20 bytes, big-endian)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0  | 1 | version/IHL = `0x45` |
| 1  | 1 | TOS = `0` |
| 2  | 2 | total length (header + payload) |
| 4  | 2 | identification = `0` |
| 6  | 2 | flags + fragment offset = `0` |
| 8  | 1 | TTL |
| 9  | 1 | protocol |
| 10 | 2 | header checksum = `0` (not modeled) |
| 12 | 4 | source IP |
| 16 | 4 | destination IP |
| 20 | … | payload |

## Building

Build with the Makefile:

```sh
make            # -> ./netsim  (-Wall -Wextra -Werror)
make clean
```

The full quality gate runs the unit tests, parser fuzzing, and the scenario suite
under AddressSanitizer + UndefinedBehaviorSanitizer:

```sh
make test       # -Werror + ASan/UBSan unit + fuzz + scenario suite
make san        # unit + fuzz only, with leak detection
```

`make check` also runs a coverage gate, a bounded-memory soak, and a throughput
floor. Set `WERROR=0` to build without `-Werror`.

Lua 5.4 is bundled under `third_party/lua/` and linked statically into `netsim`
(and the Windows CLI) — no external Lua installation is required. Only a safe
subset is compiled (no `os`, `io`, `package`, or `debug`). See
`THIRD_PARTY_NOTICES.md`.

`make tidy` runs clang-tidy using `.clang-tidy` (advisory; requires clang-tidy).

`make dist` builds the binary and packages `netsim`, `web/`, `win/`, `docs/`,
and licensing into `dist/yanas-net-<version>.tar.gz`. `make install
PREFIX=/usr/local` installs `netsim` and `docs/netsim.1`.

Native Windows build (MinGW-w64; Lua is bundled, no external Lua):

```sh
mingw32-make -f Makefile.win   # -> netsim.exe (CLI)
```

Both executables embed Lua 5.4 statically and carry an icon, version resource, and
DPI-aware manifest. See Packaging below.

Or with CMake:

```sh
cmake -S . -B build
cmake --build build
```

Or directly with `g++`:

```sh
g++ -std=c++17 -Wall -Wextra -Werror core/*.cpp device/*.cpp link/*.cpp \
    engine/*.cpp topo/*.cpp app/main.cpp -o netsim
```

Headers use relative includes (`"../core/..."`), so no `-I` flags are needed.

All build products are written under `build/`: object and dependency files in
`build/obj/<layer>/`, the Lua archive in `build/lua/`, and sanitizer/coverage
binaries in `build/` (coverage uses `build/cov/`). Source directories are never
used as object output, and tests do not delete `build/` automatically.

## Packaging and signing

```sh
make dist                                  # source + binaries tarball (POSIX)
powershell -File packaging\build-win.ps1   # Windows CLI + portable ZIP
```

- `packaging/build-win.ps1` builds `netsim.exe` and writes
  `dist/yanas-net-<ver>-cli-win64.zip` (exe, docs, license/notices).
- `packaging/sign.ps1 -Pfx cert.pfx -Password ...` code-signs `netsim.exe` with
  `signtool` (bring your certificate; timestamped SHA-256).

## Command-line interface

```sh
./netsim                     # interactive prompt (try `demo`)
./netsim scene.yn            # load a scene and exit
./netsim -i scene.yn         # load a scene, then stay interactive
./netsim script.txt          # run a line-command script
./netsim script.lua          # run a Lua script (bundled, sandboxed)
./netsim --help              # options, file types, examples
```

Options: `-h/--help`, `--version`, `--features`, `-q/--quiet`,
`--keep-going`, `--no-lua`, `-i/--interactive`, `--json`, `--log <file>`,
`-f/--file <path>`. Files are chosen by extension: `.yn`/`.json` scene,
`.lua` script, otherwise a `.txt` line-command script.

Exit codes: `0` success, `1` runtime/script error, `2` usage error. Script
errors are reported as `file:line: error: ...` and stop at the first error unless
`--keep-going` is given. Lua scripts run in a restricted sandbox (see Lua
scripting); `--no-lua` disables them entirely. A man page is in `docs/netsim.1`
(`make install` installs the binary and the man page).

`new` resets the scene; `demo` builds a sample 2-host + switch scene and pings it,
so a first run shows a result immediately. On Windows the same CLI is
`netsim.exe`. Editing commands (`remove-device`, `remove-port`, `disconnect`,
`rename-device`, `set-ip`) and `state` (a JSON snapshot) support automation;
Ctrl-C interrupts a running `run`.

Interactive use adds history (`↑`/`↓`), Tab completion (commands and device
names), Home/End, and Ctrl-A/E/U/K, saved to `~/.yanas_history` (Windows uses
plain line input). `--json` emits NDJSON (one record per command plus a final
`summary` carrying the `state`); `--log <file>` also appends those records. Both
require a file argument.

### Limits

Hard caps protect against runaway input: 4096 devices; 65536 ports (1024 per
device); 65536 links; a 5,000,000-event queue (the run halts); pcap 2,000,000
frames / 256 MiB; scripts 16 MiB / 1,000,000 lines; scenes 100,000 commands; Lua
4 MiB / 50M instructions.

Each line is one command (`#` starts a comment):

```
add-device <name> end|switch|router
add-port   <device> <mac> [<ip>/<prefix>]     # no ip = L2 (switch) port
connect    <dev:idx> <dev:idx> [delay]         # e.g. connect PC1:0 SW1:0
add-route  <router> <dst/p> <next-hop-ip>      # static routes (connected auto)
set-vlan   <dev:idx> <vid>                     # access port in VLAN <vid>
set-trunk  <dev:idx> [native-vid]              # 802.1Q trunk (tagged); native default 1
set-stp    <switch> on|off                     # enable/disable spanning tree
set-stp-mode <switch> stp|rstp                 # RSTP-style rapid mode
set-bridge <switch> <priority>                 # bridge priority (default 32768)
stp-status <switch>                            # print root + per-port state
set-link   <dev:idx> down|up                   # bring a link down/up (STP reconverge)
stats      <device>                            # per-port rx/tx/drop counters
devices | links                                # list devices / links
ports      <device>                            # port table (MAC/IP/VLAN/STP/counters)
routes     <router>                            # routing table
arp-table  <device>                            # ARP cache
mac-table  <switch>                            # MAC table
traceroute <device> <target-ip> [max-hops]     # ICMP traceroute
export     dot|svg <file>                      # export topology diagram
udp-echo   <device> on|off [port]              # UDP echo service
udp-send   <device> <ip> <dport> <text...>     # send a UDP datagram
tcp-listen <device> on|off [port]              # real TCP echo service
tcp-connect <device> <ip> <port> [text...]     # real TCP client
tcp-keepalive <device> on [idle interval count]|off
tcp-status <device>                            # connections, RTO/window/counters
tcp-backlog <device> <1-1024>                  # half-open SYN backlog
dhcp-server <device> on <start> <end> <prefix> <gateway> [dns] | off
dhcp-client <device> [port-index]              # acquire a lease
dhcp-relay  <router> <dev:idx> <server-ip>|off # relay DHCP across subnets
dns-server  <device> on|off                    # DNS A/CNAME server
dns-record  <device> <name> <ip>               # add a static A record
dns-cname   <device> <alias> <target>          # add a CNAME
dns-query   <device> [server-ip] <name>        # resolve a name
nat        <router> on <inside-dev:idx> <outside-dev:idx> | off
nat-port   <router> tcp|udp <public-port> <inside-ip> <inside-port>
nat-table  <router>
rip        <router> on|off                     # RIP v2-lite dynamic routing
rip-status <router>                            # routes with metric/next hop
ospf       <router> on|off                     # OSPFv2 (single/multi-area)
ospf-status <router>                           # interfaces, neighbors, LSDB, routes
ospf-auth  <router> none|simple <password>|md5|sha1|sha256 <key-id> <key>
ospf-cost  <router> <dev:idx> <1-65535>          # interface cost
ospf-passive <router> <dev:idx> on|off           # suppress Hellos
ospf-area  <router> <dev:idx> <area-id>          # per-interface OSPF area
ospf-area-type <router> <area-id> stub|nssa|normal    # area policy
ospf-external <router> <ip/prefix> [metric]|clear  # Type 5 external route
tcp-lite-echo   <device> on|off [port]          # deprecated (NOT TCP)
tcp-lite-echo-client <device> <ip> <port> <text...>
acl        <router> in|out allow|deny <src/p> <dst/p> <proto|any>
map                                            # ASCII topology map
generate   tree <depth> <fanout>               # build a large tree topology
remove-device <name>                           # delete a device (and its links)
remove-port   <dev:idx>                        # delete a port (and its link)
disconnect    <dev:idx>                        # remove the link on a port
rename-device <old> <new>                      # rename a device
set-ip     <dev:idx> <ip>/<prefix>             # change a port's IP/subnet
state                                          # print a JSON snapshot
set-gateway <device> <gw-ip>                   # default gateway for a host
arp        <device> <target-ip>                # inject an ARP request
ping       <device> <target-ip> [ttl]          # ICMP echo (auto-ARP, RTT)
run [duration] | step [n] | trace on|off       # bounded run / step / trace
pcap       <file> | pcap off                    # capture frames to a .pcap file
save       <file.yn>                            # export scene (.yn, JSON)
load       <file.yn>                            # build scene from .yn
lookup     <device> <ip>                       # print the device's ARP entry
bench      [n]                                 # measure event throughput
```

Example scene file:

```
add-device PC1 end
add-device PC2 end
add-port PC1 aa:aa:aa:aa:aa:01 192.168.1.1/24
add-port PC2 aa:aa:aa:aa:aa:02 192.168.1.2/24
connect PC1:0 PC2:0
arp PC1 192.168.1.2
```

In file mode the script controls time: call `run` (or `run <duration>`) where you
want the engine to advance. There is no implicit final drain.

## Lua scripting

Lua is bundled (statically linked), so `.lua` files run with no external Lua
installation. A `.lua` file is executed as a scenario and gets three globals:

| Function | Meaning |
|----------|---------|
| `exec(line)` | run one simulator command (same syntax as `.txt` scripts) |
| `run()` | drain the event queue (the `run` command) |
| `log(...)` | print its arguments |

Example (`tests/lua_ping.lua`):

```lua
exec("add-device PC1 end")
exec("add-device PC2 end")
exec("add-port PC1 aa:aa:aa:aa:aa:01 192.168.1.1/24")
exec("add-port PC2 aa:aa:aa:aa:aa:02 192.168.1.2/24")
exec("connect PC1:0 PC2:0")

for i = 1, 2 do
    exec("ping PC1 192.168.1.2")
    run()
end
```

Lua adds loops, variables, tables, and conditionals on top of the line commands,
which is what makes large or parameterized scenarios practical.

Lua runs in a restricted sandbox by default: only the base library (minus
`dofile`, `load`, `loadfile`, `require`), plus `string`, `table`, `math`, `utf8`,
and `coroutine` are available. `os`, `io`, `package`, and `debug` are not loaded,
so scripts cannot spawn processes, open files directly, or load native modules. A
per-run instruction budget (50M instructions) and a 4 MiB script-size limit stop
runaway scripts. `--no-lua` disables Lua entirely.

## Capture and configuration

- `pcap <file>` captures every frame transmitted on a link into a standard pcap
  file (Ethernet link type); `pcap off` stops and reports the frame count.
- `save <file.yn>` exports the scene (devices, ports, links, STP, routes,
  gateways) to a `.yn` file (JSON content); `load <file.yn>` replays it. Scenes may
  also carry an optional `layout` array (ignored by the CLI). See `tests/config.yn`.
- `run [duration]` advances at most `duration` time units (default 1000) or until
  the queue is empty. The bound keeps periodic STP Hello timers from running
  forever; scripts must call `run` explicitly (there is no implicit final drain).

## Testing

Three layers of tests, all runnable with `make test`:

- `tests/unit/unit_tests.cpp` — unit tests for the codecs and addressing
  (`Ipv4`, `Ipv4Subnet`, `Mac`, `ARP`, `IpPacket`, `IcmpMessage`,
  `EthernetFrame` incl. 802.1Q), TCP option/reliability behaviour and OSPF
  packet/LSA checksums (357 checks), built with `-Werror` + ASan/UBSan.
- `tests/fuzz_parsers.cpp` — deterministic fuzzing of every byte parser; must
  stay ASan/UBSan-clean.
- `tests/*.txt` scenarios — each `NAME.txt` is a scene and `NAME.want` a substring
  the output must contain (the runner also fails on `fatal:` and applies a
  timeout). Scenarios cover ARP, auto-ARP ping, ping timeout/RTT, TTL exceeded,
  ICMP unreachable, cross-subnet routing, VLAN isolation, 802.1Q trunking, STP
  loop prevention / reconvergence, port counters, JSON save/load, pcap capture,
  RSTP, TCP (direct/router/loss), DHCP/DNS, NAT, RIP, and OSPF
  (adjacency/Full/loss/authentication).
- `tests/lua_ping.lua` — a Lua scenario (loop + `exec` + `run`) when Lua is built.

```sh
make test                 # unit + fuzz (ASan/UBSan) + every scenario
bash tests/run_tests.sh   # scenarios only
```

On Windows, build with MinGW and run the PowerShell test runner:

```powershell
mingw32-make -f Makefile.win
powershell -ExecutionPolicy Bypass -File tests\run_tests.ps1
```

The PowerShell runner executes every `tests\*.txt` against its `.want`, the Lua
scenarios when Lua is present, and all examples.

Go tooling is optional (the simulator hot path remains C++17), organized into
`cmd/` entry points plus `internal/` packages:

```powershell
mingw32-make -f Makefile.win tools
mingw32-make -f Makefile.win gotest
.\build\ynstress.exe -exe .\netsim.exe -repeat 2 -jobs 4
.\build\ynpcap.exe capture.pcap
```

`ynstress` repeats scenario suites in parallel. `ynpcap` validates a capture's
IPv4/TCP/OSPF headers, checksums, TCP handshake flow, SYN options (MSS/WS/SACK/
timestamps), and OSPF packet/LSA checksums; with `-ospf-key` it verifies OSPF MD5
digests. It exits non-zero on any issue.

`make check` adds a coverage gate (about 57% now, floor 54%), a bounded-memory soak
(256 MiB address-space cap with STP reconvergence), and a throughput floor.

## Quick start

A minimal program that connects two hosts and resolves one IP to a MAC:

```cpp
#include "EndDevice.hpp"
#include "Port.hpp"
#include "Link.hpp"
#include "Ipv4.hpp"
#include "Mac.hpp"
#include <iostream>

int main()
{
    EndDevice hostA, hostB;

    Port pa(Mac("aa:aa:aa:aa:aa:01"), &hostA, Ipv4("192.168.1.1"), 24, nullptr);
    Port pb(Mac("aa:aa:aa:aa:aa:02"), &hostB, Ipv4("192.168.1.2"), 24, nullptr);

    hostA.AddPort(&pa);
    hostB.AddPort(&pb);

    Link link(&pa, &pb);                 // also wires pa.link and pb.link

    hostA.SendArpRequest(Ipv4("192.168.1.2"));   // broadcast -> reply -> cache

    Mac resolved;
    if (hostA.Lookup(Ipv4("192.168.1.2"), resolved))
        std::cout << "192.168.1.2 is " << resolved.ToString() << "\n";
}
```

Compile (assuming the snippet is `app/main.cpp`):

```sh
g++ -std=c++17 -Wall -Wextra -Icore -Idevice -Iengine \
    core/*.cpp device/*.cpp app/main.cpp -o netsim
```

## Examples and user guide

- `examples/` — runnable scenes and scripts (`01_two_hosts.txt`, `03_router.txt`,
  `04_stp.txt`, `05_lua.lua`, `06_scene.yn`, ...).
- `docs/USER_GUIDE.md` — a student-oriented walkthrough.
- `CONTRIBUTING.md` and `SECURITY.md` — how to build/contribute and the sandbox.
- License: GNU GPL v3.0 or later (`LICENSE`, `COPYRIGHT`, `SOURCE-CODE.md`).

## Behavior details

### Address filtering (host)

A received frame is accepted only if its destination MAC equals the receiving
port's MAC **or** is the broadcast address:

```cpp
if (!(port->mac == frame.dst) && !frame.IsBroadcast())
    return;   // not for me
```

### ARP on a host

- **Request** — if the target IP belongs to this port, build a reply whose sender
  is this port (IP/MAC) and whose target is the requester, then send it as a
  **unicast** frame to the requester's MAC.
- **Reply** — record `senderIp -> senderMac` in the ARP cache.

`SendArpRequest` picks the egress port whose subnet contains the target IP and
sends an ARP request as an Ethernet **broadcast**.

### Switch forwarding

For every received frame the switch:

1. **Learns** the source MAC → ingress port (only for unicast sources).
2. If the destination is a **group address** (I/G bit set), **floods** it (all
   ports except the ingress).
3. Otherwise looks up the destination in the MAC table:
   - known and egress ≠ ingress → forward out that port;
   - unknown → flood;
   - known but egress == ingress → drop.

### MAC-table aging

Each entry stores `lastSeen`. `OnFrame` calls `AgeOut(now)` before learning, which
erases entries whose age exceeds `kAgingTimeout`. Learning refreshes `lastSeen`,
so active stations never expire. Time comes from the engine's `Clock`, keeping runs
deterministic.

### Router forwarding

For a received frame the router:

1. Accepts frames addressed to its port MAC or to the broadcast address.
2. Dispatches ARP to its `ArpAgent`.
3. For IPv4: parses the packet; if the destination is one of its own port IPs it
   is local (currently ignored). Otherwise, drop if TTL ≤ 1, decrement TTL, and do
   a longest-prefix lookup in the routing table. The next hop is the destination
   itself for `direct` routes, else `route.nextHop`. The egress port is the one
   whose subnet contains the next hop. If the next-hop MAC is unknown, the router
   holds the packet in a per-next-hop pending queue and sends an ARP request; once
   the ARP reply is learned, `FlushPending` sends the held packets. Otherwise it
   rewrites the Ethernet header (destination = next-hop MAC, source = egress port
   MAC) and transmits.

Connected subnets are added automatically as `direct` routes when a port with an
IP is added (`Router::AddPort`).

## Design notes

- **Network byte order.** Multi-byte integers are written big-endian through
  `ByteIO`. Encoder and decoder share a single layout, so round-trips are exact.
- **TryParse convention.** Parsing untrusted text returns `bool` (out parameter);
  convenience string constructors call it and throw on failure.
- **Forward declarations.** Headers reference other modules only by pointer where
  possible; `.cpp` files include the definitions they use. This breaks the
  `Port` / `Link` / `Device` include cycle.
- **Polymorphic devices.** `Device` has a pure virtual `OnFrame` and a virtual
  destructor. Concrete devices implement only their packet handling, so a single
  `Port` works with any device type.
- **Engine-owned time.** Each `Engine` owns its clock (implements `Clock`) and
  advances it while processing events; nothing depends on the wall clock, so runs
  are reproducible.
- **Scenario-level parallelism.** Independent simulations run as separate engines
  (one per thread/process); the core event loop stays single-threaded and no
  mutable state is shared across simulations.
- **Shared components.** `ArpAgent` (ARP behavior), `ByteIO` (big-endian codec),
  and `Aging` (map-entry aging) are reused to avoid duplication.
- **Comment-free sources.** `.cpp` / `.hpp` files contain no comments; all design
  and behavior documentation lives in this README and `DEVELOPMENT_LOG.md`.
- **Non-copyable polymorphic base.** `Device` deletes its copy operations to
  prevent slicing; devices are held by pointer.
- **Encapsulated bit tests.** `Mac::IsGroup()` hides the I/G bit check used by the
  switch for learning and flooding.
- **Shared immutable frames.** Frames travel as `FramePtr`
  (`shared_ptr<const EthernetFrame>`); forwarding and flooding share one frame, so
  the hot path does not copy payloads.
- **Throttled aging.** The switch sweeps its MAC table at most once every
  `kSweepInterval`, not on every frame.

## Status and roadmap

Implemented:

- [x] `Ipv4`, `Ipv4Subnet`, `Mac`
- [x] `ByteIO` shared big-endian codec
- [x] `EthernetFrame`, `ARP`, `IpPacket`
- [x] `Port`, `Link`, `Device` base
- [x] `EndDevice` (ARP host)
- [x] `Switch` (learning, flooding, forwarding, aging)
- [x] `Router` (longest-prefix routing, TTL, next-hop ARP, MAC rewrite,
      automatic connected routes)
- [x] Shared `ArpAgent` (time-aged ARP cache)
- [x] Shared `Aging` helper (`core/Aging.hpp`)
- [x] Router: ARP pending-packet queue (hold until the next hop resolves)
- [x] `Event`, `EventQueue`, `Scheduler`, `Clock` (engine building blocks)
- [x] `Engine` (event loop + engine-owned time)
- [x] `FrameDelivery` + event-driven `Link` (delayed delivery)
- [x] `FramePtr` shared immutable frames (no payload copies on forward/flood)
- [x] Switch aging throttled (`kSweepInterval`)
- [x] Topology builder (`topo/`) — owns devices/ports/links, injects clock/scheduler
- [x] CLI (`app/`) — interactive prompt + `.txt` script, shared command interpreter
- [x] End-to-end: ARP round trip over the event-driven pipeline
- [x] VLAN (port-based) + 802.1Q trunk tagging (real TPID/TCI frames)
- [x] ICMP echo (ping) between hosts
- [x] Packet/event tracing (`trace on|off`)
- [x] Makefile build (`make` → `./netsim`)
- [x] CMake build (`CMakeLists.txt`)
- [x] Host default gateway — cross-subnet ping through a router
- [x] Event-throughput benchmark (`bench [n]`; ~5.9M events/s → no pool needed)
- [x] Regression test suite (`tests/run_tests.sh`)
- [x] Quality gate: `-Werror`, ASan/UBSan unit tests, deterministic parser fuzzing
- [x] Bounded resources: router ARP pending cap/timeout, `bench` input clamp
- [x] Spanning Tree (STP): root election, Blocking/Learning/Forwarding (forward delay)
- [x] ICMP Time Exceeded / unreachable, ping timeout + RTT, host auto-ARP
- [x] Lua scripting (real Lua 5.4; `exec` / `run` / `log`)
- [x] CI (gcc/clang matrix) + `.clang-tidy` config
- [x] STP link-failure reconvergence (`set-link down|up`) with MAC flush
- [x] Per-port rx/tx/drop counters (`stats <device>`)
- [x] STP Hello/Max-Age keepalives + RSTP-style rapid mode
- [x] pcap frame capture (`pcap <file>` / `pcap off`)
- [x] JSON topology save/load (`save` / `load`)
- [x] Bounded `run [duration]` (safe with periodic timers)
- [x] Makefile header dependency tracking (`-MMD -MP`)
- [x] Windows CLI (`netsim.exe`) with bundled Lua, icon and version resource
- [x] Editing: `remove-device` / `remove-port` / `disconnect` / `rename-device` / `set-ip`
- [x] `state` JSON snapshot; Ctrl-C interrupts a running `run`
- [x] Diagnostics (`devices`/`links`/`ports`/`routes`/`arp-table`/`mac-table`),
      `traceroute`, and topology `export dot|svg`
- [x] UDP datagrams + host echo service; `map` and `generate tree` for scale
- [x] Experimental `tcp-lite` (NOT TCP); ACLs; `help <command>`; link impairment;
      TCP checksum/options groundwork
- [x] Real TCP stack exposed: handshake, data, RTO retransmission, FIN/TIME_WAIT,
      congestion control; `tcp-listen`/`tcp-connect`; loss-driven retransmission tests
- [x] DHCP client/server with relay and DNS A/CNAME server/resolver over UDP
- [x] Source NAT/PAT and port forwarding (DNAT) on routers
- [x] RIP v2-lite dynamic routing (broadcast updates, split horizon, timers)
- [x] OSPFv2: RFC packets, DR/BDR, per-area LSDB, SPF, ABR Type 3/4 summaries,
      Type 5 external routes with withdrawal, stub/NSSA areas with Type 7
      translation/withdrawal, cost/passive, MD5/SHA-1/SHA-256 auth
- [x] Hard resource caps (topology, event queue, pcap, scripts, scenes)
- [x] Interactive line editing, history, and Tab completion
- [x] `--json` NDJSON + `--log` structured output
- [x] `make check`: coverage gate, bounded soak, throughput floor; CI check/macOS jobs
- [x] Packaging: portable CLI ZIP (`packaging/build-win.ps1`) + `signtool` script;
      Windows CI job building `netsim.exe`
- [x] Scene workflow: `save`/`load` `.yn`, `new` reset
- [x] Productized CLI: `--help/--version/--features`, stable exit codes,
      `file:line` script errors, `--quiet`, `--keep-going`, `-i`, `--no-lua`,
      direct `.yn` loading, `demo`/`new`, man page (`docs/netsim.1`)
- [x] Open source under GNU GPLv3 (`LICENSE`, `COPYRIGHT`, `SOURCE-CODE.md`)
- [x] Examples, student user guide, CONTRIBUTING, and SECURITY docs
- [x] `VERSION`, `CHANGELOG.md`, `make dist` / `make install` packaging

Planned:

- [ ] TCP: real-stack interoperability and PCAP conformance verification.
- [ ] OSPF virtual links, IPv6, full RSTP.
- [ ] Scale/engineering: `--jobs` parallel scenarios, `src/` restructure, CMake
      presets, three-platform CI.
- [ ] Full IEEE 802.1w proposal/agreement (current RSTP mode is a rapid subset)
- [ ] clang-tidy enforcement (advisory CI job present; needs tuning / compile DB)
- [ ] Observability: drop-reason breakdown (counters done)
- [ ] Event allocator/pool — only if a real workload justifies it (single-thread
      throughput already far exceeds simulator load)

---

## License

yanas net is free software under the **GNU General Public License v3.0 or later**
(see `LICENSE` and `COPYRIGHT`). Because binaries are distributed under the GPL,
the corresponding source is provided in `yanas-net-<version>.tar.gz` and in the
source archive shipped inside the Windows ZIP (see `SOURCE-CODE.md`). The bundled
Lua 5.4.6 is MIT-licensed and GPL-compatible; its notice is in
`THIRD_PARTY_NOTICES.md`.
