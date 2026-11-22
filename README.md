# Network Simulator (C++)

A terminal-based network simulator written in C++17 that models Layer-2 and
Layer-3 networking: IPv4 addressing and subnets, Ethernet frames, ARP, MAC-
learning switches, and IPv4 packets. Devices share a common base class and
communicate through ports connected by point-to-point links, driven by a
deterministic logical clock.

The code is intentionally small, dependency-free, and readable. Every protocol
has its own value type with a byte-level codec so it can be carried inside an
Ethernet frame, which keeps the simulation faithful to how real networks move
data (a frame carries an ARP message or an IPv4 packet in its payload).

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
- IPv4 packets with a 20-byte header, TTL handling, and a byte codec.
- Ports and point-to-point links with automatic back-reference wiring.
- Host behavior: ARP resolution and an ARP cache.
- Switch behavior: MAC learning, flooding, unicast forwarding, MAC-table aging.
- Router behavior: longest-prefix routing table, TTL handling, next-hop ARP,
  MAC-header rewrite, and automatic connected routes per configured port.
- Shared ARP agent for hosts and routers (time-based cache aging + request/reply).
- A logical simulation clock for deterministic, time-based behavior.

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
| engine layer   SimClock (logical time)                       |
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

Transmission is a straight pipeline; every device type only implements
`OnFrame`.

```
1. A device builds an EthernetFrame (dst MAC, src MAC, type, payload).
2. device -> port->Send(frame)
3. Port::Send          -> link->Transmit(this, frame)
4. Link::Transmit      -> peerPort->Receive(frame)      (the *other* endpoint)
5. Port::Receive       -> owner->OnFrame(this, frame)   (virtual dispatch)
6. Device::OnFrame     -> inspect frame.type and handle (e.g. ARP, IPv4)
```

Because `Port::Receive` calls `owner->OnFrame`, and `owner` is a `Device*`, a
single `Port` implementation can serve a host, a switch, or a router. The port
does no protocol logic; it only moves frames between the device and the link.

## Project structure

```
Internet/
├── .vscode/                 # VS Code IntelliSense configuration
├── app/                     # CLI / application entry point (planned)
├── core/                    # protocol data types
│   ├── ByteIO.hpp           # big-endian read/write helpers (header-only)
│   ├── Aging.hpp            # generic map-entry aging helper (header-only)
│   ├── Ipv4.hpp / .cpp
│   ├── Ipv4Subnet.hpp / .cpp
│   ├── Mac.hpp / .cpp
│   ├── EthernetFrame.hpp / .cpp
│   ├── ARP.hpp / .cpp
│   └── IpPacket.hpp / .cpp
├── device/                  # networked devices and interfaces
│   ├── Device.hpp / .cpp    # abstract base
│   ├── ArpAgent.hpp / .cpp  # shared ARP cache + request/reply
│   ├── EndDevice.hpp / .cpp # host
│   ├── Switch.hpp / .cpp    # Layer-2 switch
│   ├── Router.hpp / .cpp    # Layer-3 router
│   ├── Port.hpp / .cpp
│   └── Link.hpp / .cpp
├── engine/                  # simulation engine
│   └── SimClock.hpp         # logical clock (header-only)
├── link/                    # reserved (planned)
├── topo/                    # reserved (planned)
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
| `static Mac Zero()` / `Broadcast()` | `00:00:00:00:00:00` / `ff:ff:ff:ff:ff:ff` |

The least-significant bit of the first octet is the I/G bit (1 = group address);
switches use it to decide learning and flooding.

### `EthernetFrame` — `core/EthernetFrame.hpp`

A Layer-2 frame. The payload is opaque bytes so any protocol can ride inside.

| Member | Description |
|--------|-------------|
| `Mac dst`, `Mac src` | destination / source MAC |
| `uint16_t type` | EtherType |
| `std::vector<uint8_t> payload` | carried bytes |
| `static constexpr uint16_t kIPv4 = 0x0800` | IPv4 EtherType |
| `static constexpr uint16_t kARP  = 0x0806` | ARP EtherType |
| `bool IsBroadcast() const` | `dst == Mac::Broadcast()` |
| `bool operator== const` | compares all fields incl. payload |
| `std::string ToString() const` | debug form |

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
routing logic and keeps the codec simple.

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
| `virtual void OnFrame(Port*, const EthernetFrame&) = 0` | per-device handling |
| `virtual ~Device() = default` | polymorphic destruction |

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
| `void OnFrame(Port*, const EthernetFrame&) override` | filter, then dispatch ARP |
| `void SendArpRequest(Ipv4 targetIp)` | pick egress port, then ARP request |
| `bool Lookup(Ipv4, Mac&)` | query the ARP cache |

### `Router` — `device/Router.hpp` (Layer-3 router)

| Member | Description |
|--------|-------------|
| `struct Route { Ipv4Subnet dst; Ipv4 nextHop; bool direct; }` | one route |
| `ArpAgent arp` | next-hop ARP resolution |
| `std::vector<Route> routeTable` | routing table |
| `void AddPort(Port*) override` | add port; auto-add a direct route when it has an IP |
| `void OnFrame(Port*, const EthernetFrame&) override` | ARP + IPv4 forwarding |
| `void AddRoute(Ipv4Subnet, Ipv4 nextHop, bool direct)` / `AddRoute(const Route&)` | add routes |
| `const Route* FindRoute(Ipv4) const` | longest-prefix match |
| `bool IsMyIp(Ipv4) const` | whether an IP belongs to a local port |
| `Port* PortForNextHop(Ipv4)` | egress port whose subnet contains an IP |

### `Switch` — `device/Switch.hpp` (Layer-2 switch)

| Member | Description |
|--------|-------------|
| `struct Entry { Port* port; uint64_t lastSeen; }` | one MAC-table entry |
| `static constexpr uint64_t kAgingTimeout = 300` | aging threshold (clock units) |
| `std::map<Mac, Entry> macTable` | MAC → port + timestamp |
| `void OnFrame(Port*, const EthernetFrame&) override` | learn, flood, forward |
| `void Flood(Port* except, const EthernetFrame&)` | send to all ports except one |
| `void AgeOut(uint64_t now)` | evict stale entries |

### `Port` — `device/Port.hpp` (interface)

| Member | Description |
|--------|-------------|
| `Mac mac` | interface MAC |
| `bool hasIp` | whether an L3 address is configured |
| `Ipv4 ip`, `Ipv4Subnet subnet` | L3 address / subnet (when `hasIp`) |
| `Link* link` | attached link (nullptr if unconnected) |
| `Device* owner` | owning device |
| `void Send(const EthernetFrame&)` | hand a frame to the link |
| `void Receive(const EthernetFrame&)` | hand a received frame to the device |
| `void SetIp(Ipv4, uint8_t prefix)` | configure L3 address + subnet |
| `void Attach(Link*)` | bind to a link |
| `Port(Mac, Device*, Ipv4, uint8_t prefix, Link*)` | full constructor |

Switch ports typically have `hasIp == false`; host/router ports carry an address.

### `Link` — `device/Link.hpp` (point-to-point wire)

| Member | Description |
|--------|-------------|
| `Port* A`, `Port* B` | the two endpoints |
| `Link(Port*, Port*)` | connect, and make both ports point back at this link |
| `void Transmit(Port* from, const EthernetFrame&)` | forward to the other endpoint |
| `Port* Other(Port* from) const` | the endpoint opposite `from` (or nullptr) |
| `bool IsConnected() const` | both endpoints present |

## Engine module reference

### `SimClock` — `engine/SimClock.hpp` (logical clock)

```
namespace SimClock {
    uint64_t Now();
    void     Advance(uint64_t delta);
    void     Reset();
}
```

A single monotonic counter advanced by the engine (or by a test). Time-dependent
behavior such as MAC-table aging reads `Now()`, so results are reproducible and
do not depend on wall-clock time.

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

No build system is included yet; the sources are plain C++17. Compile every
module to object files:

```sh
g++ -std=c++17 -Wall -Wextra -c core/*.cpp device/*.cpp
```

Or compile a program together with all module sources (see Quick start). Headers
use relative includes (`"../core/..."`), so no `-I` flags are needed when the
`.cpp` files are compiled from their own directories.

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
so active stations never expire. Time comes from `SimClock`, keeping runs
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
- **Deterministic time.** `SimClock` is a logical counter; nothing depends on the
  wall clock.
- **Shared components.** `ArpAgent` (ARP behavior), `ByteIO` (big-endian codec),
  and `Aging` (map-entry aging) are reused to avoid duplication.
- **Comment-free sources.** `.cpp` / `.hpp` files contain no comments; all design
  and behavior documentation lives in this README and `DEVELOPMENT_LOG.md`.

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
- [x] `SimClock` logical clock

Planned:

- [ ] VLAN support
- [ ] Topology builder (`topo/`) to assemble devices and links
- [ ] Event-driven engine and packet tracing
- [ ] CLI application (`app/`) and a build system (Makefile/CMake)

---

No license file is included yet. All code is provided as-is for learning and
experimentation.
