# yanas net — operator guide

An operator-oriented walkthrough. For the full command reference and design
notes see the top-level `README.md`.

## 1. What it is

yanas net is an engineering-grade deterministic Layer-2/Layer-3 network
simulator for building and validating offline network scenarios.
You build a network out of hosts, switches, and routers, then send traffic
(ARP, ICMP) and inspect the result. It is terminal-first, scriptable, and ships
with an embedded (Lua) scripting engine. Results are reproducible because time
is a logical clock.

TCP, DHCP, DNS, and routing behavior are simulator implementations evaluated
offline. They are not live-wire stacks, production replacements, or bridges to a
real network; all traffic stays inside the simulated topology.

## 2. Build and run

Linux/macOS/WSL:

```sh
make
./netsim
```

Windows (PowerShell, MinGW-w64):

```powershell
mingw32-make -f Makefile.win
.\netsim.exe
```

The interactive prompt supports history (`↑`/`↓`), Tab completion (commands and
device names), Home/End, and Ctrl-A/E/U/K. `Ctrl-C` cancels the current line, or
interrupts a running `run`.

Type `demo` for an instant working example, or `help` for commands.

## 3. Ways to drive it

| Input | Meaning |
|-------|---------|
| interactive prompt | type commands one at a time |
| `*.txt` | a script of commands, one per line (`#` comments) |
| `*.lua` | a Lua scenario (`exec`, `run`, `log`) |
| `*.yn` | a JSON scene (topology + optional layout) |

```sh
./netsim examples/01_two_hosts.txt
./netsim examples/05_lua.lua
./netsim examples/06_scene.yn
```

## 4. Core concepts

- **Device**: `end` (host), `switch`, or `router`.
- **Port**: a device interface with a MAC; hosts/routers also have IP/prefix.
- **Link**: connects exactly two ports.
- **VLAN**: access ports belong to one VLAN (`set-vlan`); trunks carry tags
  (`set-trunk`).
- **STP**: spanning tree blocks redundant links (`set-stp on`, `stp-status`).
- **Routing**: routers use longest-prefix static routes; connected subnets are
  automatic. Hosts use a default gateway (`set-gateway`).

## 5. Command cheat sheet

```
add-device <name> end|switch|router
add-port   <device> <mac> [<ip>/<prefix>]
connect    <dev:idx> <dev:idx> [delay]
add-route  <router> <dst/p> <next-hop-ip>
add-route6 <router> <dst6/prefix> <next-hop-ip6>
set-gateway <device> <gw-ip>
set-gateway6 <device> <gw-ipv6>
set-vlan   <dev:idx> <vid>
set-trunk  <dev:idx> [native-vid]
set-stp    <switch> on|off
set-stp-mode <switch> stp|rstp
set-bridge <switch> <priority>
stp-status <switch>
span       <switch> <src-dev:idx> <dst-dev:idx> | off
set-link   <dev:idx> down|up|loss|dup|jitter|mtu|clear
remove-device <name>
remove-port   <dev:idx>
disconnect    <dev:idx>
rename-device <old> <new>
set-ip     <dev:idx> <ip>/<prefix>
set-ip6    <dev:idx> <ipv6>[/prefix]
arp        <device> <target-ip>
ping       <device> <target-ip> [ttl]
ping6      <device> <ipv6>
traceroute <device> <target-ip> [max-hops]
traceroute6 <device> <ipv6> [max-hops]
run [duration] | wait [duration] | step [n] | trace on|off
lookup     <device> <ip>
stats      <device>
devices | links | ports <device> | routes <router> | routes6 <router>
arp-table <device> | mac-table <switch>
export     dot|svg <file>
udp-echo   <device> on|off [port]
udp-send   <device> <ip> <dport> [df] <text...>
tcp-listen <device> on|off [port]
tcp-connect <device> <ip> <port> [text...]
tcp-send   <device> <text...>
tcp-keepalive <device> on [idle interval count]|off
tcp-status <device>
tcp-backlog <device> <1-1024>
tcp-congestion <device> reno|cubic
tcp-tlp <device> on|off
tcp-prr <device> on|off
tcp-rack <device> on|off
tcp-pacing <device> on|off
tcp-port-range <device> <min> <max>
ecn-mark <router> <dev:idx> on|off
dhcp-server <device> on <start> <end> <prefix> <gateway> [dns] | off
dhcp-client <device> [port-index]
dhcp-lease-time <device> <seconds>
dhcp-release <device>
dhcp-relay  <router> <dev:idx> <server-ip>|off
dns-server <device> on|off
dns-ttl    <device> <seconds>
dns-negative-ttl <device> <seconds>
dns-cache-size <device> <entries>
dns-ttl-bounds <device> <min> <max>
dns-record <device> <name> <ip> [ttl]
dns-aaaa   <device> <name> <ipv6> [ttl]
dns-cname  <device> <alias> <target> [ttl]
dns-mx     <device> <name> <preference> <exchange> [ttl]
dns-zone   <device> <zone>
dns-secondary <device> <zone> <primary-ip>
dns-notify-target <device> <zone> <ip> [ip...]
dns-notify <device> <zone>
dns-ns     <device> <owner> <nameserver>
dns-soa    <device> <zone> <mname> <rname> [ttl serial refresh retry expire minimum]
dns-query  <device> [server-ip] <name> [A|AAAA|NS|SOA|PTR|MX]
dns-axfr   <device> <server-ip> <zone>
dns-ixfr   <device> <server-ip> <zone> <serial>
dns-axfr-allow <device> <ip> [ip...] | any|none
dns-tsig   <device> <key-name> <secret> [md5|sha1|sha256]
dns-tsig-require <device> on|off
dns-update-allow <device> <ip> [ip...] | any|none
dns-update-add <device> <server-ip> <zone> <name> <ip> [ttl]
dns-update-del <device> <server-ip> <zone> <name> [A|ANY]
dns-update-check <device> <server-ip> <zone> <name> <ip>
dns-resolver <device> <ip> [ip...] | off
dns-retry  <device> <timeout> <attempts>
nat        <router> on <inside-dev:idx> <outside-dev:idx> | off
nat-port   <router> tcp|udp <public-port> <inside-ip> <inside-port>
nat-table  <router>
rip        <router> on|off
rip-status <router>
ospf       <router> on|off
ospf-status <router>
ospf-router-id <router> <id>
ospf-auth  <router> none|simple <password>|md5|sha1|sha256 <key-id> <key>
ospf-cost  <router> <dev:idx> <1-65535>
ospf-passive <router> <dev:idx> on|off
ospf-external <router> <ip/prefix> [metric]
ospf-default-originate <router> on|off [metric] [type1|type2]
ospf-redistribute <router> connected|static|off [metric] [type1|type2]
ospf-area  <router> <dev:idx> <area-id>
ospf-area-type <router> <area-id> stub|nssa|normal
ospf-summary <router> <area-id> <prefix> [not-advertise] | clear
tcp-lite-echo   <device> on|off [port]
tcp-lite-echo-client <device> <ip> <port> <text...>
acl        <router> in|out allow|deny <src/p> <dst/p> <proto|any>
acl6       <router> in|out allow|deny <src6/p> <dst6/p> <proto|any>
map | generate tree <depth> <fanout>
state
pcap       <file> | pcap off
save       <file.yn> | load <file.yn>
new | demo | bench [n] | quit | help
```

## 6. Worked examples

The `examples/` directory has runnable files. A few:

**Two hosts, one link.** ARP resolves automatically, then ICMP works:

```
add-device PC1 end
add-device PC2 end
add-port PC1 aa:aa:aa:aa:aa:01 192.168.1.1/24
add-port PC2 aa:aa:aa:aa:aa:02 192.168.1.2/24
connect PC1:0 PC2:0
ping PC1 192.168.1.2
run
```

IPv6 hosts use `set-ip6 PC1:0 2001:db8:1::1/64` and
`set-ip6 PC2:0 2001:db8:2::2/64`; routers get addresses on each interface and
automatically install connected IPv6 routes. Hosts use
`set-gateway6 PC1 2001:db8:1::254`; add static routes with
`add-route6 R1 2001:db8:3::/64 2001:db8:2::2`. `ping6` resolves next hops with
NDP, `routes6 R1` prints the IPv6 table, `nd6-table R1` prints resolved IPv6
neighbors, and `traceroute6` walks IPv6 hops. Routers return ICMPv6
unreachable/time-exceeded errors; unanswered `ping6` reports
`ping6 timeout from <target> seq=<n>`.

**Switch and VLAN.** Assign both switch ports to VLAN 10 (`set-vlan SW1:0 10`).
Hosts in different VLANs cannot reach each other until you bridge them with a
router or trunk.

**Router.** Put a router between `192.168.1.0/24` and `192.168.2.0/24`, set each
host's gateway to the router interface, then `ping PC1 192.168.2.1`.

**STP.** Connect three switches in a triangle, `set-stp` on, `run`, then ping: one
link is blocked and traffic still flows. `set-link SW3:1 down` and `run` to watch
reconvergence. **SPAN.** `span SW1 SW1:0 SW1:2` mirrors frames received on port 0
to port 2; `span SW1 off` clears it.

## 7. Automation

`traceroute <dev> <ip>` sends probes with increasing TTL and prints each hop, so
you can see the path a packet takes. Diagnostics: `devices`, `links`,
`ports <dev>`, `routes <router>`, `routes6 <router>`, `arp-table <dev>`,
`nd6-table <dev>`, `mac-table <switch>`, `stats <dev>`, and `drop-stats <dev>`
(per-port drop reasons such as acl, mtu, loss, ttl, no-route, and vlan).
`export dot <file>` writes a Graphviz graph; `export svg <file>` writes an SVG
diagram you can open in a browser. `map` prints a terminal adjacency map.
`generate tree <depth> <fanout>` builds a large switch tree with one host per
leaf (for scale experiments). UDP echo: `udp-echo PC2 on 7` then
`udp-send PC1 10.0.0.2 7 hello` and `run`. Add `df` before the text to set the
Don't Fragment bit; an oversized datagram on a router path reports
`icmp frag needed from <router> mtu=<bytes>`. Real TCP: `tcp-listen PC2 on 80`
then `tcp-connect PC1 10.0.0.2 80 hello` performs a three-way handshake, sends
the text reliably (RTO retransmission, congestion control), and the service
echoes it back. `tcp-send PC1 more data` appends data on an established
connection. TCP segments use DF; ICMP Fragmentation Needed lowers the path MTU,
re-segments unacked data, and after a hold interval the path MTU is re-probed
upward when new data is sent. `tcp-status` shows `mss=` and `pmtu=`.
The older `tcp-lite-*` commands remain as a deprecated legacy
transport and are **not** TCP. DHCP/DNS: on a server host use
`dhcp-server SRV on 10.0.0.100 10.0.0.110 24 10.0.0.1 10.0.0.1`,
`dns-server SRV on`, and `dns-record SRV example.com 10.0.0.1`. A host with an
unconfigured port runs `dhcp-client PC1 0`, then `dns-query PC1 example.com`
uses the DNS server supplied by DHCP. For a server on another subnet, attach a
relay to the client-facing router port: `dhcp-relay R1 R1:0 10.1.0.2`. DNS
supports multiple A records and CNAMEs (`dns-cname SRV www.example.com example.com`);
`dns-aaaa SRV host.example.com 2001:db8::5` publishes AAAA records (DNS data
plane; IPv6 routing is a separate stack concern). `dns-ttl SRV 300` sets answer TTLs and clients cache until expiry. `wait 300`
advances the clock during idle periods (useful for TTL/timeout tests). NXDOMAIN
responses carry an SOA and are negatively cached for
`dns-negative-ttl SRV 100` seconds. NODATA is distinguished from NXDOMAIN and
cached separately. Queries advertise EDNS0 (1232-byte UDP); if a response is
truncated (`TC`), the client automatically retries over TCP port 53 and prints
`dns: truncated; retrying over TCP`. `dns-resolver PC1 10.0.0.53 10.0.0.54`
configures failover; `dns-retry PC1 50 2` sets 50-unit timeouts with two attempts
per server. Declare authoritative zones with `dns-zone SRV example.com`, set
SOA values with `dns-soa`, and delegate with `dns-ns SRV sub.example.com
ns1.sub.example.com` plus glue A records. Primary/secondary replication uses
`dns-secondary SEC example.com 10.0.0.2` (initial AXFR) and
`dns-notify-target PRI example.com 10.0.0.3`; UPDATE bumps the SOA serial and
sends NOTIFY, which triggers the secondary refresh. Refreshes use IXFR with
AXFR fallback; periodic SOA refresh/retry/expire timers are honored and expired
zones answer SERVFAIL. The resolver follows referrals with
glue and prints `dns: referral <zone> -> <ns-ip>`. If referral glue is absent,
the resolver resolves the NS hostname (out-of-bailiwick) first and then retries
the original query. Wildcards use `*` in the owner (`dns-record SRV *.example.com 10.0.0.9`), apply to A/CNAME/MX, and do not
override exact names. `dns-cache-size PC1 1024` bounds the LRU cache;
`dns-ttl-bounds PC1 50 100` clamps cached TTLs. `dns-axfr PC1 10.0.0.2 example.com`
performs an authoritative zone transfer over TCP and prints the SOA/NS/A/CNAME/MX
records. AXFR is denied by default; allow sources with
`dns-axfr-allow SRV 10.0.0.1 10.0.0.4`, or `any`/`none`. `dns-ixfr PC1 10.0.0.2
example.com 1` requests incremental change records since serial 1; the server
falls back to AXFR when its journal cannot cover the requested serial. Secure transfers with
TSIG on both sides (`dns-tsig SRV key1 secret sha256` and the same on the client)
and optionally require it on the server (`dns-tsig-require SRV on`). Dynamic
updates use `dns-update-allow` for source ACLs and the same TSIG settings:
`dns-update-add PC1 10.0.0.2 example.com host.example.com 10.0.0.9 300` and
`dns-update-del PC1 10.0.0.2 example.com host.example.com A`. Static and UPDATE
records accept a per-RRset TTL, honored by clients and AXFR.
`dns-update-check PC1 10.0.0.2 example.com host.example.com 10.0.0.9` sends a
value-dependent prerequisite and reports `ok`, `prereq` or `nxdomain`. PTR is derived from A records
(`dns-query PC1 10.0.0.2 5.0.0.10.in-addr.arpa PTR`), and MX records use
`dns-mx SRV example.com 10 mail.example.com`.
Leases are renewed by unicast at 50% of the lease and rebind by broadcast at
87.5%; if both fail the address expires and the port loses its IP. The server
reclaims expired leases and supports `dhcp-release PC1`; set the server lease
duration with `dhcp-lease-time SRV 3600`.
NAT: on the router, mark the LAN and WAN
ports with `nat R1 on R1:0 R1:1`; inside hosts are translated to the WAN address,
and `nat-port R1 tcp 8080 192.168.1.1 80` forwards a public port to an inside
host. `nat-table R1` shows mappings. TCP, UDP and ICMP echo are supported
(no application gateways). RIP: enable `rip R1 on` and `rip R2 on` on connected
routers, `run` to exchange updates, then `rip-status R1` shows learned routes
with metric and next hop. OSPF: enable `ospf R1 on` on connected routers and
`run`; `ospf-status R1` shows interfaces, DR/BDR, neighbors, LSDB size and SPF
routes. `ospf-auth R1 simple secret` enables 8-byte simple-password auth;
`ospf-auth R1 md5 7 0123456789abcdef` enables MD5 auth with a 16-byte key;
`sha1`/`sha256` use the same syntax with a 1–64 byte key. Both ends must match. `ospf-cost R1 R1:1 5` changes interface cost; 
`ospf-passive R1 R1:0 on` suppresses Hellos and advertises the interface as a
stub. `ospf-area R1 R1:0 0.0.0.1` assigns an interface area; a router with
interfaces in multiple areas becomes an ABR and originates Type 3 summaries.
`ospf-external R2 172.16.0.0/16 20` injects a Type 5 external route;
`ospf-external R2 clear` withdraws it. `ospf-default-originate R1 on 20 type1`
injects a default route; `ospf-redistribute R1 connected|static 30 type2`
redistributes selected local routes into OSPF.
`ospf-area-type R1 0.0.0.1 stub` marks an area stub; its ABR advertises a
default summary and external LSAs are suppressed there. `nssa` allows Type 7
external LSAs inside the area and the ABR translates them to Type 5 outside.
`ospf-summary R1 0.0.0.1 10.10.0.0/23` aggregates matching area networks into
one Type 3 LSA; `not-advertise` suppresses them and `clear` removes the range.
Link reliability tests: `set-link PC1:0 loss 100`
drops everything (ping times out); `set-link PC1:0 clear` restores it.
`set-link PC1:0 mtu 576` limits the link MTU and reduces TCP MSS accordingly;
larger IPv4 datagrams are fragmented on egress and reassembled at the far port.
ACLs: `acl R1 in deny 10.0.0.0/24 10.0.1.0/24 icmp` blocks matching transit
traffic; `acl6 R1 in deny 2001:db8:1::/64 2001:db8:2::/64 icmpv6` does the same
for IPv6. `help <command>` prints one command's usage.

- `state` prints the topology and counters as JSON, including IPv4/IPv6 addresses,
  IPv6 routes, and NDP neighbor caches.
- `save`/`load` persists ports, IPv4/IPv6 addresses, links, routes, gateways,
  ACLs, NAT, and SPAN mirroring.
- `--json <file>` emits NDJSON (one record per command plus a final `summary`).
- `--log <file>` also writes those JSON records to a file.
- Exit codes: `0` success, `1` runtime/script error, `2` usage error.
- Script errors are reported as `file:line: error: ...`; use `--keep-going` to
  continue past errors.

```sh
./netsim --json examples/03_router.txt --log run.jsonl
```

## 8. Limits and sandbox

Hard caps prevent runaway input: 4096 devices, 65536 ports (1024/device), 65536
links, a 5,000,000-event queue, pcap 2,000,000 frames / 256 MiB, scripts 16 MiB /
1,000,000 lines, scenes 100,000 commands. Lua is sandboxed (no `os`/`io`/
`package`/`debug`; 50M instructions; 4 MiB) and can be disabled with `--no-lua`.

## 9. Troubleshooting

- `error: unknown device 'X'` — check `add-device` names and `state`.
- `error: port index out of range` — use the port index shown by `stats <dev>`.
- `ping timeout` — the target is unreachable; check `set-gateway`, routes, VLANs,
  and whether STP has converged (`stp-status`).
- `no entry` from `lookup` — ARP has not resolved yet; `run` after `arp`/`ping`.

## 10. License

yanas net is free software under the GNU General Public License v3.0 or later.
See `LICENSE`, `COPYRIGHT`, and `SOURCE-CODE.md`.
