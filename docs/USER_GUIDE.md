# yanas net — user guide

A short, student-oriented walkthrough. For the full command reference and design
notes see the top-level `README.md`.

## 1. What it is

yanas net is a deterministic Layer-2/Layer-3 network simulator. You build a small
network out of hosts, switches, and routers, then send traffic (ARP, ICMP) and
watch what happens. It is terminal-first, scriptable, and ships with an embedded
(Lua) scripting engine. Results are reproducible because time is a logical clock.

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
set-gateway <device> <gw-ip>
set-vlan   <dev:idx> <vid>
set-trunk  <dev:idx> [native-vid]
set-stp    <switch> on|off
set-stp-mode <switch> stp|rstp
set-bridge <switch> <priority>
stp-status <switch>
set-link   <dev:idx> down|up
remove-device <name>
remove-port   <dev:idx>
disconnect    <dev:idx>
rename-device <old> <new>
set-ip     <dev:idx> <ip>/<prefix>
arp        <device> <target-ip>
ping       <device> <target-ip> [ttl]
traceroute <device> <target-ip> [max-hops]
run [duration] | step [n] | trace on|off
lookup     <device> <ip>
stats      <device>
devices | links | ports <device> | routes <router>
arp-table <device> | mac-table <switch>
export     dot|svg <file>
udp-echo   <device> on|off [port]
udp-send   <device> <ip> <dport> <text...>
tcp-listen <device> on|off [port]
tcp-connect <device> <ip> <port> [text...]
tcp-keepalive <device> on [idle interval count]|off
tcp-status <device>
tcp-backlog <device> <1-1024>
dhcp-server <device> on <start> <end> <prefix> <gateway> [dns] | off
dhcp-client <device> [port-index]
dhcp-relay  <router> <dev:idx> <server-ip>|off
dns-server <device> on|off
dns-record <device> <name> <ip>
dns-cname  <device> <alias> <target>
dns-query <device> [server-ip] <name>
nat        <router> on <inside-dev:idx> <outside-dev:idx> | off
nat-port   <router> tcp|udp <public-port> <inside-ip> <inside-port>
nat-table  <router>
rip        <router> on|off
rip-status <router>
ospf       <router> on|off
ospf-status <router>
ospf-auth  <router> none|simple <password>|md5|sha1|sha256 <key-id> <key>
ospf-cost  <router> <dev:idx> <1-65535>
ospf-passive <router> <dev:idx> on|off
ospf-external <router> <ip/prefix> [metric]
ospf-area  <router> <dev:idx> <area-id>
ospf-area-type <router> <area-id> stub|nssa|normal
tcp-lite-echo   <device> on|off [port]
tcp-lite-echo-client <device> <ip> <port> <text...>
acl        <router> in|out allow|deny <src/p> <dst/p> <proto|any>
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

**Switch and VLAN.** Assign both switch ports to VLAN 10 (`set-vlan SW1:0 10`).
Hosts in different VLANs cannot reach each other until you bridge them with a
router or trunk.

**Router.** Put a router between `192.168.1.0/24` and `192.168.2.0/24`, set each
host's gateway to the router interface, then `ping PC1 192.168.2.1`.

**STP.** Connect three switches in a triangle, `set-stp` on, `run`, then ping: one
link is blocked and traffic still flows. `set-link SW3:1 down` and `run` to watch
reconvergence.

## 7. Automation

`traceroute <dev> <ip>` sends probes with increasing TTL and prints each hop, so
you can see the path a packet takes. Diagnostics: `devices`, `links`,
`ports <dev>`, `routes <router>`, `arp-table <dev>`, `mac-table <switch>`.
`export dot <file>` writes a Graphviz graph; `export svg <file>` writes an SVG
diagram you can open in a browser. `map` prints a terminal adjacency map.
`generate tree <depth> <fanout>` builds a large switch tree with one host per
leaf (for scale experiments). UDP echo: `udp-echo PC2 on 7` then
`udp-send PC1 10.0.0.2 7 hello` and `run`. Real TCP: `tcp-listen PC2 on 80`
then `tcp-connect PC1 10.0.0.2 80 hello` performs a three-way handshake, sends
the text reliably (RTO retransmission, congestion control), and the service
echoes it back. The older `tcp-lite-*` commands remain as a deprecated teaching
transport and are **not** TCP. DHCP/DNS: on a server host use
`dhcp-server SRV on 10.0.0.100 10.0.0.110 24 10.0.0.1 10.0.0.1`,
`dns-server SRV on`, and `dns-record SRV example.com 10.0.0.1`. A host with an
unconfigured port runs `dhcp-client PC1 0`, then `dns-query PC1 example.com`
uses the DNS server supplied by DHCP. For a server on another subnet, attach a
relay to the client-facing router port: `dhcp-relay R1 R1:0 10.1.0.2`. DNS
supports multiple A records and CNAMEs (`dns-cname SRV www.example.com example.com`).
Leases are renewed by unicast at 50% of the lease and rebind by broadcast at
87.5%; if both fail the address expires and the port loses its IP.
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
`ospf-external R2 clear` withdraws it.
`ospf-area-type R1 0.0.0.1 stub` marks an area stub; its ABR advertises a
default summary and external LSAs are suppressed there. `nssa` allows Type 7
external LSAs inside the area and the ABR translates them to Type 5 outside.
Link reliability tests: `set-link PC1:0 loss 100`
drops everything (ping times out); `set-link PC1:0 clear` restores it.
ACLs: `acl R1 in deny 10.0.0.0/24 10.0.1.0/24 icmp` blocks matching transit
traffic. `help <command>` prints one command's usage.

- `state` prints the topology and counters as JSON.
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
