# Examples

Runnable scenarios for learning and for copying as a starting point. From the
project root (after `make`, or with `netsim.exe` on Windows):

```sh
./netsim -q examples/01_two_hosts.txt
./netsim -q examples/04_stp.txt
./netsim examples/05_lua.lua
./netsim examples/06_scene.yn
```

| File | Shows |
|------|-------|
| `01_two_hosts.txt` | a direct link, automatic ARP, and an ICMP ping |
| `02_switch_vlan.txt` | two hosts in the same VLAN behind a MAC-learning switch |
| `03_router.txt` | cross-subnet ping through a router with default gateways |
| `04_stp.txt` | a redundant triangle converging with spanning tree |
| `05_lua.lua` | scripting a loop with Lua (`exec` / `run` / `log`) |
| `06_scene.yn` | a JSON scene file (devices, ports, links, layout) |
| `07_traceroute.txt` | traceroute across a router, plus `ports` / `routes` |
| `08_udp.txt` | a UDP echo service and a `udp-send` round trip |

See `docs/USER_GUIDE.md` for a walkthrough and the top-level README for the full
command reference.
