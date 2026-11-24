# Legacy live bridge (archived)

This directory preserves the experimental real-time TAP bridge. It is **not**
built, packaged, or supported by the offline product.

Archived pieces:

- `ynbridge/`: Go bridge (frame codec, netsim live client, TAP, impairment).
- `live_tap.sh`: root TAP integration test (ping, TCP echo, concurrency, RST).
- `simulator/main-live.cpp`: snapshot of `app/main.cpp` with `--live`.
- `simulator/Port-live.hpp`, `Port-live.cpp`: snapshot with `Port::bridge`.

The active simulator no longer exposes `--live` or `Port::bridge`. Restoring
this experiment requires re-applying those snapshots and rebuilding both the
simulator and the Go bridge.
