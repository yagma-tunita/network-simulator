# Security policy

## Supported versions

The latest release (see `VERSION`) receives fixes.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** to the maintainer rather
than opening a public issue. Include steps to reproduce and the affected version.

## Security model and limits

- **Lua sandbox.** Embedded Lua 5.4.6 is compiled from a safe subset: `os`, `io`,
  `package`, and `debug` are not built or exposed; `dofile`, `load`, `loadfile`,
  and `require` are removed. Scripts run with a 50M-instruction budget and a 4 MiB
  size limit. `--no-lua` disables Lua entirely.
- **Resource caps.** Devices (4096), ports (65536; 1024/device), links (65536), a
  5,000,000-event queue (the run halts), pcap (2,000,000 frames / 256 MiB),
  scripts (16 MiB / 1,000,000 lines), scenes (100,000 commands).
- **File capabilities.** The command set can read/write scene `.yn` files
  (`load`/`save`/`state`) and write pcap capture files. Treat untrusted scripts
  and scenes as untrusted input. For strict isolation, run in a container or use
  `--no-lua`.
- **Network.** This build is terminal-only; there is no listening network service.

## Not in scope

The simulator is not a security boundary for hostile code inside Lua scripts when
you have deliberately extended the sandbox or disabled limits; do not do that for
untrusted input.
