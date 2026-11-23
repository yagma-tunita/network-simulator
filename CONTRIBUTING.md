# Contributing

Thanks for helping improve yanas net. This is a terminal-first C++17 network
simulator; contributions should keep it deterministic, dependency-light, and
well tested.

## Build and test

```sh
make              # -> ./netsim (bundled Lua, -Werror)
make test         # unit + fuzz (ASan/UBSan) + scenarios + CLI
make check        # test + coverage gate + bounded soak + throughput floor
```

Windows (MinGW-w64):

```sh
mingw32-make -f Makefile.win      # -> netsim.exe
```

Use `WERROR=0` if a different compiler emits warnings you are triaging.

## Style

- C++17, layers: `core/` -> `device/` -> `link/` -> `engine/` -> `topo/` -> `app/`.
- **Sources are comment-free**; documentation lives in `README.md`,
  `docs/USER_GUIDE.md`, and `DEVELOPMENT_LOG.md`. Keep them in sync.
- Prefer `bool TryParse(...)` for untrusted text; throw from convenience
  constructors only.
- Keep `EthernetFrame`/`IpPacket` codecs byte-accurate and big-endian.
- Add a unit test (`tests/unit/`) for new parsers/codecs and a scenario
  (`tests/*.txt` + `.want`) for new device behavior.

## Lua sandbox

The embedded Lua only compiles a safe subset. Do not add `os`, `io`, `package`,
or `debug` to the library set, and keep the instruction budget and size limits.

## Licensing

yanas net is licensed under the GNU GPL v3.0 or later (see `LICENSE`,
`COPYRIGHT`). By contributing you agree your changes are licensed under the same
terms.

## Commits

Write focused commits with a short imperative subject, e.g.
`cli: add remove-port and disconnect commands`. If tests are relevant, mention
what you ran (`make test`, `make check`).
