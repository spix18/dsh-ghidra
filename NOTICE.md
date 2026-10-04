# Third-party notices

`dsh-ghidra` is a bridge: it drives other people's software rather than bundling it.

- **Ghidra** — Apache License 2.0 — https://github.com/NationalSecurityAgency/ghidra
  Not redistributed here. The plugin uses a locally installed Ghidra (its own copy under
  `node_modules/dsh-ghidra-home/ghidra`, or an external install you point it at).

- **GhidraMCP** (`bethington/ghidra-mcp`) — https://github.com/bethington/ghidra-mcp
  Installed separately as a Ghidra extension (`GhidraMCP-*.jar` in the Ghidra user extensions
  directory) and **not redistributed** in this repository or npm package.
  The 168 generated tool definitions in `lib/mcp-tools.js` are derived from GhidraMCP's published
  REST schema (captured in `UPSTREAM-SCHEMA-LIVE.json`) purely for interoperability, and the
  local patches against upstream behaviour are documented in `PATCHES.md`.

- **PyGhidra** — ships with Ghidra; used to launch the in-process bridge script.
