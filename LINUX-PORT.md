# Linux port of dsh-ghidra

What was broken, what I changed, and how it was verified.

Upstream `dsh-ghidra` is Windows-only. On Linux every `ghidra_*` tool reported
*"Ghidra not installed"*, even with Ghidra correctly installed and on `PATH`. This
document records the root causes, the fixes, and the host setup that is not part of
the repository.

Commit: `1e0498c` — *port plugin to Linux; fix MCP output schema and process-tree cleanup*
Files touched: `lib/ghidra.js`, `lib/run.js`, `lib/mcp.js`, `index.js`, `sync-installed.mjs`

---

## 1. The environment as it is now

| Component | Value | Note |
|---|---|---|
| Ghidra | `/opt/ghidra`, 12.1.2 **DEV** | `GHIDRA_INSTALL_DIR` |
| JDK | `/usr/lib/jvm/java-27-openjdk` | pinned — Ghidra 12 needs Java 21+, this box defaults to 17 |
| Python | `/home/arminwylin/pyghidra-venv`, 3.14.7 | `pyghidra` 3.1.0 installed in the venv |
| GhidraMCP | `~/.config/ghidra/ghidra_12.1.2_DEV/Extensions/GhidraMCP` | **XDG path**, not `~/.ghidra` |
| Project dir | `/tmp/dsh-ghidra-projects` | |

Three variables are exported from `~/.bashrc` (added during this work):

```sh
export GHIDRA_INSTALL_DIR=/opt/ghidra
export JAVA_HOME=/usr/lib/jvm/java-27-openjdk
export PYGHIDRA_JAVA_HOME=/usr/lib/jvm/java-27-openjdk
```

`JAVA_HOME` matters because `analyzeHeadless` (used for the import pass) resolves its
own JDK; without it the import step runs under Java 17 and fails.

---

## 2. Root causes and fixes

### 2.1 Ghidra detection was `.bat`-only — `lib/ghidra.js`

`detectGhidraHome()` only accepted a Ghidra home containing
`support/analyzeHeadless.bat`. Ghidra ships the launcher as `analyzeHeadless.bat`
on Windows and as an **extensionless executable** everywhere else. So on Linux no
install was ever recognised, and the `gh` object stayed `null` — which is what
produced the misleading "Ghidra not installed" on every tool.

Added two helpers and used them everywhere the old literal appeared:

```js
export function hasHeadless(home) {
  return existsSync(join(home, 'support', 'analyzeHeadless.bat'))
    || existsSync(join(home, 'support', 'analyzeHeadless'))
}
export function headlessLauncher(home) {
  const win = join(home, 'support', 'analyzeHeadless.bat')
  return existsSync(win) ? win : join(home, 'support', 'analyzeHeadless')
}
```

`importBinary()` also exec'd the `.bat` path directly. That is the exec that failed
with `exit 127` — it never even reached Python resolution.

### 2.2 The Python launcher was hardcoded to `py` — `lib/ghidra.js`

`startServer()` did `spawn('py', ['-' + pythonVer, ...args])`. `py` is the Windows
Python Launcher; it does not exist here, so the bridge could not start even after
detection was fixed. `pythonCommand()` now resolves a real interpreter — on Windows
it keeps `py -<ver>`, elsewhere it probes `pythonX.Y`, `python3.X`, then `python3`
and caches the first one that actually imports `pyghidra`. It falls back to the
first candidate so error messages can still name a concrete command.

Two more Windows assumptions in the same file:

- **`PY_PYTHON`** is a `py`-launcher variable and is meaningless on Linux; it is now
  exported only on `win32` so it cannot confuse the real interpreter.
- **`python_command.save`** was written to `%APPDATA%/ghidra/ghidra_<ver>_<rel>/`,
  a path that does not exist on Linux. `ghidraSettingsDir()` now uses
  `~/.ghidra/.ghidra_<ver>_<rel>` off Windows. This file is advisory — the bridge
  invokes `pyghidra_launcher.py` directly — but writing it to a nonexistent
  directory was silently wrong.

### 2.3 Stale JVMs were never cleaned up — `lib/ghidra.js`

`killProcessesUsing()` opened with `if (process.platform !== 'win32') return 0`, so
on Linux it did nothing. This matters more than it looks: Ghidra holds a Java
Channel Lock on the project, and deleting the `.lock` file does not release a live
JVM. A surviving JVM makes the next launcher exit 0 without ever writing a port
file — which looks exactly like a startup failure, with the misleading symptom
"bridge not running".

Reimplemented for Linux with `pgrep -f` (the project path appears in the command
line), skipping our own pid. The Windows PowerShell branch is preserved.

### 2.4 `killPid` orphaned the JVM — `lib/run.js`

On Windows `taskkill /T` kills the whole tree. Off Windows the code only called
`process.kill(pid)`, which kills the launcher but leaves the JVM it spawned holding
the project lock — the same failure mode as 2.3.

`collectTree()` snapshots descendants via `pgrep -P` **before** signalling (after
`SIGTERM` the children re-parent and a re-walk would miss them), sends `SIGTERM`
so Ghidra can flush and save, then escalates to `SIGKILL` after 3s.

### 2.5 `netstat -ano` is Windows-only — `lib/mcp.js`

`findPidByPort()` used `netstat -ano`, so `mcpStop` could not find the real java
PID and the port stayed bound after a stop. Now branches: `netstat -ano` on
Windows, otherwise `ss -ltnp` (iproute2) with an `lsof` fallback.

Also fixed `mcpStart()`. It always used `shell: true` with hand-rolled quoting —
needed only because Node 20.12+ throws `EINVAL` when spawning a `.bat` without a
shell. Elsewhere the launcher is a real executable, so it now spawns the argv
array directly with no shell, which also removes a quoting/injection hazard around
the `file` path argument.

### 2.6 `MCP_OUT` was missing a field it declared — `index.js`

This one is **not** Linux-specific; it affects Windows identically. `ghidra_mcp_start`
and `ghidra_mcp_status` both return a `mode` field, but `MCP_OUT` is declared with
`additionalProperties: false` and did not list `mode`. The framework therefore
rejected the tool's own output:

```
Error: tool "ghidra_mcp_start" returned invalid output:
"value.mode" is not a declared property (additionalProperties: false)
```

The confusing part: the server **had actually started successfully** at that
point. The tool reported failure while doing exactly what it was asked. Adding
`mode: { type: 'string' }` fixes it. Left in this commit deliberately — without it
MCP is unreachable on any platform, so the port would be incomplete.

### 2.7 Remaining Windows literals — `index.js`, `sync-installed.mjs`

- Status panel and the `pyghidraInstalled` error message now name the interpreter
  that `pythonCommand()` actually resolved, instead of telling you to run `py -3.13`.
- Extraction validation accepts either launcher name.
- `ghidraMCPHeadless` is resolved per platform (`.bat` if present, else extensionless).
- The status label reads *GhidraMCP headless launcher* with a note that unified
  mode does not need it.
- `sync-installed.mjs` had `ROOT = 'C:/Users/Administrator/.dsh/profiles'` hardcoded.
  It now derives the root from `DSH_HOME` (falling back to `$HOME/.dsh`).

---

## 3. Host setup done outside the repository

These are machine changes, not code changes. They are needed to reproduce the result.

1. **Ghidra 12.1.2** unpacked at `/opt/ghidra`.
2. **JDK 27** installed; the three exports added to `~/.bashrc` (see §1).
3. **PyGhidra venv** at `~/pyghidra-venv` with `pyghidra` 3.1.0.
4. **GhidraMCP 6.0.0** installed as a Ghidra extension.

### 3.1 The extension path is XDG, not `~/.ghidra`

This one cost real time. Ghidra on Linux puts user extensions under
`~/.config/ghidra/`, not `~/.ghidra/`. Confirmed by asking the running JVM rather
than guessing:

```
extension_installation_dirs: ['/home/arminwylin/.config/ghidra/ghidra_12.1.2_DEV/Extensions',
                               '/opt/ghidra/Ghidra/Extensions']
user_settings_dir:           '/home/arminwylin/.config/ghidra/ghidra_12.1.2_DEV'
```

Note the `_DEV` suffix — it comes from `application.release.name=DEV` in
`application.properties`, not `_PUBLIC`. Installing to the wrong dir fails
**silently**: Ghidra starts normally and the class is simply absent from the
classpath.

Correct layout:

```
~/.config/ghidra/ghidra_12.1.2_DEV/Extensions/GhidraMCP/
├── extension.properties
├── Module.manifest
└── lib/GhidraMCP-6.0.0.jar
```

`/opt/ghidra/Extensions` is root-owned and not writable, so the per-user directory
is the only option.

---

## 4. Verification

A small ELF was built for the test (`verify` / `secretcheck` / `main`, compiled `-O0`,
not stripped).

| Check | Result |
|---|---|
| `detectGhidraHome()` | `/opt/ghidra` via `external` |
| `pythonCommand()` | `/home/arminwylin/pyghidra-venv/bin/python3` |
| `pyghidraInstalled()` | `true` |
| `ghidra_open` | imported, 30 functions, 86 symbols, all segments mapped |
| `ghidra_decompile verify` | correct C body |
| `killPid()` tree kill | child dead after `SIGTERM` |
| MCP `/health` | `200` — `{"status":"healthy","version":"6.0.0-headless","program_loaded":true,"program_name":"port"}` |
| MCP `/decompile_function?address=secretcheck` | correct C |
| MCP `/list_exports`, `/list_functions` | correct output |

The bridge JVM runs the REST server **in-process** (unified mode) on
`127.0.0.1:8123`, sharing the open program — which is what the 168 generated MCP
tools operate through.

---

## 5. Known limitations — deliberately not fixed

**Bogus prototypes from the shipped data archive.** `verify(const char*)` decompiles
with `EVP_DigestVerify`'s signature. Ghidra's bundled `.gdt` assigns the mangled name
to our binary's `verify`; the archive's `EVP_DigestVerify` wins the match. `secretcheck`
is fine, which is what isolates it to name resolution rather than the port. This is
an upstream Ghidra data issue that reproduces identically on Windows, and fixing it
properly means patching `EVP_DigestVerify` in the archive — out of scope here.

**DSH restart required.** The fork is synced into the profile
(`~/.dsh/profiles/web/node_modules/dsh-ghidra`) but the running `dsh web` process
still holds the old code in memory. **Restart DSH** for the fix in §2.6 to take
effect; until then `ghidra_mcp_start` still reports the schema error even though the
server starts.

**The `py` shim at `~/.local/bin/py` is now redundant.** It was a stopgap created
before `pythonCommand()` existed, so the old hardcoded `py` could find a real
interpreter. With §2.2 in place nothing calls `py` on Linux. Safe to delete once
DSH has been restarted.

**Version skew.** The plugin's generated tool schema targets GhidraMCP 7.0.0;
upstream's latest published release is 6.0.0. The tools that were exercised work, but
the generated parameter names may be one version ahead of the server.

---

## 6. Reapplying and rollback

The profile copy is **not** a symlink to the fork — it is a synced copy. After any
edit in `/home/arminwylin/dsh-ghidra-fork`, run:

```sh
node sync-installed.mjs     # copies 18 files, verifies SHA256 per profile
```

Then restart DSH. The script deliberately loads the *installed* copy in its
verification step, because testing the source tree gives a false pass.

Original npm-installed copy is preserved at:

```
~/.dsh/backup-dsh-ghidra-npm-20261005-230234/
```

To roll back, copy that directory over
`~/.dsh/profiles/web/node_modules/dsh-ghidra` and restart DSH.
