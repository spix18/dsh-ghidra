---
name: dsh-ghidra
description: Reverse-engineer native binaries with Ghidra through the dsh-ghidra plugin — decompile functions, map call graphs and xrefs, inspect segments/imports/exports/data types, extract strings and IOCs, detect crypto constants, malware behaviours and anti-analysis tricks, compare functions and hashes, and script the full Ghidra API when no tool fits.
whenToUse: The target is a native compiled artifact (PE/EXE/DLL/SYS, ELF/.so, Mach-O, firmware, a Ghidra project or .gzf analysis database) and the user wants to know what it does — decompilation, control flow, xrefs, strings, imports/exports, memory layout, function identity/comparison, or malware/IOC/crypto triage. Do NOT use for JavaScript/Electron/ASAR bundles, archives (.zip/.apk/.ipa), .NET managed assemblies, or ordinary source-code reading — this plugin has no engine for those and will only mislead you.
metadata:
  version: "1"
  tool_count: "218"
---

# Reverse-engineering a binary with dsh-ghidra

You drive a real Ghidra installation through two tool families. Everything below assumes a native target.

## Route the target first

Pick the surface by what the user actually handed you:

- **Native executable / shared library / driver / firmware** → this skill. Open it with `ghidra_open`.
- **An already-analysed Ghidra project or `.gzf`** → still `ghidra_open`, pointing at the project, so you reuse the existing analysis instead of re-importing.
- **JavaScript, Electron, ASAR, source maps, archives, .NET/managed PE** → **not this plugin.** Say so plainly and name what would work. Ghidra will happily import a managed assembly as an opaque native blob and every conclusion you draw from it will be wrong.
- **Not sure the file is native** → ask for the path and check the header before opening. Do not open first and interpret later.

If the user's question is about *behaviour at runtime* (what it connects to, what it writes, what it decrypts when run), static analysis cannot answer it. Say that, and say what observation would be needed — do not fill the gap with inference dressed as fact.

## Bring the binary up once

1. `ghidra_status` — is Ghidra installed, is a server already running, what is loaded.
2. `ghidra_open { binaryPath }` — starts the resident PyGhidra bridge, imports and auto-analyses the binary. This runs as a background job and streams progress; wait for it to finish before reading results.
3. `ghidra_info` — confirm what you got: language, compiler, image base, memory blocks, function and symbol counts, entry points.

**The analysis tools only exist while the bridge is running.** They are registered when the bridge comes up and unregistered when it goes down, so the tool list you see reflects reality. If a `ghidra_*` tool you expected is missing, the bridge is not running: call `ghidra_open` (or `ghidra_status` to re-check). This is deliberate — the plugin does not advertise tools that cannot currently run.

Import a binary once per session. Re-running `ghidra_open` on the same path tears down and rebuilds the bridge.

## Which family to use

| | `ghidra_*` (native, 47 tools) | `ghidra_mcp_*` (generated, 168 tools) |
|---|---|---|
| Engine | PyGhidra bridge — direct Ghidra API | upstream GhidraMCP REST server |
| Availability | while `ghidra_open` is live | **only after `ghidra_mcp_start`** |
| Shape | structured JSON, real paging, composite analysis | one endpoint per call, convenience long tail |

**Prefer the native family.** It gives you paging (`max`/`offset`), composite calls that replace three round trips (`ghidra_function_context`, `ghidra_data_flow`, `ghidra_compare_functions`), and the whole write path. Reach for `ghidra_mcp_*` only when the native family has no equivalent — structs, data types, bookmarks, analyzer configuration, server administration. Never use a `ghidra_mcp_*` call to duplicate a `ghidra_*` call you can already make; they are separate engines and can disagree.

`ghidra_mcp_start` (unified mode, the default) attaches the REST server inside the bridge JVM so both families act on the **same program in the same process**. Run it only when you actually need that family.

## Work summary-first

Start with the cheapest view that can answer the question, then narrow. Answers are deterministic while the program is loaded — **never repeat an identical call**.

1. `ghidra_info` — the shape of the program.
2. `ghidra_functions` — the function inventory (`filter`, `sort`, `max`).
3. `ghidra_imports` / `ghidra_exports` — the external contract, often the fastest route to "what is this".
4. `ghidra_strings` / `ghidra_search_strings` — cheap, high-signal, and usually the first real clue.
5. Only then go per-function. `ghidra_function_context` returns signature, parameters, locals, callers, callees, entry xrefs, string references, instruction count, hashes, cyclomatic complexity and pseudo-code **in one call** — it beats `ghidra_decompile` + `ghidra_xrefs` + `ghidra_variables` as three round trips.

## Separate observations, inferences, and unknowns

Every conclusion you report must be labelled by what it rests on:

- **Observation** — something a tool returned: an address, an instruction, a string, a symbol, a segment, a hash.
- **Inference** — what you concluded from it. State what it rests on.
- **Unknown** — what you could not establish, *and the boundary that stopped you* (no symbols, indirect call, packed section, truncated list).

**Missing evidence is unknown — not empty, and not false.** A string sitting in `.rdata` is not proof the code path runs. A function named `decrypt` is a name, not a finding. An empty `ghidra_xrefs` result means "no xrefs in what Ghidra indexed", not "nothing calls this".

Quote evidence inline so the user can re-check it: `0x1400012a0 (FUN_1400012a0) calls …`, `"https://…" @ 0x14002a018`.

## Plan a broader investigation

1. Turn the request into an explicit question list, and note what evidence each answer would need.
2. Before opening anything: check `ghidra_status`, the currently loaded program, and whether an analysis database already exists for this binary. **Reuse it** — do not re-import or re-analyse a program that is already loaded.
3. Start from the smallest useful overview, then batch related calls around one specific hypothesis rather than browsing.
4. Look at packaging and configuration alongside the code — imports, embedded strings, resources, sections. **Do not infer behaviour from a file name, a single string, or a section layout.**
5. Match the evidence type to the question. Static evidence settles structure, control flow, and data layout. It does not settle runtime behaviour; when that is the question, say so instead of guessing.
6. Split independent questions and keep their evidence separate. When they can be answered in parallel, say which calls are independent.
7. Keep a short finding ledger as you go: conclusion → supporting evidence → confidence → search boundary → still unknown. Update it instead of re-deriving it.

Before finishing, walk the original question list and mark each item answered / partially answered / unresolved. A bounded negative search stays bounded — "not among the 200 strings I listed" is not "not present". **Do not call an investigation complete while a required question is still open.**

## Common investigations

- **What does this binary do?** `ghidra_strings` → `ghidra_imports` → entry point from `ghidra_info` → `ghidra_call_graph` from the entry → `ghidra_function_context` on the interesting leaves.
- **Find a function** — `ghidra_search_functions` (regex) · `ghidra_search_strings` (regex, then `ghidra_xrefs` on the string address) · `ghidra_search_instructions` (`mnemonic`/`operand`/`pattern`, scope it with `target`).
- **Trace data** — `ghidra_data_flow { target, variable, direction }` walks the decompiler's p-code def/use chain; `ghidra_pcode` when you need the raw IR.
- **Compare two functions** — `ghidra_compare_functions` (size, instruction count, mnemonic similarity, parameter and callee diffs) or `ghidra_hash { scope: 'function' }` for exact identity. Cross-binary comparison: hash both, then compare the hashes.
- **Malware triage** — `ghidra_detect_malware_behaviors` (API × behaviour class, with the owning function) · `ghidra_extract_iocs_with_context` (17 IOC classes, each with address and owning function) · `ghidra_detect_crypto_constants` (known table signatures) · `ghidra_find_anti_analysis_techniques` (anti-debug/anti-VM/tool strings plus RDTSC/CPUID/INT3 counts). These are **leads, not verdicts** — read the address each one points at before concluding anything. A `VirtualAllocEx` appears in debuggers and game trainers as readily as in injectors.
- **Bytes and gaps** — `ghidra_search_byte_patterns` (`??`/`4?` wildcards, `|` alternation) · `ghidra_find_code_gaps` · `ghidra_find_dead_code` (candidates only — indirect calls are invisible to that analysis).
- **No tool fits** — `ghidra_run_script_inline` runs Python in the live Ghidra context with `currentProgram`, `program`, `monitor`, `println`, and `getScriptArgs()`; assign to `result` to return a value. This is the full Ghidra API and the correct escape hatch. Pass `write: true` for anything that mutates, and prefer `ghidra_run_script_file` for anything longer than a few lines.

## Writing changes back

- Mutations — `ghidra_set_comment`, `ghidra_rename`, `ghidra_label`, `ghidra_set_prototype`, `ghidra_set_variables`, `ghidra_create_function`, `ghidra_delete_function`, `ghidra_tags`, `ghidra_configure_analyzer`, `ghidra_reanalyze`, `ghidra_run_analysis`, and any script with `write: true` — change the **in-memory** program.
- They reach the Ghidra project only when you call `ghidra_save`, which restarts the bridge and takes roughly 40 seconds. **Batch your edits, then save once.**
- `ghidra_delete_function`, `ghidra_reanalyze`, and `ghidra_run_analysis` with `force: true` are destructive to existing analysis. Confirm before running them, and say what will be lost.
- Finish with `ghidra_close` to release the program and the server.

## Limits to state to the user

- Analysis is **static**. There is no execution, debugging, instrumentation, dynamic tracing, or network capture.
- Output is truncated at `maxOutputChars` (default 100000). **Page with `max`/`offset`** rather than reporting a truncated list as if it were complete.
- Auto-analysis quality depends on the loader. Stripped binaries, packers, and non-x86 architectures produce more `FUN_*` and more unknowns — say so rather than presenting guesses as structure.
- The plugin needs a Ghidra installation plus a Python with `pyghidra`. `ghidra_status` reports both; if either is missing, `ghidra_open` fails with the exact remediation to give the user.

## Finish the task

Explain what you found in plain language and tie each claim to the evidence the tools returned. When the user wants a reconstruction or a patch, use ordinary coding tools — and keep observed behaviour separate from your design choices. Close with `ghidra_close` when you are done.
