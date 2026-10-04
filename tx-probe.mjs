// tx-probe.mjs — 找出哪个 **读** op 会在程序上留下悬空事务（悬空 = 后续写 op 变成嵌套子事务，
// headless 收尾提交外层时子树被丢弃 → "Save succeeded" 但改动全丢）。
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const INSTALLED = 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra'
const BIN = 'C:\\Windows\\System32\\winver.exe'
const t0 = Date.now()
const ts = () => '[' + String(Date.now() - t0).padStart(6) + 'ms] '

const tools = new Map()
const ctx = {
  effect() {},
  tools: { register(t) { tools.set(t.name, t) } },
  jobs: { start() { return 'job-0' } },
  logger: { info() {}, warn() {}, error() {} },
}
const mod = await import(pathToFileURL(join(INSTALLED, 'index.js')).href)
const sock = await import(pathToFileURL(join(INSTALLED, 'lib', 'socket.js')).href)
mod.apply(ctx, mod.Config ? mod.Config({}) : {})
const call = async (name, args) => {
  try { return await tools.get(name).execute(args || {}, {}) } catch (e) { return { ok: false, error: String((e && e.message) || e) } }
}
let PORT = 0
const probeTx = async (label) => {
  const r = await sock.jsonRequest(PORT, { op: 'probe', tx: true }, 60000)
  const d = r && r.result ? r.result : r
  console.log(ts() + '  TX after ' + label.padEnd(22) + ' → tx=' + (d.tx === 'none' ? 'none' : String(d.tx).slice(0, 60)) + '  changed=' + d.changed)
}
const readPlate = async () => {
  const r = await call('ghidra_get_comments', { address: '0x1400013c0' })
  return r.result?.list?.[0]?.plate
}

const a = await call('ghidra_open', { binaryPath: BIN, stream: false })
PORT = a.port
console.log(ts() + 'open ok=' + a.ok + ' port=' + PORT)
const TOKEN = 'TXPROBE-' + Date.now()
try {
  await probeTx('open')
  await call('ghidra_functions', { max: 3 }); await probeTx('functions')
  await call('ghidra_strings', { minLength: 6, max: 3 }); await probeTx('strings')
  await call('ghidra_decompile', { target: 'entry' }); await probeTx('decompile')
  await call('ghidra_xrefs', { target: '0x1400013c0' }); await probeTx('xrefs')
  await call('ghidra_call_graph', { target: 'entry', depth: 1 }); await probeTx('call_graph')
  await call('ghidra_pcode', { target: 'entry', mode: 'listing' }); await probeTx('pcode(listing)')
  await call('ghidra_pcode', { target: 'entry', mode: 'high' }); await probeTx('pcode(high)')
  await call('ghidra_variables', { target: 'FUN_140001140' }); await probeTx('variables')
  await call('ghidra_disassemble', { target: 'entry' }); await probeTx('disassemble')

  console.log(ts() + '--- 现在写 + save，看能否落盘 ---')
  await call('ghidra_set_comment', { address: '0x1400013c0', comment: TOKEN, type: 'plate' })
  console.log(ts() + '  in-session plate=' + await readPlate())
  const s = await call('ghidra_save', {})
  console.log(ts() + 'save → flushed=' + s.result?.flushed + ' stop=' + s.result?.stopMs + 'ms')
  const after = await readPlate()
  console.log(ts() + '  after-flush plate=' + after + '  PERSISTED=' + (after === TOKEN))
} catch (e) {
  console.log(ts() + 'UNCAUGHT ' + e)
}
await call('ghidra_close')
