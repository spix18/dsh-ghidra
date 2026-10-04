// readwrite-test.mjs — 验证「先跑读侧 op（含反编译器）再跑大批写侧 op」是否会破坏落盘。
// volume-test 证明：只做 19 个写 op → 落盘 OK。tx-probe 证明：只做读 op + 1 个写 → 落盘 OK。
// 本脚本把两者合起来（与 harness 的真实顺序一致），并在读后/写后各探一次事务。
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const INSTALLED = 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra'
const BIN = 'C:\\Windows\\System32\\winver.exe'
const t0 = Date.now()
const ts = () => '[' + String(Date.now() - t0).padStart(6) + 'ms] '
const alive = (pid) => {
  if (!pid) return false
  const r = spawnSync('tasklist', ['/FI', 'PID eq ' + pid, '/NH'], { encoding: 'utf8' })
  return String(r.stdout || '').includes(String(pid))
}

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
const readPlate = async () => {
  const r = await call('ghidra_get_comments', { address: '0x1400013c0' })
  return r.result?.list?.[0]?.plate
}

const a = await call('ghidra_open', { binaryPath: BIN, stream: false })
const pid1 = a.pid
console.log(ts() + 'open ok=' + a.ok + ' port=' + a.port + ' pid=' + pid1)
const TOKEN = 'RW-' + Date.now()
const txProbe = async (tag) => {
  try {
    const r = await sock.jsonRequest(a.port, { op: 'probe', tx: true }, 60000)
    console.log(ts() + '  tx[' + tag + '] = ' + JSON.stringify(r.result))
  } catch (e) { console.log(ts() + '  tx[' + tag + '] err ' + e) }
}
try {
  // ---- 阶段 1：完整读侧负载（与 harness B 段一致，含反编译器） ----
  await call('ghidra_functions', { max: 3 })
  await call('ghidra_strings', { minLength: 6, max: 3 })
  await call('ghidra_decompile', { target: 'entry' })
  await call('ghidra_xrefs', { target: '0x1400013c0' })
  await call('ghidra_calls', { target: 'entry', direction: 'both' })
  await call('ghidra_call_graph', { target: 'entry', depth: 2 })
  await call('ghidra_pcode', { target: 'entry', mode: 'listing', limit: 10 })
  await call('ghidra_pcode', { target: 'entry', mode: 'high', limit: 20 })
  await call('ghidra_variables', { target: 'entry' })
  await call('ghidra_disassemble', { target: 'entry' })
  await txProbe('after-reads')
  console.log(ts() + '  in-session plate(before writes)=' + await readPlate() + '  pidAlive=' + alive(pid1))

  // ---- 阶段 2：完整写侧负载 ----
  await call('ghidra_set_comment', { address: '0x1400013c0', comment: TOKEN, type: 'plate' })
  await call('ghidra_set_comment', { address: '0x1400013c4', comments: { eol: 'RW-EOL', post: 'RW-POST' } })
  await call('ghidra_set_comment', { address: '0x1400013c4', comment: '', type: 'post' })
  await call('ghidra_set_comment', { addresses: ['0x1400013c0', '0x1400013c4'], comment: 'RW-PRE', type: 'pre' })
  await call('ghidra_rename', { target: 'FUN_140001010', newName: 'RW_RENAMED' })
  await call('ghidra_rename', { target: 'RW_RENAMED', newName: 'FUN_140001010' })
  await call('ghidra_label', { action: 'create', address: '0x140001010', names: ['RW_LA'] })
  await call('ghidra_label', { action: 'delete', address: '0x140001010', name: 'RW_LA' })
  await call('ghidra_set_variables', { target: 'FUN_1400010f0', variables: [{ name: 'local_18', newName: 'rw_local', newType: 'int' }] })
  await call('ghidra_set_prototype', { target: 'FUN_140001140', prototype: 'int FUN_140001140(char *buf, int len)' })
  await call('ghidra_set_prototype', { target: 'FUN_140001140', noReturn: true })
  await call('ghidra_set_prototype', { target: 'FUN_140001140', noReturn: false })
  await call('ghidra_tags', { action: 'create', name: 'RW-TAG', comment: 'rw' })
  await call('ghidra_tags', { action: 'attach', target: 'entry', tags: ['RW-TAG'] })
  await call('ghidra_tags', { action: 'detach', target: 'entry', tags: ['RW-TAG'] })
  await call('ghidra_tags', { action: 'delete', name: 'RW-TAG' })
  await call('ghidra_delete_function', { address: 'FUN_140001010' })
  await call('ghidra_create_function', { address: '0x140001010', name: 'FUN_140001010' })
  await txProbe('after-writes')
  console.log(ts() + '  in-session plate(after writes)=' + await readPlate() + '  pidAlive=' + alive(pid1))

  const fin = await call('ghidra_close')
  console.log(ts() + '  close -> ' + JSON.stringify(fin.result) + ' pidAlive=' + alive(pid1))

  const b = await call('ghidra_open', { binaryPath: BIN, stream: false })
  console.log(ts() + 'reopen port=' + b.port + ' pid=' + b.pid)
  const got = await readPlate()
  console.log(ts() + '  after-reopen plate=' + got + '  PERSISTED=' + (got === TOKEN))
} catch (e) {
  console.log(ts() + 'UNCAUGHT ' + (e && e.stack || e))
}
await call('ghidra_close')
