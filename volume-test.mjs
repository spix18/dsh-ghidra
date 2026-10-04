// volume-test.mjs — 复刻 harness B3 的**全部**写负载（一次会话里累积，不中途 save），
// 然后手工发 shutdown，每 100ms 轮询 JVM 存活，量出它到底多久才死；最后重开读回，判断是否落盘。
//   - 死亡时间恒定但很短 → 有东西在杀它/它提前退出（保存被截断）
//   - 落盘失败 → 大改动集本身保存不了
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
const TOKEN = 'VOL-' + Date.now()
try {
  // --- 完整 B3 写负载 ---
  await call('ghidra_set_comment', { address: '0x1400013c0', comment: TOKEN, type: 'plate' })
  await call('ghidra_set_comment', { address: '0x1400013c4', comments: { eol: 'V-EOL', post: 'V-POST' } })
  await call('ghidra_set_comment', { address: '0x1400013c4', comment: '', type: 'eol' })
  await call('ghidra_set_comment', { addresses: ['0x1400013c0', '0x1400013c4'], comment: 'V-PRE', type: 'pre' })
  await call('ghidra_rename', { target: 'FUN_140001010', newName: 'V_RENAMED' })
  await call('ghidra_rename', { target: 'V_RENAMED', newName: 'FUN_140001010' })
  await call('ghidra_label', { action: 'create', address: '0x140001010', names: ['V_LA', 'V_LB'] })
  await call('ghidra_label', { action: 'delete', address: '0x140001010', name: 'V_LA' })
  await call('ghidra_label', { action: 'delete', address: '0x140001010', name: 'V_LB' })
  await call('ghidra_set_variables', { target: 'FUN_1400010f0', variables: [{ name: 'local_18', newName: 'v_local', newType: 'int' }] })
  await call('ghidra_set_prototype', { target: 'FUN_140001140', prototype: 'int FUN_140001140(char *buf, int len)' })
  await call('ghidra_set_prototype', { target: 'FUN_140001140', noReturn: true })
  await call('ghidra_set_prototype', { target: 'FUN_140001140', noReturn: false })
  await call('ghidra_tags', { action: 'create', name: 'V-TAG', comment: 'v' })
  await call('ghidra_tags', { action: 'attach', target: 'entry', tags: ['V-TAG'] })
  await call('ghidra_tags', { action: 'detach', target: 'entry', tags: ['V-TAG'] })
  await call('ghidra_tags', { action: 'delete', name: 'V-TAG' })
  await call('ghidra_delete_function', { address: 'FUN_140001010' })
  await call('ghidra_create_function', { address: '0x140001010', name: 'FUN_140001010' })
  console.log(ts() + '  in-session plate=' + await readPlate() + '  pidAlive=' + alive(pid1))

  // --- 手工 shutdown + 毫秒级观测死亡时刻 ---
  const tShut = Date.now()
  await sock.jsonRequest(a.port, { op: 'shutdown' }, 5000).catch((e) => console.log(ts() + '  shutdown req err ' + e))
  let diedAt = 0
  for (let i = 0; i < 200; i++) {
    await new Promise((r) => setTimeout(r, 100))
    if (!alive(pid1)) { diedAt = Date.now() - tShut; break }
  }
  console.log(ts() + '  JVM pid=' + pid1 + ' died ' + (diedAt ? diedAt + 'ms after shutdown' : 'NEVER (>20s)'))

  const b = await call('ghidra_open', { binaryPath: BIN, stream: false })
  console.log(ts() + 'reopen port=' + b.port + ' pid=' + b.pid)
  const got = await readPlate()
  console.log(ts() + '  after-reopen plate=' + got + '  PERSISTED=' + (got === TOKEN))
} catch (e) {
  console.log(ts() + 'UNCAUGHT ' + e)
}
await call('ghidra_close')
