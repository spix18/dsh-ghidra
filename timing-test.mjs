// timing-test.mjs — 精确定位「落盘点」在会话时间轴上的位置。
// 每个变体：open → 写 EARLY token → 等 10s → 写 LATE token（另一个地址）→ 关闭 → 重开读两个。
//   EARLY 在 LATE 不在  → 落盘点在会话早期（headless 在脚本返回前就保存了）
//   两个都在            → 落盘点在会话结束 ✓（harness 的丢失另有原因）
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const INSTALLED = 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra'
const BIN = 'C:\\Windows\\System32\\winver.exe'
const A1 = '0x1400013c0'   // plate EARLY
const A2 = '0x1400013c4'   // plate LATE
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
mod.apply(ctx, mod.Config ? mod.Config({}) : {})
const call = async (name, args) => {
  try { return await tools.get(name).execute(args || {}, {}) } catch (e) { return { ok: false, error: String((e && e.message) || e) } }
}
const readTwo = async () => {
  const r = await call('ghidra_get_comments', { addresses: [A1, A2] })
  const rest = r.result
  const arr = Array.isArray(rest) ? rest : (rest && rest.list) || []
  const at = (a) => (arr.find((x) => String(x.address).toLowerCase().endsWith(a.slice(2))) || {}).plate
  return { early: at(A1), late: at(A2) }
}

async function variant(label, finish) {
  const a = await call('ghidra_open', { binaryPath: BIN, stream: false })
  const E = label + '-EARLY-' + Date.now()
  const L = label + '-LATE-' + Date.now()
  console.log(ts() + label + ' open port=' + a.port + ' pid=' + a.pid)
  await call('ghidra_set_comment', { address: A1, comment: E, type: 'plate' })
  console.log(ts() + label + '  wrote EARLY=' + E + '  pidAlive=' + alive(a.pid))
  await new Promise((r) => setTimeout(r, 10000))
  await call('ghidra_set_comment', { address: A2, comment: L, type: 'plate' })
  console.log(ts() + label + '  wrote LATE=' + L + ' after 10s wait  pidAlive=' + alive(a.pid))
  const fin = await call(finish)
  console.log(ts() + label + '  ' + finish + ' -> ' + JSON.stringify(fin.result || fin).slice(0, 200))
  console.log(ts() + label + '  pidAlive after finish=' + alive(a.pid))

  const b = await call('ghidra_open', { binaryPath: BIN, stream: false })
  const got = await readTwo()
  console.log(ts() + label + '  reopen port=' + b.port + ' -> ' + JSON.stringify(got))
  console.log(ts() + label + '  EARLY_SAVED=' + (got.early === E) + '  LATE_SAVED=' + (got.late === L))
  await call('ghidra_close')
}

try {
  await variant('V1', 'ghidra_close')
  console.log('')
  await variant('V2', 'ghidra_save')
} catch (e) {
  console.log(ts() + 'UNCAUGHT ' + (e && e.stack || e))
  await call('ghidra_close')
}
