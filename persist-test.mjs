// persist-test.mjs — 用**唯一 token** 判定落盘，避免与项目里已有的旧值混淆。
//   open#1 → 写 plate=TOKEN → ghidra_save(flush) → 读 → close → open#2 → 读
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const INSTALLED = 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra'
const BIN = 'C:\\Windows\\System32\\winver.exe'
const TOKEN = 'PERSIST-' + Date.now()

function pidAlive(pid) {
  if (!pid) return false
  const r = spawnSync('tasklist', ['/FI', 'PID eq ' + pid, '/NH'], { encoding: 'utf8' })
  return String(r.stdout || '').includes(String(pid))
}
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
mod.apply(ctx, mod.Config ? mod.Config({}) : {})
const call = async (name, args) => {
  try { return await tools.get(name).execute(args || {}, {}) } catch (e) { return { ok: false, error: String((e && e.message) || e) } }
}
const readPlate = async () => {
  const r = await call('ghidra_get_comments', { address: '0x1400013c0' })
  return r.result?.list?.[0]?.plate
}

console.log(ts() + 'TOKEN = ' + TOKEN)
let firstPid = 0
try {
  const a = await call('ghidra_open', { binaryPath: BIN, stream: false })
  firstPid = a.pid
  console.log(ts() + 'open#1 ok=' + a.ok + ' port=' + a.port + ' pid=' + a.pid)
  await call('ghidra_set_comment', { address: '0x1400013c0', comment: TOKEN, type: 'plate' })
  console.log(ts() + '  after-write   plate=' + await readPlate())

  const s = await call('ghidra_save', {})
  console.log(ts() + 'save → ' + JSON.stringify(s.result || s.error))
  const afterFlush = await readPlate()
  console.log(ts() + '  after-flush   plate=' + afterFlush + '   FLUSH_SAVED=' + (afterFlush === TOKEN))

  const c1 = await call('ghidra_close')
  console.log(ts() + 'close#1 → ' + JSON.stringify(c1.result || c1.error) + ' pid' + firstPid + ' alive=' + pidAlive(firstPid))

  const b = await call('ghidra_open', { binaryPath: BIN, stream: false })
  console.log(ts() + 'open#2 ok=' + b.ok + ' port=' + b.port + ' pid=' + b.pid)
  const afterReopen = await readPlate()
  console.log(ts() + '  after-reopen  plate=' + afterReopen + '   CLOSE_SAVED=' + (afterReopen === TOKEN))

  const c2 = await call('ghidra_close')
  console.log(ts() + 'close#2 → ' + JSON.stringify(c2.result || c2.error))
  console.log(ts() + 'RESULT flushSaved=' + (afterFlush === TOKEN) + ' closeSaved=' + (afterReopen === TOKEN))
} catch (e) {
  console.log(ts() + 'UNCAUGHT: ' + e)
  try { await call('ghidra_close') } catch { /* ignore */ }
}
