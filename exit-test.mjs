// exit-test.mjs — 模型化「DSH 卸载插件时（用户/agent 都没调 ghidra_close/ghidra_save）本次会话的写改动是否落盘」。
// 现状：index.js:102 `ctx.effect(() => () => killServer())` 是**硬杀**（process.kill + taskkill /F /T），
// Ghidra headless 的 DecompileBridge.py 还在 accept 循环里，没机会 return → 脚本不返回 → headless 从不保存。
// 用法（两阶段，必须用两个独立进程）：
//   $env:EXIT_TOKEN='EXIT-...'; node exit-test.mjs write
//   node exit-test.mjs read          # 读回并断言 plate === $env:EXIT_TOKEN
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const INSTALLED = 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra'
const BIN = 'C:\\Windows\\System32\\winver.exe'
const TOKEN = process.env.EXIT_TOKEN || 'EXIT-NO-TOKEN'
const phase = process.argv[2] || 'write'

const tools = new Map()
let disposeFn = null
const ctx = {
  effect(fn) { disposeFn = fn(); return disposeFn },
  tools: { register(t) { tools.set(t.name, t) } },
  jobs: { start() { return 'job-0' } },
  logger: { info() {}, warn() {}, error() {} },
}
const mod = await import(pathToFileURL(join(INSTALLED, 'index.js')).href)
mod.apply(ctx, mod.Config ? mod.Config({}) : {})

const call = async (name, args) => {
  try { return await tools.get(name).execute(args || {}, {}) }
  catch (e) { return { ok: false, error: String((e && e.message) || e) } }
}
const pidAlive = (pid) => {
  if (!pid) return false
  const r = spawnSync('tasklist', ['/FI', 'PID eq ' + pid, '/NH'], { encoding: 'utf8' })
  return String(r.stdout || '').includes(String(pid))
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const readPlate = async () => {
  const r = await call('ghidra_get_comments', { address: '0x1400013c0' })
  return r.result?.list?.[0]?.plate
}

if (phase === 'write') {
  const o = await call('ghidra_open', { binaryPath: BIN, stream: false })
  const pid = o.pid || 0
  console.log('open port=' + o.port + ' jvmPid=' + pid)
  const w = await call('ghidra_set_comment', { address: '0x1400013c0', type: 'plate', comment: TOKEN })
  console.log('set_comment ' + JSON.stringify(w.result || w.error))
  const got = await readPlate()
  console.log('in-session plate=' + JSON.stringify(got) + '  WROTE_IN_SESSION=' + (got === TOKEN))
  const hard = process.argv[3] === 'hard'
  console.log('--- simulate DSH unload: ' + (hard ? 'process.exit(0) WITHOUT calling the dispose hook (tests the sync exit guard)' : 'call the registered dispose hook, no ghidra_close / ghidra_save') + ' ---')
  const t0 = Date.now()
  if (!hard) {
    const p = disposeFn()
    if (p && typeof p.then === 'function') await p
    console.log('dispose() returned after ' + (Date.now() - t0) + 'ms')
    await sleep(2500)
  } else {
    process.exit(0)
  }
  console.log('jvmAliveAfterDispose=' + pidAlive(pid))
  process.exit(0)
} else {
  const o = await call('ghidra_open', { binaryPath: BIN, stream: false })
  console.log('reopen port=' + (o.result?.port))
  const got = await readPlate()
  console.log('after-unload plate=' + JSON.stringify(got))
  console.log('PERSISTED=' + (got === TOKEN) + '  (expect ' + TOKEN + ')')
  await call('ghidra_close', {})
  process.exit(0)
}
