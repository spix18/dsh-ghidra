// bisect-save.mjs — 逐步重放 harness B3 的写侧序列，每一步之后写一个唯一 plate 标记并 ghidra_save，
// 再看新服务器（从磁盘加载）读回来的是不是那个标记。第一个 LOST 的步骤就是让 headless 收尾保存失效的元凶。
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
mod.apply(ctx, mod.Config ? mod.Config({}) : {})
const call = async (name, args) => {
  try { return await tools.get(name).execute(args || {}, {}) } catch (e) { return { ok: false, error: String((e && e.message) || e) } }
}
const readPlate = async () => {
  const r = await call('ghidra_get_comments', { address: '0x1400013c0' })
  return r.result?.list?.[0]?.plate
}

const steps = [
  ['set_comment plate', () => call('ghidra_set_comment', { address: '0x1400013c0', comment: 'BISECT-PLATE', type: 'plate' })],
  ['set_comment eol+post', () => call('ghidra_set_comment', { address: '0x1400013c4', comments: { eol: 'BISECT-EOL', post: 'BISECT-POST' } })],
  ['set_comment clear eol', () => call('ghidra_set_comment', { address: '0x1400013c4', comment: '', type: 'eol' })],
  ['set_comment pre batch', () => call('ghidra_set_comment', { addresses: ['0x1400013c0', '0x1400013c4'], comment: 'BISECT-PRE', type: 'pre' })],
  ['rename', () => call('ghidra_rename', { target: 'FUN_140001010', newName: 'BISECT_FN' })],
  ['rename back', () => call('ghidra_rename', { target: 'BISECT_FN', newName: 'FUN_140001010' })],
  ['label create', () => call('ghidra_label', { action: 'create', address: '0x140001010', names: ['BISECT_LA', 'BISECT_LB'] })],
  ['label delete', () => call('ghidra_label', { action: 'delete', address: '0x140001010', name: 'BISECT_LB' })],
  ['set_variables', () => call('ghidra_set_variables', { target: 'FUN_1400010f0', variables: [{ name: 'local_18', newName: 'bisect_local', newType: 'int' }] })],
  ['set_prototype', () => call('ghidra_set_prototype', { target: 'FUN_140001140', prototype: 'int FUN_140001140(char *buf, int len)' })],
  ['set_proto noRet=true', () => call('ghidra_set_prototype', { target: 'FUN_140001140', noReturn: true })],
  ['set_proto noRet=false', () => call('ghidra_set_prototype', { target: 'FUN_140001140', noReturn: false })],
  ['tags create', () => call('ghidra_tags', { action: 'create', name: 'BISECT-TAG', comment: 'bisect' })],
  ['tags attach', () => call('ghidra_tags', { action: 'attach', target: 'entry', tags: ['BISECT-TAG'] })],
  ['tags detach', () => call('ghidra_tags', { action: 'detach', target: 'entry', tags: ['BISECT-TAG'] })],
  ['tags delete', () => call('ghidra_tags', { action: 'delete', name: 'BISECT-TAG' })],
  ['delete_function', () => call('ghidra_delete_function', { address: 'FUN_140001010' })],
  ['create_function', () => call('ghidra_create_function', { address: '0x140001010', name: 'FUN_140001010' })],
]

const a = await call('ghidra_open', { binaryPath: BIN, stream: false })
console.log(ts() + 'open ok=' + a.ok + ' port=' + a.port + ' pid=' + a.pid)
try {
  await call('ghidra_set_comment', { address: '0x1400013c0', comment: 'MARK-0', type: 'plate' })
  const s0 = await call('ghidra_save', {})
  const p0 = await readPlate()
  console.log(ts() + 'BASE  read=' + p0 + '  ok=' + (p0 === 'MARK-0') + '  stop=' + s0.result?.stopMs + 'ms graceful=' + s0.result?.stopGraceful)

  let broken = 'none'
  for (let i = 0; i < steps.length; i++) {
    const [name, fn] = steps[i]
    const r = await fn()
    const mark = 'MARK-' + (i + 1)
    await call('ghidra_set_comment', { address: '0x1400013c0', comment: mark, type: 'plate' })
    const s = await call('ghidra_save', {})
    const got = await readPlate()
    const ok = got === mark
    if (!ok && broken === 'none') broken = name
    console.log(ts() + String(i + 1).padStart(2) + ' ' + name.padEnd(23) + ' op=' + (r.ok === true ? 'ok ' : 'ERR') +
      '  read=' + got + '  ' + (ok ? 'SAVED' : '*** LOST ***') + '  stop=' + s.result?.stopMs + 'ms')
  }
  console.log(ts() + 'FIRST_BROKEN_STEP=' + broken)
} catch (e) {
  console.log(ts() + 'UNCAUGHT ' + e)
}
await call('ghidra_close')
