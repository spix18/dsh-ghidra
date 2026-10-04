// probe2.mjs — 查 Program 的 change-set / transaction 相关 API。
// 目的：判断「写进程序了、save 也报成功、但磁盘没变」是不是因为 getChanges() 为空（没有待保存改动）。
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const INSTALLED = 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra'
const binary = process.argv[2] || 'C:\\Windows\\System32\\winver.exe'

const tools = new Map()
const ctx = {
  effect() {},
  tools: { register(t) { tools.set(t.name, t) } },
  jobs: { start() { return 'job-0' } },
  logger: { info() {}, warn() {}, error() {} },
}
const mod = await import(pathToFileURL(join(INSTALLED, 'index.js')).href)
mod.apply(ctx, mod.Config({}))
const { jsonRequest } = await import(pathToFileURL(join(INSTALLED, 'lib', 'socket.js')).href)
const call = (n, a) => tools.get(n).execute(a || {}, {})

const open = await call('ghidra_open', { binaryPath: binary, stream: false })
if (!open.ok) { console.error('open failed:', open.error); process.exit(1) }
console.log('open ok port=' + open.port + '\n')
const probe = async (o) => {
  const r = await jsonRequest(open.port, { op: 'probe', ...o }, 120000)
  return r.ok ? r.result : { error: r.error }
}
const show = (title, res) => {
  console.log('===== ' + title + ' =====')
  if (res.error) { console.log('  ERROR: ' + res.error); return }
  for (const m of res.methods || []) console.log('  M  ' + m)
  for (const k of Object.keys(res)) console.log('  .' + k + ' = ' + JSON.stringify(res[k]))
  console.log('')
}
for (const c of ['ghidra.program.database.ProgramDB', 'ghidra.framework.model.DomainObject', 'ghidra.framework.model.Transaction']) {
  show(c, await probe({ class: c, match: process.argv[3] || 'change|transaction|save|lock' }))
}
console.log('close:', JSON.stringify(await call('ghidra_close')))
