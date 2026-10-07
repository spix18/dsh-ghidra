// probe3c.mjs — 确认「分析选项」的真实键名与内容（probe {analysis:true}）。
import { join } from 'node:path'
import { installedDir } from './lib/dev-env.mjs'
import { pathToFileURL } from 'node:url'

const INSTALLED = process.argv[2] || installedDir('web')
const binary = process.argv[3] || 'C:\\Windows\\System32\\winver.exe'

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
console.log('open ok port=' + open.port + ' program=' + open.program + '\n')

const r = await jsonRequest(open.port, { op: 'probe', analysis: true }, 120000)
console.log(JSON.stringify(r.ok ? r.result : { error: r.error }, null, 1))

console.log('close:', JSON.stringify(await call('ghidra_close')))
