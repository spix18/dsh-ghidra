// probe3d.mjs — 枚举型选项怎么读怎么写（SubOptions/Options 的 enum 方法）。
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const INSTALLED = process.argv[2] || 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra'
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
console.log('open ok port=' + open.port + '\n')

const probe = async (o) => {
  const r = await jsonRequest(open.port, { op: 'probe', ...o }, 120000)
  return r.ok ? r.result : { error: r.error }
}
const show = (title, res) => {
  console.log('===== ' + title + ' =====')
  if (res.error) { console.log('  ERROR: ' + res.error); return }
  if (res.class) console.log('  class: ' + res.class)
  for (const m of res.methods || []) console.log('  M  ' + m)
  console.log('')
}

show('Options.enum', await probe({ class: 'ghidra.framework.options.Options', match: 'enum' }))
show('SubOptions.enum', await probe({ class: 'ghidra.framework.options.SubOptions', match: 'enum' }))
show('Options.getType/register', await probe({ class: 'ghidra.framework.options.Options', match: 'gettype' }))
show('Options.getValue', await probe({ class: 'ghidra.framework.options.Options', match: 'getvalue' }))

console.log('close:', JSON.stringify(await call('ghidra_close')))
