// probe3.mjs — 批次 3「分析自动化」的 Java API 反射。
// 走 DecompileBridge.py 的 probe op（只注册在 Python 的 OPS 里，不注册成 Node 工具）。
//
//   node probe3.mjs [已装副本目录] [binaryPath]
//
// 结论会直接打印出来，不参与验收。
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
console.log('open ok port=' + open.port + ' program=' + open.program + '\n')

const probe = async (o) => {
  const r = await jsonRequest(open.port, { op: 'probe', ...o }, 120000)
  return r.ok ? r.result : { error: r.error }
}

const show = (title, res) => {
  console.log('===== ' + title + ' =====')
  if (res.error) { console.log('  ERROR: ' + res.error); return }
  if (res.class) console.log('  class: ' + res.class)
  for (const m of res.methods || []) console.log('  M  ' + m)
  for (const f of res.fields || []) console.log('  F  ' + f)
  for (const h of res.handles || []) console.log('  H  ' + JSON.stringify(h))
  console.log('')
}

show('handles', await probe({ handles: true }))
show('analysis handle：分析相关方法', await probe({ handle: 'analysis', match: 'analy' }))
show('AutoAnalysisManager（全部）', await probe({ class: 'ghidra.app.plugin.core.analysis.AutoAnalysisManager' }))
show('Analyzer', await probe({ class: 'ghidra.app.services.Analyzer' }))
show('Memory.findBytes', await probe({ class: 'ghidra.program.model.mem.Memory', match: 'findbytes' }))
show('Listing（指令/代码单元）', await probe({ class: 'ghidra.program.model.listing.Listing', match: 'instruction|undefined|codeunit' }))
show('AddressSetView', await probe({ class: 'ghidra.program.model.address.AddressSetView' }))
show('AddressSet', await probe({ class: 'ghidra.program.model.address.AddressSet', match: 'add|iterator|getmin|getmax' }))
show('FunctionManager.getFunctions', await probe({ class: 'ghidra.program.model.listing.FunctionManager', match: 'getfunctions' }))

console.log('close:', JSON.stringify(await call('ghidra_close')))
