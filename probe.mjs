// probe.mjs — 开发者诊断：问 Java API 的真实形状。
// 走 DecompileBridge.py 的 probe op（只注册在 Python 的 OPS 里，不注册成 Node 工具），
// 用于在没有交互调试器的情况下确定某个类到底有哪些方法。
//
//   node probe.mjs [binaryPath]
//
// 结论会直接打印出来，不参与验收。
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
  for (const v of res.db_vars || []) console.log('  DB ' + v)
  for (const v of res.decompiler_vars || []) console.log('  DEC ' + v)
  for (const h of res.handles || []) console.log('  H  ' + JSON.stringify(h))
  console.log('')
}

show('handles', await probe({ handles: true }))
show('Function (tag 相关方法)', await probe({ class: 'ghidra.program.model.listing.Function', match: 'tag' }))
show('FunctionTag', await probe({ class: 'ghidra.program.model.listing.FunctionTag' }))
show('FunctionTagDB', await probe({ class: 'ghidra.program.database.function.FunctionTagDB' }))
show('C.CParserUtils.parseSignature', await probe({ class: 'ghidra.app.util.cparser.C.CParserUtils', match: 'parse' }))
show('DeleteFunctionCmd.applyTo', await probe({ class: 'ghidra.app.cmd.function.DeleteFunctionCmd', match: 'applyto' }))
show('vars @0x1400010f0', await probe({ locals: '0x1400010f0' }))

console.log('close:', JSON.stringify(await call('ghidra_close')))
