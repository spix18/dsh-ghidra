// probe4.mjs — 批次 3 后半（复合函数分析 / 指令搜索 / 哈希与比较 / 数据流）的 API 反射。
// 注意 probe 的 match 是**子串**匹配，不是正则；一轮约 40 秒。
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
  console.log('')
}

show('HighVariable', await probe({ class: 'ghidra.program.model.pcode.HighVariable' }))
show('Varnode.def/descendants', await probe({ class: 'ghidra.program.model.pcode.Varnode', match: 'def' }))
show('Varnode.getDescendants', await probe({ class: 'ghidra.program.model.pcode.Varnode', match: 'descendant' }))
show('PcodeOp.mnemonic/inputs/output', await probe({ class: 'ghidra.program.model.pcode.PcodeOp', match: 'get' }))
show('HighFunction', await probe({ class: 'ghidra.program.model.pcode.HighFunction', match: 'get' }))
show('HighSymbol', await probe({ class: 'ghidra.program.model.pcode.HighSymbol', match: 'get' }))
show('LocalSymbolMap', await probe({ class: 'ghidra.program.model.pcode.LocalSymbolMap', match: 'get' }))
show('Program executable hash', await probe({ class: 'ghidra.program.model.listing.Program', match: 'executable' }))
show('Memory.getBytes', await probe({ handle: 'mem', match: 'getbytes' }))
show('BasicBlockModel', await probe({ class: 'ghidra.program.model.block.BasicBlockModel', match: 'getcodeblocks' }))

console.log('close:', JSON.stringify(await call('ghidra_close')))
