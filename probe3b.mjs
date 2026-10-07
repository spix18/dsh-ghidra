// probe3b.mjs — 批次 3 第二轮反射（probe 的 match 是**子串**匹配，不是正则，故一个 probe 只问一个词）。
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

show('Listing.getInstructions', await probe({ class: 'ghidra.program.model.listing.Listing', match: 'getinstruction' }))
show('Listing.getUndefined', await probe({ class: 'ghidra.program.model.listing.Listing', match: 'undefined' }))
show('Options.getOptionNames', await probe({ class: 'ghidra.framework.options.Options', match: 'optionname' }))
show('Options.boolean', await probe({ class: 'ghidra.framework.options.Options', match: 'boolean' }))
show('Program.analysis', await probe({ class: 'ghidra.program.model.listing.Program', match: 'analysis' }))
show('Memory.getBlock', await probe({ handle: 'mem', match: 'getblock' }))
show('MemoryBlock.execute', await probe({ class: 'ghidra.program.model.mem.MemoryBlock', match: 'execute' }))
show('MemoryBlock.initialized', await probe({ class: 'ghidra.program.model.mem.MemoryBlock', match: 'initialized' }))
show('AddressSet.add', await probe({ class: 'ghidra.program.model.address.AddressSet', match: 'add' }))
show('AddressSet.getAddressRanges', await probe({ class: 'ghidra.program.model.address.AddressSet', match: 'addressrange' }))
show('MessageLog.getMessage', await probe({ class: 'ghidra.app.util.importer.MessageLog', match: 'message' }))
show('SymbolTable.getExternal', await probe({ class: 'ghidra.program.model.symbol.SymbolTable', match: 'getexternal' }))

console.log('close:', JSON.stringify(await call('ghidra_close')))
