// ioc-probe.mjs — 用已装副本直驱 IOC 工具做实测（不经 LLM）。
// 验证点：① 补丁 11：_range_len 对 MemoryBlock 曾返回 0 → includeRawMemory 扫 0 字节
//         ② 补丁 12：OID 表项（2.5.29.14 之类）不再混进 ipv4，改归 oid
//         ③ 注册表键：cmd.exe 里本来就没有 HKEY_* 字符串（原断言错），换成 reg.exe 验证
//
//   node ioc-probe.mjs
import { join } from 'node:path'
import { installedDir } from './lib/dev-env.mjs'
import { pathToFileURL } from 'node:url'

const INSTALLED = installedDir('web')

const tools = new Map()
const effects = []
const ctx = {
  effect(fn) { effects.push(fn) },
  tools: { register(t) { tools.set(t.name, t) } },
  jobs: { start() { return 'job-0' } },
  logger: { info() {}, warn() {}, error() {} },
}
const mod = await import(pathToFileURL(join(INSTALLED, 'index.js')).href)
mod.apply(ctx, mod.Config ? mod.Config({}) : {})
const call = (name, args) => tools.get(name).execute(args || {}, {})

async function open(label, path) {
  const r = await call('ghidra_open', { binaryPath: path, stream: false })
  console.log('\n==== open ' + label + ' → ok=' + r.ok + ' port=' + r.port +
    ' funcs=' + (r.result || {}).functions + (r.ok ? '' : ' ERR=' + r.error))
  if (!r.ok) process.exit(1)
}

function show(label, r, maxRows) {
  console.log('\n---- ' + label + ' ----')
  const res = r.result || {}
  console.log('ok=' + r.ok + ' error=' + (r.error || '-'))
  console.log('total=' + res.total + ' bytesScanned=' + res.bytesScanned +
    ' rawBlocksScanned=' + res.rawBlocksScanned + ' stringsScanned=' + res.stringsScanned +
    ' truncated=' + res.truncated)
  console.log('byType=' + JSON.stringify(res.byType))
  for (const row of (res.list || []).slice(0, maxRows || 12)) {
    console.log('   [' + row.type + '] ' + JSON.stringify(row.value) + '  src=' + row.source +
      ' @' + row.address + (row.function ? ' fn=' + row.function : ''))
  }
}

const C = 'C:\\Windows\\System32\\certutil.exe'
await open('certutil.exe', C)

show('全类型 + includeRawMemory maxBytes=2MB', await call('ghidra_extract_iocs_with_context',
  { includeRawMemory: true, maxBytes: 2097152, max: 200 }), 20)

show('types=ipv4（OID 修复后应为 0）', await call('ghidra_extract_iocs_with_context',
  { types: 'ipv4', max: 40 }), 15)

show('types=oid（应接管原来的 2.5.29.* 表项）', await call('ghidra_extract_iocs_with_context',
  { types: 'oid', max: 40 }), 10)

show('types=url,domain,mutex,winpath', await call('ghidra_extract_iocs_with_context',
  { types: 'url,domain,mutex,winpath', max: 60 }), 20)

show('types=registry（certutil 预期 0）', await call('ghidra_extract_iocs_with_context',
  { types: 'registry', max: 20 }), 10)

// 注册表键换到真有 HKEY_* 字符串的目标上验证（字节级侦察：reg.exe 里有 "HKEY_LOCAL_MACHINE\SOFTWARE"）
await open('reg.exe', 'C:\\Windows\\System32\\reg.exe')
show('reg.exe types=registry', await call('ghidra_extract_iocs_with_context',
  { types: 'registry', max: 20 }), 10)
show('reg.exe 全类型 + includeRawMemory 64KB', await call('ghidra_extract_iocs_with_context',
  { includeRawMemory: true, maxBytes: 65536, max: 40 }), 20)
