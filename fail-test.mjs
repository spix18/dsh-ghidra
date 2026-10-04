// fail-test.mjs — 定位「哪个失败 op 会毒化事务/破坏落盘」。
// 假说：_Tx.__exit__ 在异常时调 endTransaction(tid, False)（abort 子事务），
// Ghidra 不允许 abort 子事务 → 异常被 except: pass 吞掉 → 子事务悬空不关 →
// 之后的写都挂在这个悬空事务下 → headless 收尾提交时全部丢弃（但仍报 Save succeeded）。
// 每个候选隔离验证：open → 探事务 → 跑失败 op → 再探事务（是否变对象）→ 写 plate → flush → 读回。
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const INSTALLED = 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra'
const BIN = 'C:\\Windows\\System32\\winver.exe'

const tools = new Map()
const ctx = {
  effect() {},
  tools: { register(t) { tools.set(t.name, t) } },
  jobs: { start() { return 'job-0' } },
  logger: { info() {}, warn() {}, error() {} },
}
const mod = await import(pathToFileURL(join(INSTALLED, 'index.js')).href)
const sock = await import(pathToFileURL(join(INSTALLED, 'lib', 'socket.js')).href)
mod.apply(ctx, mod.Config ? mod.Config({}) : {})
const call = async (name, args) => {
  try { return await tools.get(name).execute(args || {}, {}) } catch (e) { return { ok: false, error: String((e && e.message) || e) } }
}
const tx = async (port) => {
  try { const r = await sock.jsonRequest(port, { op: 'probe', tx: true }, 60000); return r.result }
  catch (e) { return { err: String(e) } }
}
const readPlate = async () => {
  const r = await call('ghidra_get_comments', { address: '0x1400013c0' })
  return r.result?.list?.[0]?.plate
}

const CASES = [
  ['create_function 坏地址', 'ghidra_create_function', { address: '0x14000f000' }],
  ['set_prototype 坏签名', 'ghidra_set_prototype', { target: 'FUN_140001140', prototype: 'int ???bad(' }],
  ['set_variables 坏变量名', 'ghidra_set_variables', { target: 'FUN_1400010f0', variables: [{ name: 'no_such_var_xyz', newName: 'x' }] }],
  ['set_variables 坏类型', 'ghidra_set_variables', { target: 'FUN_1400010f0', variables: [{ name: 'local_18', newType: 'no_such_type_xyz' }] }],
  ['search_strings 坏正则', 'ghidra_search_strings', { pattern: '([' }],
  ['get_comments 坏地址', 'ghidra_get_comments', { address: 'zzz_no_such_symbol_xyz' }],
  ['tags attach 不存在的标签', 'ghidra_tags', { action: 'attach', target: 'entry', tags: ['NO-SUCH-TAG-XYZ'] }],
  ['rename 不存在的函数', 'ghidra_rename', { target: 'NO_SUCH_FN_XYZ', newName: 'X' }],
]

for (const [label, tool, args] of CASES) {
  const o = await call('ghidra_open', { binaryPath: BIN, stream: false })
  const before = await tx(o.port)
  const res = await call(tool, args)
  const after = await tx(o.port)
  const TOKEN = 'FT-' + Date.now()
  await call('ghidra_set_comment', { address: '0x1400013c0', comment: TOKEN, type: 'plate' })
  await call('ghidra_save')
  const got = await readPlate()
  const sameTx = before.tx === after.tx
  console.log(
    '[CASE] ' + label +
    '\n   opOk=' + res.ok + ' err=' + String(res.error || '').slice(0, 80) +
    '\n   txSame=' + sameTx + (sameTx ? '' : '\n   before=' + before.tx + '\n   after =' + after.tx) +
    '\n   PERSISTED=' + (got === TOKEN) + ' (got ' + got + ')')
  await call('ghidra_close')
}

// 收尾：清掉失败用例留下的垃圾标签（本脚本可重复运行，不给 harness 留污染）
{
  const o = await call('ghidra_open', { binaryPath: BIN, stream: false })
  await call('ghidra_tags', { action: 'detach', target: 'entry', tags: ['NO-SUCH-TAG-XYZ'] })
  const del = await call('ghidra_tags', { action: 'delete', name: 'NO-SUCH-TAG-XYZ' })
  const got = await call('ghidra_tags', { action: 'get', target: 'entry' })
  console.log('[CLEANUP] delete=' + JSON.stringify(del.result || del.error) + ' entryTags=' + JSON.stringify(got.result?.tags))
  await call('ghidra_close')
}
