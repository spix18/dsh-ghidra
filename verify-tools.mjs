// verify-tools.mjs — 驱动【已安装副本】的**工具层**（index.js 的 ctx.tools.register 结果），
// 覆盖 ghidra_open(同步/流式 job 两条路径) → info/functions/strings/decompile/xrefs → close，
// 并断言 close 之后真正的 JVM 进程确实被杀掉（回归 pyghidra_launcher.py 提前退出导致孤儿 JVM 的 bug）。
//
//   node verify-tools.mjs [另一个工作目录]
//
// 直接调工具，不经过 LLM，所以不会被 provider 限流影响。
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const INSTALLED = 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra'
// 允许用第一个参数指定工作目录，验证「换工作区仍可用」
const workdir = process.argv[2] || process.cwd()
process.chdir(workdir)
console.log('cwd =', process.cwd())

let pass = 0, fail = 0
const check = (name, cond, detail) => {
  if (cond) { pass++; console.log('  PASS  ' + name + (detail ? '  → ' + detail : '')) }
  else { fail++; console.log('  FAIL  ' + name + '  → ' + detail) }
}

function pidAlive(pid) {
  if (!pid) return false
  const r = spawnSync('tasklist', ['/FI', 'PID eq ' + pid, '/NH'], { encoding: 'utf8' })
  return String(r.stdout || '').includes(String(pid))
}

// ---- 最小 cordis ctx 桩（只实现插件真正用到的方法） ----
const tools = new Map()
const effects = []
const jobs = []
const ctx = {
  effect(fn) { effects.push(fn) },
  tools: { register(t) { tools.set(t.name, t) } },
  jobs: { start(spec) { const id = 'job-' + jobs.length; const handle = spec.run(); jobs.push({ id, spec, handle }); return id } },
  logger: { info() {}, warn() {}, error() {} },
}

const mod = await import(pathToFileURL(join(INSTALLED, 'index.js')).href)
// 真实运行时是 cordis 用 Config schema 填默认值；桩环境下必须自己填，否则 pythonVer/stream 都是 undefined
const cfg = mod.Config ? mod.Config({}) : {}
console.log('config defaults =', JSON.stringify(cfg))
mod.apply(ctx, cfg)

const call = (name, args, exec) => tools.get(name).execute(args || {}, exec || {})

console.log('\n== A. 同步路径 ghidra_open(stream:false) ==')
const opened = await call('ghidra_open', { binaryPath: 'C:\\Windows\\System32\\winver.exe', stream: false })
check('ghidra_open ok', opened.ok === true, 'ok=' + opened.ok + ' err=' + (opened.error || '-'))
check('返回 port', Number.isInteger(opened.port) && opened.port > 0, 'port=' + opened.port)
check('返回真实 JVM pid（非 wrapper pid）', Number.isInteger(opened.pid) && opened.pid > 0, 'pid=' + opened.pid)
check('该 pid 进程当前存活', pidAlive(opened.pid), 'pid=' + opened.pid + ' alive=' + pidAlive(opened.pid))
check('info 已随 open 返回', opened.result && opened.result.program === 'winver.exe', 'program=' + opened.result?.program + ' functions=' + opened.result?.functions + ' blocks=' + opened.result?.blocks?.length)
const portFileText = readFileSync(join(process.env.TEMP, 'dsh-ghidra', 'port.txt'), 'utf8').trim()
check('port.txt 形如 "<port> <pid>"', /^\d+\s+\d+$/.test(portFileText), 'port.txt=' + JSON.stringify(portFileText))

console.log('\n== B. 各操作工具 ==')
const info = await call('ghidra_info')
check('ghidra_info ok', info.ok === true && info.result?.program === 'winver.exe', 'program=' + info.result?.program + ' functions=' + info.result?.functions + ' symbols=' + info.result?.symbols)
const fns = await call('ghidra_functions', { max: 3 })
check('ghidra_functions ok', fns.ok === true && fns.result.total > 0, 'total=' + fns.result?.total + ' first=' + fns.result?.list?.[0]?.name)
const strs = await call('ghidra_strings', { max: 3 })
check('ghidra_strings ok', strs.ok === true && strs.result.total > 0, 'total=' + strs.result?.total)
const dec = await call('ghidra_decompile', { target: 'entry' })
check('ghidra_decompile(entry) ok', dec.ok === true && typeof dec.result?.code === 'string' && dec.result.code.length > 0, 'function=' + dec.result?.function + ' addr=' + dec.result?.address + ' codeLen=' + dec.result?.code?.length)
const xr = await call('ghidra_xrefs', { target: 'entry' })
check('ghidra_xrefs ok', xr.ok === true, 'addr=' + xr.result?.address + ' total=' + xr.result?.total)

// ---- 批次 1：读侧补齐 11 个工具 ----
const tryCall = async (name, args) => {
  try { return await call(name, args) } catch (e) { return { ok: false, error: String((e && e.message) || e) } }
}

console.log('\n== B2. 批次 1 新工具（读侧补齐） ==')

const seg = await tryCall('ghidra_segments')
check('ghidra_segments ok', seg.ok === true && seg.result.total >= 5, 'total=' + seg.result?.total + ' err=' + (seg.error || '-'))
const segText = (seg.result?.list || []).find((r) => r.name === '.text')
check('segments 权限位格式正确', !!segText && /^[r-][w-][x-]$/.test(segText.rwx), '.text rwx=' + (segText && segText.rwx) + ' init=' + (segText && segText.initialized))
check('segments .text 可执行', !!segText && segText.rwx[2] === 'x', 'rwx=' + (segText && segText.rwx))

const imp = await tryCall('ghidra_imports', { max: 5 })
check('ghidra_imports ok', imp.ok === true, 'total=' + imp.result?.total + ' err=' + (imp.error || '-'))
check('imports 带所属库名', (imp.result?.list || []).every((r) => typeof r.library === 'string'), JSON.stringify((imp.result?.list || []).slice(0, 2)))

const exp = await tryCall('ghidra_exports')
check('ghidra_exports ok', exp.ok === true && exp.result.total >= 1, 'total=' + exp.result?.total + ' first=' + exp.result?.list?.[0]?.name + ' err=' + (exp.error || '-'))

const ss = await tryCall('ghidra_search_strings', { pattern: '^\\.', limit: 2 })
check('ghidra_search_strings 正则命中', ss.ok === true && ss.result.matched >= 1 && ss.result.total === 2, 'matched=' + ss.result?.matched + ' total=' + ss.result?.total + ' err=' + (ss.error || '-'))
const ssPage = await tryCall('ghidra_search_strings', { pattern: '^\\.', limit: 2, offset: 2 })
check('search_strings offset 翻页生效', ssPage.ok === true && ssPage.result.offset === 2 && (ssPage.result.list[0]?.address !== ss.result.list[0]?.address), 'p2first=' + ssPage.result?.list?.[0]?.value + ' p1first=' + ss.result?.list?.[0]?.value)
const ssBad = await tryCall('ghidra_search_strings', { pattern: '([' })
check('search_strings 坏正则报错而非崩溃', ssBad.ok === false, String(ssBad.error).slice(0, 60))

const sf = await tryCall('ghidra_search_functions', { pattern: '^FUN_', limit: 2 })
check('ghidra_search_functions 正则命中', sf.ok === true && sf.result.matched >= 2 && sf.result.total === 2, 'matched=' + sf.result?.matched + ' total=' + sf.result?.total + ' err=' + (sf.error || '-'))

const ca = await tryCall('ghidra_calls', { target: 'entry', direction: 'both' })
check('ghidra_calls ok', ca.ok === true && ca.result.function === 'entry', 'function=' + ca.result?.function + ' err=' + (ca.error || '-'))
const calleeNames = (ca.result?.callees?.list || []).map((r) => r.name)
check('calls callees 与反编译结果一致', calleeNames.includes('FUN_140001604') && calleeNames.includes('FUN_140001140'), 'callees=' + JSON.stringify(calleeNames))
check('calls 同时返回 callers 数组', Array.isArray(ca.result?.callers?.list), 'callers=' + ca.result?.callers?.total)

const cg = await tryCall('ghidra_call_graph', { target: 'entry', depth: 2 })
check('ghidra_call_graph ok', cg.ok === true && cg.result.nodes.length >= 2 && cg.result.edges.length >= 1, 'nodes=' + cg.result?.nodes?.length + ' edges=' + cg.result?.edges?.length + ' err=' + (cg.error || '-'))
check('call_graph root 为入口地址', cg.result?.root?.address === '1400013c0', 'root=' + JSON.stringify(cg.result?.root))

const rm = await tryCall('ghidra_read_memory', { address: '0x140000000', length: 32 })
check('ghidra_read_memory 读到 PE 头 "MZ"', rm.ok === true && String(rm.result?.rows?.[0]?.hex || '').startsWith('4d 5a'), 'l0=' + rm.result?.rows?.[0]?.hex + ' ascii=' + rm.result?.rows?.[0]?.ascii + ' err=' + (rm.error || '-'))
check('read_memory 行数/长度正确', rm.result?.length === 32 && rm.result?.rows?.length === 2, 'len=' + rm.result?.length + ' rows=' + rm.result?.rows?.length)

const da = await tryCall('ghidra_disassemble', { target: 'entry' })
check('ghidra_disassemble ok', da.ok === true && da.result.list.length >= 3 && da.result.list[0].address === '1400013c0', 'n=' + da.result?.list?.length + ' first=' + da.result?.list?.[0]?.address + ' ' + da.result?.list?.[0]?.text + ' err=' + (da.error || '-'))
check('disassemble 标明作用域为函数体', String(da.result?.scope || '').includes('entry'), 'scope=' + da.result?.scope)

const vr = await tryCall('ghidra_variables', { target: 'entry' })
check('ghidra_variables ok', vr.ok === true && vr.result.function === 'entry', JSON.stringify(vr.result).slice(0, 220) + ' err=' + (vr.error || '-'))
// 不假设 entry 一定无参：项目跨轮次累积，跑过 run_analysis/reanalyze 后 Ghidra 可能自己推出参数。
// 改成**与反编译签名对齐**的判据（这才是这个工具真正要保证的一致性）。
const decEntry = await tryCall('ghidra_decompile', { target: 'entry' })
const entrySig = String(decEntry.result?.signature || '')
const entryInner = (entrySig.match(/\(([^)]*)\)/) || [])[1] || ''
const entrySigParams = (entryInner.trim() === '' || entryInner.trim() === 'void') ? 0 : entryInner.split(',').length
check('variables 的参数数与反编译签名一致', Array.isArray(vr.result?.parameters) && vr.result.parameters.length === entrySigParams,
  'vars=' + (vr.result?.parameters || []).length + ' sig=' + entrySigParams + ' line=' + entrySig)
check('variables 返回结构完整（name/type/storage）', (vr.result?.parameters || []).every((p) => p.name && p.type) && Array.isArray(vr.result?.locals),
  'params=' + JSON.stringify(vr.result?.parameters))

const pc = await tryCall('ghidra_pcode', { target: 'entry', mode: 'listing', limit: 10 })
check('ghidra_pcode(listing) ok', pc.ok === true && pc.result.list.length >= 1 && pc.result.list[0].pcode.length >= 1, 'insns=' + pc.result?.list?.length + ' ops=' + pc.result?.total + ' err=' + (pc.error || '-'))
const pch = await tryCall('ghidra_pcode', { target: 'entry', mode: 'high', limit: 20 })
check('ghidra_pcode(high) ok', pch.ok === true && pch.result.list.length >= 1, 'ops=' + pch.result?.total + ' err=' + (pch.error || '-'))

console.log('\n== B3. 批次 2 写侧工具（改数据库 → save → 重开验证持久化） ==')

// --- 注释 ---
const sc1 = await tryCall('ghidra_set_comment', { address: 'entry', type: 'plate', comment: 'DSH-BATCH2-PLATE' })
check('set_comment(plate) ok', sc1.ok === true && sc1.result.applied.length === 1, JSON.stringify(sc1.result || sc1.error))
const gc1 = await tryCall('ghidra_get_comments', { address: 'entry' })
check('get_comments 读回 plate', gc1.ok === true && gc1.result.list[0]?.plate === 'DSH-BATCH2-PLATE', JSON.stringify(gc1.result?.list?.[0] || gc1.error))
const sc2 = await tryCall('ghidra_set_comment', { address: '0x1400013c4', comments: { eol: 'DSH-EOL', post: 'DSH-POST' } })
check('set_comment 一次多种类型', sc2.ok === true && sc2.result.applied.length === 2, JSON.stringify(sc2.result || sc2.error))
const gc2 = await tryCall('ghidra_get_comments', { address: '0x1400013c4' })
check('get_comments 多类型读回', gc2.result?.list?.[0]?.eol === 'DSH-EOL' && gc2.result?.list?.[0]?.post === 'DSH-POST', JSON.stringify(gc2.result?.list?.[0]))
const sc3 = await tryCall('ghidra_set_comment', { address: '0x1400013c4', type: 'post', comment: '' })
const gc3 = await tryCall('ghidra_get_comments', { address: '0x1400013c4' })
check('空字符串清除该类型注释', sc3.ok === true && gc3.result?.list?.[0]?.post === undefined && gc3.result?.list?.[0]?.eol === 'DSH-EOL', JSON.stringify(gc3.result?.list?.[0]))
const sc4 = await tryCall('ghidra_set_comment', { addresses: ['entry', '0x1400013c4'], type: 'pre', comment: 'DSH-PRE' })
check('set_comment 批量写多地址', sc4.ok === true && sc4.result.applied.length === 2, JSON.stringify(sc4.result || sc4.error))
const gc4 = await tryCall('ghidra_get_comments', { addresses: ['entry', '0x1400013c4'] })
check('batch_get_comments 两地址都读到', gc4.result?.list?.length === 2 && gc4.result.list.every((r) => r.pre === 'DSH-PRE'), JSON.stringify(gc4.result?.list))
const gc5 = await tryCall('ghidra_get_comments', { addresses: ['entry', 'entry'], onlyWithComments: true })
check('onlyWithComments 过滤生效', gc5.result?.list?.length === 2, 'n=' + gc5.result?.list?.length)
const gcBad = await tryCall('ghidra_get_comments', { address: 'zzz_no_such_symbol_xyz' })
check('get_comments 无法解析的目标报错而非崩溃', gcBad.ok === false, String(gcBad.error || JSON.stringify(gcBad.result)).slice(0, 80))

// --- 重命名 ---
const rn = await tryCall('ghidra_rename', { target: 'FUN_140001010', newName: 'DSH_RENAMED_FN' })
check('rename 函数 ok', rn.ok === true && rn.result.kind === 'function' && rn.result.oldName === 'FUN_140001010', JSON.stringify(rn.result || rn.error))
const rnSearch = await tryCall('ghidra_search_functions', { pattern: '^DSH_RENAMED_FN$' })
check('rename 后能按新名搜到', rnSearch.ok === true && rnSearch.result.matched === 1, 'matched=' + rnSearch.result?.matched)
const rnBack = await tryCall('ghidra_rename', { target: 'DSH_RENAMED_FN', newName: 'FUN_140001010' })
check('rename 支持按名定位并改回', rnBack.ok === true && rnBack.result.oldName === 'DSH_RENAMED_FN', JSON.stringify(rnBack.result || rnBack.error))

// --- 标签 ---
const lb1 = await tryCall('ghidra_label', { action: 'create', address: '0x140001010', names: ['DSH_LABEL_A', 'DSH_LABEL_B'] })
check('label create 多标签 ok', lb1.ok === true && lb1.result.total === 2, JSON.stringify(lb1.result || lb1.error))
const lb2 = await tryCall('ghidra_label', { action: 'list', target: '0x140001010' })
check('label list 读到新建标签', lb2.ok === true && (lb2.result.list || []).some((r) => r.name === 'DSH_LABEL_A'), JSON.stringify(lb2.result || lb2.error).slice(0, 300))
const lbListFn = await tryCall('ghidra_label', { action: 'list', target: 'FUN_140001140' })
check('label list 支持按函数列出体内符号', lbListFn.ok === true && lbListFn.result.total >= 1, JSON.stringify(lbListFn.result || lbListFn.error).slice(0, 200))
const lb3 = await tryCall('ghidra_label', { action: 'delete', address: '0x140001010', name: 'DSH_LABEL_A' })
check('label delete 指定名 ok', lb3.ok === true && lb3.result.total === 1 && lb3.result.list[0].name === 'DSH_LABEL_A', JSON.stringify(lb3.result || lb3.error))
await tryCall('ghidra_label', { action: 'delete', address: '0x140001010', name: 'DSH_LABEL_B' })

// --- 变量类型/改名（自动挑一个真实局部变量） ---
// 用**地址**而不是函数名：项目是跨轮次累积的，历史会话可能把 FUN_1400010f0 改过名
// （真实踩过：GUI 会话里 set_prototype 改了签名名 → 按旧名解析直接失败）。
const VAR_TARGET = '0x1400010f0'
const vBefore = await tryCall('ghidra_variables', { target: VAR_TARGET })
const localName = (vBefore.result?.locals || [])[0]?.name
check('set_variables 前先探测到真实局部变量', !!localName, 'local=' + localName + ' n=' + (vBefore.result?.locals || []).length + ' target=' + VAR_TARGET)
if (localName) {
  const sv = await tryCall('ghidra_set_variables', { target: VAR_TARGET, variables: [{ name: localName, newName: 'dsh_local', newType: 'int' }] })
  check('set_variables 改名+改类型 ok', sv.ok === true && sv.result.applied.length === 1, JSON.stringify(sv.result || sv.error))
  const vAfter = await tryCall('ghidra_variables', { target: VAR_TARGET })
  const renamed = (vAfter.result?.locals || []).find((r) => r.name === 'dsh_local')
  check('set_variables 改后能读回新名与新类型', !!renamed && String(renamed.type).includes('int'), JSON.stringify(renamed || vAfter.result?.locals?.slice(0, 3)))
}
const svBad = await tryCall('ghidra_set_variables', { target: VAR_TARGET, variables: [{ name: 'no_such_var_xyz', newName: 'x' }] })
check('set_variables 不存在的变量进 failed 而非抛错', svBad.ok === true && svBad.result.failed.length === 1, JSON.stringify(svBad.result?.failed || svBad.error))
const svBadType = await tryCall('ghidra_set_variables', { target: VAR_TARGET, variables: [{ name: localName || 'x', newType: 'no_such_type_xyz' }] })
check('set_variables 未知类型进 failed', svBadType.ok === true && svBadType.result.failed.length === 1, JSON.stringify(svBadType.result?.failed || svBadType.error))

// --- 函数原型 / 调用约定 / 无返回 ---
const sp = await tryCall('ghidra_set_prototype', { target: 'FUN_140001140', prototype: 'int FUN_140001140(char *buf, int len)' })
check('set_prototype ok', sp.ok === true && String(sp.result?.signature || '').includes('char *'), 'sig=' + sp.result?.signature + ' err=' + (sp.error || '-'))
const vrAfterPrototype = await tryCall('ghidra_variables', { target: 'FUN_140001140' })
check('set_prototype 后参数表变为 2 个', vrAfterPrototype.result?.parameters?.length === 2, 'params=' + JSON.stringify((vrAfterPrototype.result?.parameters || []).map((p) => p.name + ':' + p.type)))
const snr = await tryCall('ghidra_set_prototype', { target: 'FUN_140001140', noReturn: true })
check('set_prototype noReturn=true ok', snr.ok === true && snr.result.noReturn === true, JSON.stringify(snr.result || snr.error))
const snr2 = await tryCall('ghidra_set_prototype', { target: 'FUN_140001140', noReturn: false })
check('set_prototype noReturn=false 可复位', snr2.ok === true && snr2.result.noReturn === false, JSON.stringify(snr2.result || snr2.error))
const spBad = await tryCall('ghidra_set_prototype', { target: 'FUN_140001140', prototype: 'int ???bad(' })
check('set_prototype 坏原型报错而非崩溃', spBad.ok === false, String(spBad.error).slice(0, 80))

// --- 函数标签 ---
const tg1 = await tryCall('ghidra_tags', { action: 'create', name: 'DSH-TAG', comment: 'batch2 test' })
check('tags create ok', tg1.ok === true && tg1.result.created === true, JSON.stringify(tg1.result || tg1.error))
const tg2 = await tryCall('ghidra_tags', { action: 'attach', target: 'entry', tags: ['DSH-TAG'] })
check('tags attach ok', tg2.ok === true && tg2.result.attach.length === 1, JSON.stringify(tg2.result || tg2.error))
const tg3 = await tryCall('ghidra_tags', { action: 'get', target: 'entry' })
check('tags get 读到已挂标签', tg3.ok === true && tg3.result.tags.includes('DSH-TAG'), JSON.stringify(tg3.result || tg3.error))
const tg4 = await tryCall('ghidra_tags', { action: 'search', tag: 'DSH-TAG' })
check('tags search 找到函数', tg4.ok === true && tg4.result.total === 1 && tg4.result.list[0].name === 'entry', JSON.stringify(tg4.result || tg4.error))
const tg5 = await tryCall('ghidra_tags', { action: 'detach', target: 'entry', tags: ['DSH-TAG'] })
const tg6 = await tryCall('ghidra_tags', { action: 'get', target: 'entry' })
// 只看**本次挂上的**标签是否摘掉：项目里可能还留着历史会话挂的其他标签（如 GUI-TAG-LIVE）
check('tags detach ok', tg5.ok === true && !(tg6.result?.tags || []).includes('DSH-TAG'), JSON.stringify(tg6.result || tg6.error))
const tg7 = await tryCall('ghidra_tags', { action: 'delete', name: 'DSH-TAG' })
const tg8 = await tryCall('ghidra_tags', { action: 'list' })
check('tags delete 后列表里没有了', tg7.ok === true && !(tg8.result?.list || []).some((t) => t.name === 'DSH-TAG'), 'tags=' + JSON.stringify((tg8.result?.list || []).map((t) => t.name)))

// --- 函数创建 / 删除 ---
const del = await tryCall('ghidra_delete_function', { address: 'FUN_140001010' })
check('delete_function ok', del.ok === true && del.result.deleted === true && del.result.name === 'FUN_140001010', JSON.stringify(del.result || del.error))
const delCheck = await tryCall('ghidra_calls', { target: '0x140001010' })
check('删除后该地址已无函数', delCheck.ok === false, String(delCheck.error).slice(0, 70))
const crt = await tryCall('ghidra_create_function', { address: '0x140001010', name: 'FUN_140001010' })
check('create_function ok（含先反汇编）', crt.ok === true && crt.result.function === 'FUN_140001010', JSON.stringify(crt.result || crt.error))
const crtCheck = await tryCall('ghidra_disassemble', { target: '0x140001010' })
check('重建后能反汇编该函数', crtCheck.ok === true && crtCheck.result.function === 'FUN_140001010', 'scope=' + crtCheck.result?.scope)
const crtBad = await tryCall('ghidra_create_function', { address: '0x14000f000' })
check('create_function 空地址返回明确错误', crtBad.ok === false && /createFunction failed/.test(String(crtBad.error)), String(crtBad.error).slice(0, 90))

// --- 保存 ---
const sv = await tryCall('ghidra_save')
check('save 报告 changed=true 且 saved=true', sv.ok === true && sv.result.changed === true && sv.result.saved === true, JSON.stringify(sv.result || sv.error))
const sv2 = await tryCall('ghidra_save')
check('第二次 save 无改动可跳过', sv2.ok === true && sv2.result.changed === false, JSON.stringify(sv2.result || sv2.error))

console.log('\n== C. 关闭并确认无孤儿 JVM ==')
const pidBeforeClose = opened.pid
const closed = await call('ghidra_close')
check('ghidra_close ok', closed.ok === true, JSON.stringify(closed.result || closed))
await new Promise((r) => setTimeout(r, 4000))
check('close 后真实 JVM 已消失（孤儿回归）', !pidAlive(pidBeforeClose), 'pid=' + pidBeforeClose + ' alive=' + pidAlive(pidBeforeClose))

console.log('\n== D. 流式/job 路径 ghidra_open(默认 stream=true) ==')
const jobRes = await call('ghidra_open', { binaryPath: 'C:\\Windows\\System32\\winver.exe' })
check('返回后台任务', jobRes.kind === 'background' && !!jobRes.jobId, JSON.stringify({ kind: jobRes.kind, jobId: jobRes.jobId }))
const handle = jobs[jobs.length - 1].handle
const done = await handle.done
check('job 完成', done.status === 'completed', JSON.stringify(done))
const out = handle.readOutput()
check('job 流式输出含就绪行', /port=\d+/.test(out), JSON.stringify(out.slice(-120)))
const st = await call('ghidra_status')
check('status 显示 running', st.result?.server?.running === true, JSON.stringify(st.result?.server))
const gcSaved = await tryCall('ghidra_get_comments', { address: 'entry' })
check('重开后 plate 注释仍在（ghidra_save 真落盘）', gcSaved.result?.list?.[0]?.plate === 'DSH-BATCH2-PLATE', JSON.stringify(gcSaved.result?.list?.[0] || gcSaved.error))
const fnSaved = await tryCall('ghidra_search_functions', { pattern: '^FUN_140001010$' })
check('重开后重建的函数仍在', fnSaved.result?.matched === 1, 'matched=' + fnSaved.result?.matched + ' err=' + (fnSaved.error || '-'))
const tgSaved = await tryCall('ghidra_tags', { action: 'list' })
check('重开后标签删除结果仍在（列表里没有 DSH-TAG）', tgSaved.ok === true && !(tgSaved.result?.list || []).some((t) => t.name === 'DSH-TAG'), 'tags=' + JSON.stringify((tgSaved.result?.list || []).map((t) => t.name)))
const pid2 = jobs.length && st.result?.server?.port
await call('ghidra_close')
await new Promise((r) => setTimeout(r, 3000))
const alive = spawnSync('tasklist', ['/FI', 'IMAGENAME eq java.exe', '/NH'], { encoding: 'utf8' })
check('全部关闭后无 java.exe 残留', !String(alive.stdout || '').includes('java.exe'), String(alive.stdout || '').trim().slice(0, 80) || '(none)')

console.log('\n== E. dispose 钩子 ==')
check('ctx.effect 注册了清理函数', effects.length === 1 && typeof effects[0] === 'function')
effects[0] && effects[0]()

console.log('\n==== ' + pass + '/' + (pass + fail) + ' PASS ====')
if (fail === 0) console.log('TOOLS_E2E_OK')
else { console.log('TOOLS_E2E_FAILED'); process.exitCode = 1 }
