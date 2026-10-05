// verify-batch3.mjs — 批次 3「分析自动化」14 个新工具的工具层验收。
// 驱动【已安装副本】的 defineTool.execute，不经 LLM（不受 provider 限流）。
//
//   node verify-batch3.mjs [另一个工作目录]
//
// 覆盖：run_script_inline（读/报错/写事务）、run_script_file（args + stdout）、
// list_analyzers、configure_analyzer（改回原值）、run_analysis、reanalyze、
// search_byte_patterns（通配/半字节/多模式/坏模式）、find_code_gaps、find_dead_code，
// 以及后半的 function_context（复合分析）、search_instructions、hash（函数级/程序级）、
// compare_functions、data_flow（变量定义/使用链），
// 最后用 ghidra_save 的 flush 路径验证「inline 写的注释真的落盘」。
import { spawnSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const INSTALLED = process.argv[2] && process.argv[2].includes('node_modules')
  ? process.argv[2]
  : 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra'
const workdir = process.argv[3] || process.argv[2] || process.cwd()
process.chdir(workdir)
console.log('cwd =', process.cwd())
console.log('installed =', INSTALLED)

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

const tools = new Map()
const effects = []
const ctx = {
  effect(fn) { effects.push(fn) },
  tools: { register(t) { tools.set(t.name, t); return () => { tools.delete(t.name) } } },
  jobs: { start() { return 'job-0' } },
  logger: { info() {}, warn() {}, error() {} },
  inject(names, cb) {
    const p = {}
    for (const n of names) if (n === 'webServer') p.webServer = { exact: new Map(), prefixes: new Map(), register() { return () => {} } }
    return cb(p)
  },
}
const mod = await import(pathToFileURL(join(INSTALLED, 'index.js')).href)
mod.apply(ctx, mod.Config ? mod.Config({}) : {})
const call = (name, args) => tools.get(name).execute(args || {}, {})

const TOKEN = 'B3-INLINE-' + Date.now()
const t0 = Date.now()
const opened = await call('ghidra_open', { binaryPath: 'C:\\Windows\\System32\\winver.exe', stream: false })
check('ghidra_open ok', opened.ok === true, 'ok=' + opened.ok + ' err=' + (opened.error || '-') + ' port=' + opened.port)
const FUNCS = opened.result?.functions

console.log('\n== A. ghidra_run_script_inline（只读） ==')
const inlineRead = await call('ghidra_run_script_inline', {
  code: "result = {'n': currentProgram.getFunctionManager().getFunctionCount(), 'name': currentProgram.getName(), 'callers': str(currentProgram.getCompiler())}\nprint('hello-from-inline')\nprintln('second-line')",
})
check('inline 只读 ok', inlineRead.ok === true, 'ok=' + inlineRead.ok + ' err=' + (inlineRead.error || inlineRead.result?.error || '-'))
check('result 原样回传', inlineRead.result?.result?.name === 'winver.exe' && inlineRead.result?.result?.n === FUNCS,
  'result=' + JSON.stringify(inlineRead.result?.result) + ' (info.functions=' + FUNCS + ')')
check('Python stdout 被捕获', String(inlineRead.result?.stdout || '').includes('hello-from-inline'), JSON.stringify(String(inlineRead.result?.stdout || '').slice(0, 80)))
check('println 也被捕获', String(inlineRead.result?.stdout || '').includes('second-line'), JSON.stringify(String(inlineRead.result?.stdout || '').slice(0, 120)))
check('defined 里能看到脚本新变量', Array.isArray(inlineRead.result?.defined) && inlineRead.result.defined.includes('result'), JSON.stringify(inlineRead.result?.defined))

console.log('\n== B. ghidra_run_script_inline（脚本报错不打断桥） ==')
const inlineErr = await call('ghidra_run_script_inline', { code: "print('before-boom')\nraise ValueError('boom-inline')" })
check('报错的脚本仍返回 ok=true', inlineErr.ok === true, 'ok=' + inlineErr.ok)
check('error 带原始异常文本', String(inlineErr.result?.error || '').includes('boom-inline'), JSON.stringify(inlineErr.result?.error))
check('traceback 存在', String(inlineErr.result?.traceback || '').includes('ValueError'), JSON.stringify(String(inlineErr.result?.traceback || '').slice(0, 120)))
check('报错前的 stdout 仍在', String(inlineErr.result?.stdout || '').includes('before-boom'), JSON.stringify(String(inlineErr.result?.stdout || '').slice(0, 80)))

console.log('\n== C. ghidra_run_script_inline（write=true 写事务） ==')
const inlineWrite = await call('ghidra_run_script_inline', {
  write: true,
  code: "from ghidra.program.model.listing import CodeUnit\n" +
    "a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x1400013c0)\n" +
    "currentProgram.getListing().setComment(a, CodeUnit.PLATE_COMMENT, '" + TOKEN + "')\n" +
    "result = str(a)",
})
check('inline 写 ok', inlineWrite.ok === true && inlineWrite.result?.error === undefined, 'ok=' + inlineWrite.ok + ' err=' + (inlineWrite.error || inlineWrite.result?.error || '-'))
check('changed 变 true', inlineWrite.result?.changed === true, 'changed=' + inlineWrite.result?.changed)
const cmt = await call('ghidra_get_comments', { address: '0x1400013c0' })
check('会话内读回 plate 等于 token', cmt.result?.list?.[0]?.plate === TOKEN, 'plate=' + JSON.stringify(cmt.result?.list?.[0]?.plate))

console.log('\n== D. ghidra_run_script_file（args + stdout） ==')
const scriptPath = join(tmpdir(), 'dsh-b3-script.py')
writeFileSync(scriptPath,
  "# dsh 批次 3 验收脚本\n" +
  "args = getScriptArgs()\n" +
  "print('file-script-ran')\n" +
  "result = {'program': currentProgram.getName(), 'args': args, 'scriptArgs': scriptArgs}\n", 'utf8')
const fileRun = await call('ghidra_run_script_file', { scriptPath, args: ['alpha', 'beta'] })
check('run_script_file ok', fileRun.ok === true && fileRun.result?.error === undefined, 'ok=' + fileRun.ok + ' err=' + (fileRun.error || fileRun.result?.error || '-'))
check('脚本拿到 args', JSON.stringify(fileRun.result?.result?.args) === JSON.stringify(['alpha', 'beta']), 'args=' + JSON.stringify(fileRun.result?.result?.args))
check('文件脚本 stdout 被捕获', String(fileRun.result?.stdout || '').includes('file-script-ran'), JSON.stringify(String(fileRun.result?.stdout || '').slice(0, 80)))
check('回传 scriptPath 与字节数', typeof fileRun.result?.scriptPath === 'string' && fileRun.result?.bytes > 0, 'bytes=' + fileRun.result?.bytes)
const badExt = join(tmpdir(), 'dsh-b3-script.java')
writeFileSync(badExt, '// not python\n', 'utf8')
let badExtErr = ''
try { await call('ghidra_run_script_file', { scriptPath: badExt }) } catch (e) { badExtErr = String(e.message || e) }
check('非 Python 脚本被明确拒绝', badExtErr.includes('只支持 Python 脚本'), JSON.stringify(badExtErr.slice(0, 140)))

console.log('\n== E. ghidra_list_analyzers ==')
const ana = await call('ghidra_list_analyzers', {})
check('list_analyzers ok', ana.ok === true && ana.result?.key === 'Analyzers', 'key=' + ana.result?.key + ' total=' + ana.result?.total + ' registered=' + ana.result?.registered)
check('注册分析器数量合理（>20）', ana.result?.total > 20, 'total=' + ana.result?.total)
const anaFiltered = await call('ghidra_list_analyzers', { filter: 'ASCII' })
check('filter 只留匹配项', anaFiltered.result?.total > 0 && anaFiltered.result.list.every((r) => r.name.toLowerCase().includes('ascii')),
  'total=' + anaFiltered.result?.total + ' first=' + JSON.stringify(anaFiltered.result?.list?.[0]?.name))
check('每行带 enabled/type/subOptions/description', anaFiltered.result?.list?.[0]?.enabled === true && typeof anaFiltered.result?.list?.[0]?.description === 'string',
  JSON.stringify(anaFiltered.result?.list?.[0]).slice(0, 200))

console.log('\n== F. ghidra_configure_analyzer（真值翻转：on→off→on） ==')
const anaOn = (await call('ghidra_list_analyzers', { filter: 'ASCII Strings', onlyEnabled: true })).result?.list?.[0]
const target = anaOn?.name
check('先找到一个当前启用的分析器', typeof target === 'string' && target.length > 0, 'target=' + JSON.stringify(target))
const off = await call('ghidra_configure_analyzer', { name: target, enabled: false })
check('关掉分析器 ok 且读回 false', off.ok === true && off.result?.now === false, 'now=' + JSON.stringify(off.result?.now) + ' applied=' + JSON.stringify(off.result?.applied))
const stillOff = (await call('ghidra_list_analyzers', { filter: target })).result?.list?.[0]
check('列表里也变成 false（真的写进选项）', stillOff?.enabled === false, 'enabled=' + JSON.stringify(stillOff?.enabled))
const on = await call('ghidra_configure_analyzer', { name: target, enabled: true })
check('再打开并读回 true', on.ok === true && on.result?.now === true, 'now=' + JSON.stringify(on.result?.now) + ' applied=' + JSON.stringify(on.result?.applied))
let badNameErr = ''
try { await call('ghidra_configure_analyzer', { name: 'NO SUCH ANALYZER XYZ', enabled: true }) } catch (e) { badNameErr = String(e.message || e) }
check('未知分析器名被明确拒绝', badNameErr.includes('没有这个分析选项'), JSON.stringify(badNameErr.slice(0, 140)))
const ENUM_OPT = 'ASCII Strings.Minimum String Length'
const enumRead = await call('ghidra_configure_analyzer', { name: ENUM_OPT })
check('读一个非布尔选项（ENUM）不报错', enumRead.ok === true, 'type=' + JSON.stringify(enumRead.result?.type) + ' now=' + JSON.stringify(enumRead.result?.now))
const enumVal = String(enumRead.result?.now)
const enumWrite = await call('ghidra_configure_analyzer', { name: ENUM_OPT, value: enumVal })
check('非布尔选项按真实类型写回（ENUM 走 setEnum）', enumWrite.ok === true && String(enumWrite.result?.applied?.value) === enumVal,
  'type=' + JSON.stringify(enumWrite.result?.type) + ' applied=' + JSON.stringify(enumWrite.result?.applied) + ' now=' + JSON.stringify(enumWrite.result?.now))
let badTypeErr = ''
try { await call('ghidra_configure_analyzer', { name: ENUM_OPT, value: '不是数字也不是合法枚举值' }) } catch (e) { badTypeErr = String(e.message || e) }
check('非法枚举值被明确拒绝', badTypeErr.length > 0, JSON.stringify(badTypeErr.slice(0, 160)))

console.log('\n== G. ghidra_search_byte_patterns ==')
const mz = await call('ghidra_search_byte_patterns', { pattern: '4D 5A ?? ??', limit: 3 })
check('通配搜索 ok', mz.ok === true && mz.result?.total >= 1, 'total=' + mz.result?.total + ' first=' + JSON.stringify(mz.result?.list?.[0]))
check('MZ 头命中 140000000', mz.result?.list?.[0]?.address === '140000000', 'first=' + JSON.stringify(mz.result?.list?.[0]))
const nib = await call('ghidra_search_byte_patterns', { pattern: '4? 5? 9? 0?', limit: 3 })
check('半字节通配可用', nib.ok === true && nib.result?.total >= 1, 'total=' + nib.result?.total + ' first=' + JSON.stringify(nib.result?.list?.[0]?.address))
const multi = await call('ghidra_search_byte_patterns', { pattern: '4D 5A ?? ?? | 50 45 00 00', limit: 5, executable: false })
check('多模式（|）都返回且带 pattern 字段', multi.ok === true && multi.result?.patterns?.length === 2 && multi.result.list.every((r) => typeof r.pattern === 'string'),
  'patterns=' + JSON.stringify(multi.result?.patterns) + ' total=' + multi.result?.total)
const execOnly = await call('ghidra_search_byte_patterns', { pattern: 'FF FF', executable: true, limit: 2 })
check('executable=true 只扫可执行块', execOnly.ok === true && execOnly.result.list.every((r) => !r.block.includes('Headers')),
  'blocks=' + JSON.stringify(execOnly.result?.list?.map((r) => r.block)))
let badPat = ''
try { await call('ghidra_search_byte_patterns', { pattern: 'ZZ ZZ' }) } catch (e) { badPat = String(e.message || e) }
check('非法模式被明确拒绝', badPat.includes('bytePattern'), JSON.stringify(badPat.slice(0, 140)))

console.log('\n== H. ghidra_find_code_gaps ==')
const gaps = await call('ghidra_find_code_gaps', { minSize: 1, limit: 5 })
check('find_code_gaps ok', gaps.ok === true && Array.isArray(gaps.result?.list), 'total=' + gaps.result?.total + ' scannedBlocks=' + gaps.result?.scannedBlocks)
check('没有块级错误（曾把 MemoryBlock 传给 getUndefinedRanges 而全部失败）', (gaps.result?.errors || []).length === 0,
  'errors=' + JSON.stringify(gaps.result?.errors).slice(0, 300))
check('空洞行字段完整', (gaps.result?.total === 0) || (gaps.result.list.every((r) => r.start && r.end && r.size >= 1 && typeof r.block === 'string')),
  JSON.stringify(gaps.result?.list?.[0]))

console.log('\n== I. ghidra_find_dead_code ==')
const dead = await call('ghidra_find_dead_code', { limit: 5 })
check('find_dead_code ok', dead.ok === true && Array.isArray(dead.result?.list), 'total=' + dead.result?.total + ' scanned=' + dead.result?.scanned)
check('候选都是 callers=0', (dead.result?.list || []).every((r) => r.callers === 0), JSON.stringify(dead.result?.list?.[0]))

console.log('\n== J. ghidra_reanalyze（小范围） ==')
const re = await call('ghidra_reanalyze', { target: 'entry' })
check('reanalyze ok（函数范围）', re.ok === true && String(re.result?.reanalyzed || '').includes('function'), 'reanalyzed=' + re.result?.reanalyzed + ' addresses=' + re.result?.addresses)

console.log('\n== K. ghidra_run_analysis（force=false） ==')
const tA = Date.now()
const ra = await call('ghidra_run_analysis', {})
check('run_analysis ok', ra.ok === true && ra.result?.ran === true, 'ok=' + ra.ok + ' ms=' + (Date.now() - tA) + ' elapsed=' + JSON.stringify(ra.result?.elapsedMs) + ' err=' + (ra.error || '-'))

console.log('\n== L. ghidra_function_context（复合分析） ==')
const ENTRY = '0x1400013c0'
const OTHER = '0x140001140'
const fc = await call('ghidra_function_context', { target: ENTRY })
const fcR = fc.result || {}
check('function_context ok', fc.ok === true && fcR.address === '1400013c0', 'address=' + fcR.address + ' name=' + fcR.name + ' err=' + (fc.error || fcR.error || '-'))
check('带签名/参数/局部变量/调用关系', typeof fcR.signature === 'string' && Array.isArray(fcR.parameters) && Array.isArray(fcR.locals) && Array.isArray(fcR.callees),
  'sig=' + JSON.stringify(fcR.signature) + ' params=' + (fcR.parameters || []).length + ' locals=' + (fcR.locals || []).length + ' callees=' + (fcR.callees || []).length)
check('指令统计与两种哈希都在', fcR.instructionCount >= 1 && /^[0-9a-f]{32}$/.test(String(fcR.codeMd5)) && /^[0-9a-f]{32}$/.test(String(fcR.mnemonicMd5)),
  'insns=' + fcR.instructionCount + ' codeMd5=' + fcR.codeMd5)
check('反编译器给了基本块/圈复杂度', fcR.decompiler && fcR.decompiler.basicBlocks >= 1 && typeof fcR.decompiler.cyclomaticComplexity === 'number',
  JSON.stringify(fcR.decompiler))
check('默认附伪代码（含函数名）', typeof fcR.pseudocode === 'string' && fcR.pseudocode.includes(String(fcR.name)), 'len=' + String(fcR.pseudocode || '').length)
check('能列出指向字符串的引用', Array.isArray(fcR.strings), 'strings=' + (fcR.strings || []).length)
const fcNoCode = await call('ghidra_function_context', { target: ENTRY, includeCode: false })
check('includeCode=false 时不返回伪代码', fcNoCode.ok === true && fcNoCode.result?.pseudocode === undefined, 'keys=' + JSON.stringify(Object.keys(fcNoCode.result || {}).slice(0, 6)))
let fcBad = ''
try { await call('ghidra_function_context', { target: '0x1' }) } catch (e) { fcBad = String(e.message || e) }
check('没有函数的地址被明确拒绝', fcBad.includes('no function at'), JSON.stringify(fcBad.slice(0, 140)))

console.log('\n== M. ghidra_search_instructions ==')
const siCall = await call('ghidra_search_instructions', { mnemonic: 'call', target: ENTRY })
check('按助记符搜（限定函数体）ok', siCall.ok === true && siCall.result?.total >= 1, 'total=' + siCall.result?.total + ' scope=' + siCall.result?.scope)
check('scope 标出函数且在函数体内', String(siCall.result?.scope || '').includes('function') && siCall.result.list.every((r) => r.mnemonic.toLowerCase().includes('call')),
  'scope=' + siCall.result?.scope + ' first=' + JSON.stringify(siCall.result?.list?.[0]))
const siReg = await call('ghidra_search_instructions', { pattern: '^MOV .*\\[RSP', limit: 5, caseSensitive: false })
check('整条指令正则可用', siReg.ok === true && (siReg.result?.total === 0 || siReg.result.list.every((r) => /^mov .*\[rsp/i.test(r.text))),
  'total=' + siReg.result?.total + ' first=' + JSON.stringify(siReg.result?.list?.[0]?.text))
const siOp = await call('ghidra_search_instructions', { operand: 'rsp', limit: 5 })
check('按操作数子串搜', siOp.ok === true && siOp.result.list.every((r) => r.text.toLowerCase().includes('rsp')), 'total=' + siOp.result?.total)
let siBad = ''
try { await call('ghidra_search_instructions', {}) } catch (e) { siBad = String(e.message || e) }
check('三个条件都不给时被拒绝', siBad.includes('至少要给'), JSON.stringify(siBad.slice(0, 120)))

console.log('\n== N. ghidra_hash（函数级 / 程序级） ==')
const hf = await call('ghidra_hash', { target: ENTRY })
const hfR = hf.result || {}
check('函数级哈希 ok', hf.ok === true && hfR.scope === 'function' && /^[0-9a-f]{32}$/.test(String(hfR.bytesHash)) && /^[0-9a-f]{32}$/.test(String(hfR.codeHash)) && /^[0-9a-f]{32}$/.test(String(hfR.mnemonicHash)),
  'bytesHash=' + hfR.bytesHash + ' instructions=' + hfR.instructions)
const hf2 = await call('ghidra_hash', { target: ENTRY })
check('同一函数两次哈希一致', hf2.result?.bytesHash === hfR.bytesHash && hf2.result?.codeHash === hfR.codeHash, 'again=' + hf2.result?.bytesHash)
const hprog = await call('ghidra_hash', { scope: 'program', algorithm: 'sha256' })
const hpR = hprog.result || {}
check('程序级哈希 ok（sha256）', hprog.ok === true && hpR.scope === 'program' && /^[0-9a-f]{64}$/.test(String(hpR.imageHash)),
  'imageHash=' + String(hpR.imageHash).slice(0, 16) + '… blocks=' + (hpR.blocks || []).length + ' bytes=' + hpR.hashedBytes)
check('逐块哈希 + Ghidra 记的可执行文件哈希', (hpR.blocks || []).length >= 1 && typeof hpR.executableMD5 === 'string' && hpR.executableMD5.length > 0,
  'md5=' + hpR.executableMD5 + ' format=' + hpR.executableFormat)
let hBad = ''
try { await call('ghidra_hash', { target: ENTRY, algorithm: 'crc32' }) } catch (e) { hBad = String(e.message || e) }
check('不支持的算法被拒绝', hBad.includes('只支持 md5/sha1/sha256'), JSON.stringify(hBad.slice(0, 120)))

console.log('\n== O. ghidra_compare_functions ==')
const selfCmp = await call('ghidra_compare_functions', { a: ENTRY, b: ENTRY })
check('自己比自己：相似度 1、无差异', selfCmp.ok === true && selfCmp.result?.textSimilarity === 1 && selfCmp.result?.mnemonicSimilarity === 1 && selfCmp.result?.sameMnemonicSequence === true,
  'text=' + selfCmp.result?.textSimilarity + ' mn=' + selfCmp.result?.mnemonicSimilarity + ' diffs=' + selfCmp.result?.differencesShown)
check('自己比自己：条数差 0、差异列表为空', selfCmp.result?.instructionCountDelta === 0 && (selfCmp.result?.firstDifferences || []).length === 0,
  JSON.stringify(selfCmp.result?.firstDifferences))
const crossCmp = await call('ghidra_compare_functions', { a: ENTRY, b: OTHER })
check('两个不同函数可比且相似度 < 1', crossCmp.ok === true && crossCmp.result?.textSimilarity < 1 && crossCmp.result?.a?.address === '1400013c0' && crossCmp.result?.b?.address === '140001140',
  'a=' + crossCmp.result?.a?.instructions + ' insns, b=' + crossCmp.result?.b?.instructions + ' insns, text=' + crossCmp.result?.textSimilarity)
check('回传参数与被调用函数差集', Array.isArray(crossCmp.result?.paramsOnlyInA) && Array.isArray(crossCmp.result?.calleesOnlyInB), JSON.stringify({ pA: crossCmp.result?.paramsOnlyInA, cB: crossCmp.result?.calleesOnlyInB }))
let cmpBad = ''
try { await call('ghidra_compare_functions', { a: ENTRY }) } catch (e) { cmpBad = String(e.message || e) }
check('只给 a 不给 b 时被拒绝（schema 或显式校验）', cmpBad.includes('需要 a 与 b') || cmpBad.includes('missing required property'), JSON.stringify(cmpBad.slice(0, 120)))

console.log('\n== P. ghidra_data_flow ==')
const dfList = await call('ghidra_data_flow', { target: OTHER, list: true })
check('list=true 列出高层变量', dfList.ok === true && Array.isArray(dfList.result?.variables) && typeof dfList.result?.params === 'number',
  'total=' + dfList.result?.total + ' params=' + dfList.result?.params + ' err=' + (dfList.error || dfList.result?.error || '-'))
const firstVar = dfList.result?.variables?.[0]?.name
check('至少有一个可追踪变量（取第一个）', typeof firstVar === 'string' && firstVar.length > 0, 'first=' + JSON.stringify(firstVar))
const dfFwd = await call('ghidra_data_flow', { target: OTHER, variable: firstVar, direction: 'both', depth: 3, max: 50 })
check('按变量追定义/使用链 ok', dfFwd.ok === true && Array.isArray(dfFwd.result?.ops) && dfFwd.result?.variable === firstVar,
  'variable=' + dfFwd.result?.variable + ' ops=' + (dfFwd.result?.ops || []).length + ' instances=' + (dfFwd.result?.instances || []).length + ' err=' + (dfFwd.error || dfFwd.result?.error || '-'))
check('每一步带 seqnum/深度/助记符', (dfFwd.result?.ops || []).length === 0 || dfFwd.result.ops.every((o) => o.seq && typeof o.depth === 'number' && typeof o.mnemonic === 'string'),
  JSON.stringify(dfFwd.result?.ops?.[0]))
let dfBad = ''
try { await call('ghidra_data_flow', { target: OTHER, variable: 'NO_SUCH_VAR_XYZ' }) } catch (e) { dfBad = String(e.message || e) }
check('未知变量被明确拒绝并给出候选', dfBad.includes('没有变量'), JSON.stringify(dfBad.slice(0, 140)))
let dfDir = ''
try { await call('ghidra_data_flow', { target: OTHER, direction: 'sideways' }) } catch (e) { dfDir = String(e.message || e) }
check('非法 direction 被拒绝', dfDir.includes('forward/backward/both'), JSON.stringify(dfDir.slice(0, 140)))

console.log('\n== Q. ghidra_save 的 flush 路径（inline 写的注释必须真落盘） ==')
const portBefore = opened.port
const saved = await call('ghidra_save')
check('ghidra_save ok 且 flushed', saved.ok === true && saved.result?.flushed === true, 'flushed=' + saved.result?.flushed + ' stopMs=' + saved.result?.stopMs + ' port=' + saved.result?.port)
check('flush 后是新端口', saved.result?.port !== portBefore, portBefore + ' → ' + saved.result?.port)
const back = await call('ghidra_get_comments', { address: '0x1400013c0' })
check('重开后 plate 仍是 inline 写的 token（真落盘）', back.result?.list?.[0]?.plate === TOKEN, 'plate=' + JSON.stringify(back.result?.list?.[0]?.plate) + ' want=' + TOKEN)

console.log('\n== R. close ==')
const closed = await call('ghidra_close')
check('ghidra_close ok', closed.ok === true && closed.result?.closed === true, JSON.stringify(closed.result))
await new Promise((r) => setTimeout(r, 1500))
check('close 后没有残留 java/python/py 进程', !pidAlive(saved.result?.pid), 'pid=' + saved.result?.pid + ' alive=' + pidAlive(saved.result?.pid))

console.log('\n==== ' + pass + '/' + (pass + fail) + ' PASS ====  (' + Math.round((Date.now() - t0) / 1000) + 's)')
if (fail === 0) console.log('BATCH3_E2E_OK')
else { console.log('TOOLS_E2E_FAILED'); process.exitCode = 1 }
