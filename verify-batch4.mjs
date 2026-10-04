// verify-batch4.mjs — 批次 4「恶意代码分析」4 个新工具的工具层验收。
// 驱动【已安装副本】的 defineTool.execute，不经 LLM（不受 provider 限流）。
//
//   node verify-batch4.mjs [工作目录]
//
// 目标选择不是随手挑的（都用字节级侦察确认过）：
//   winver.exe    —— 负对照：32KB 小样本，全表扫描必须 0 命中（避免"永远有结果"的假绿）
//   kernel32.dll  —— 真阳性：含完整 CRC32 表（poly 0xEDB88320，1024 字节）+ 前缀
//   cmd.exe       —— 行为/反分析：导入表里有 CreateProcessW/RegOpenKeyExW/IsDebuggerPresent/
//                    OpenProcess，0xCC 出现上万次（**没有** HKEY_* 字符串，别拿它测注册表）
//   certutil.exe  —— IOC：11 个 CT 日志域名 + 若干 URL + 5 个互斥体 + 180 条点分十进制 OID
//   reg.exe       —— 注册表键：唯一含 "HKEY_LOCAL_MACHINE\SOFTWARE" 的小样本
// 首次分析这几个目标要花几分钟，之后项目里就缓存了。
import { spawnSync } from 'node:child_process'
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
  tools: { register(t) { tools.set(t.name, t) } },
  jobs: { start() { return 'job-0' } },
  logger: { info() {}, warn() {}, error() {} },
}
const mod = await import(pathToFileURL(join(INSTALLED, 'index.js')).href)
mod.apply(ctx, mod.Config ? mod.Config({}) : {})
const call = (name, args) => tools.get(name).execute(args || {}, {})

const t0 = Date.now()
const WINVER = 'C:\\Windows\\System32\\winver.exe'
const KERNEL32 = 'C:\\Windows\\System32\\kernel32.dll'
const CMD = 'C:\\Windows\\System32\\cmd.exe'
const CERTUTIL = 'C:\\Windows\\System32\\certutil.exe'
const REG = 'C:\\Windows\\System32\\reg.exe'

async function open(label, path) {
  const r = await call('ghidra_open', { binaryPath: path, stream: false })
  check('ghidra_open ' + label, r.ok === true, 'ok=' + r.ok + ' err=' + (r.error || '-') + ' port=' + r.port +
    ' funcs=' + r.result?.functions + ' (' + Math.round((Date.now() - t0) / 1000) + 's)')
  return r
}

// ---------------------------------------------------------------- A. 负对照 + 过滤
console.log('\n== A. ghidra_detect_crypto_constants（winver.exe 负对照 + 过滤） ==')
const w = await open('winver.exe', WINVER)
const cAll = await call('ghidra_detect_crypto_constants', {})
const cR = cAll.result || {}
check('未过滤扫描 ok', cAll.ok === true, 'ok=' + cAll.ok + ' err=' + (cAll.error || cR.error || '-'))
check('签名表规模合理（>=25 条）', Number(cR.signaturesAvailable) >= 25 && cR.signaturesScanned === cR.signaturesAvailable,
  'available=' + cR.signaturesAvailable + ' scanned=' + cR.signaturesScanned)
check('★ 负对照：winver.exe 里一条加密常量表都没有', Array.isArray(cR.list) && cR.list.length === 0 && cR.total === 0,
  'total=' + cR.total + ' list=' + JSON.stringify((cR.list || []).slice(0, 3)))
check('truncated 是布尔', typeof cR.truncated === 'boolean', 'truncated=' + cR.truncated)

const cAes = await call('ghidra_detect_crypto_constants', { filter: 'aes' })
const cAesR = cAes.result || {}
check('filter=aes 只扫 AES 类签名', cAes.ok === true && cAesR.signaturesScanned >= 1 && cAesR.signaturesScanned < cR.signaturesAvailable,
  'scanned=' + cAesR.signaturesScanned + '/' + cAesR.signaturesAvailable)
const cSha = await call('ghidra_detect_crypto_constants', { filter: 'sha-256' })
check('filter 支持算法名（sha-256）', cSha.ok === true && cSha.result?.signaturesScanned >= 1 && cSha.result?.signaturesScanned <= 6,
  'scanned=' + cSha.result?.signaturesScanned)
const cBlock = await call('ghidra_detect_crypto_constants', { blockFilter: 'NO_SUCH_BLOCK_XYZ' })
check('blockFilter 指到不存在的块 → 0 命中', cBlock.ok === true && cBlock.result?.total === 0,
  'total=' + cBlock.result?.total + ' scanned=' + cBlock.result?.signaturesScanned)
const cLim = await call('ghidra_detect_crypto_constants', { limit: 999 })
check('limit 超上限被夹到 64 且不报错', cLim.ok === true && cLim.result?.total === 0,
  'ok=' + cLim.ok + ' total=' + cLim.result?.total)

// ---------------------------------------------------------------- B. 真阳性（kernel32.dll）
console.log('\n== B. ghidra_detect_crypto_constants（kernel32.dll 真阳性） ==')
const k = await open('kernel32.dll', KERNEL32)
const cK = await call('ghidra_detect_crypto_constants', {})
const cKR = cK.result || {}
const names = (cKR.list || []).map((r) => r.constant)
check('扫描 ok', cK.ok === true, 'ok=' + cK.ok + ' err=' + (cK.error || cKR.error || '-'))
check('★ 真阳性：找到完整 CRC32 表', names.includes('CRC32 table (full)'),
  'total=' + cKR.total + ' constants=' + JSON.stringify([...new Set(names)]))
check('同时找到它的前缀签名', names.includes('CRC32 table prefix'), JSON.stringify([...new Set(names)]))
const crcRow = (cKR.list || []).find((r) => r.constant === 'CRC32 table (full)')
check('命中行形状完整（constant/algorithm/address/block/length/note）',
  !!crcRow && crcRow.algorithm === 'CRC-32' && /^[0-9a-f]+$/i.test(String(crcRow.address)) &&
  typeof crcRow.block === 'string' && crcRow.block.length > 0 && crcRow.length === 1024 && crcRow.note.length > 0,
  JSON.stringify(crcRow))
const cKRdata = await call('ghidra_detect_crypto_constants', { blockFilter: '.rdata' })
check('blockFilter 只会收窄结果、不会变多',
  cKRdata.ok === true && (cKRdata.result?.list || []).length <= (cKR.list || []).length,
  'all=' + cKR.total + ' .rdata=' + cKRdata.result?.total)
check('未过滤时扫遍全部签名', Number(cKR.signaturesScanned) === Number(cR.signaturesAvailable),
  'scanned=' + cKR.signaturesScanned)

// ---------------------------------------------------------------- C. 行为线索（cmd.exe）
console.log('\n== C. ghidra_detect_malware_behaviors（cmd.exe） ==')
const c = await open('cmd.exe', CMD)
const beh = await call('ghidra_detect_malware_behaviors', {})
const bR = beh.result || {}
check('行为扫描 ok', beh.ok === true, 'ok=' + beh.ok + ' err=' + (beh.error || bR.error || '-'))
check('扫了 10 类行为', bR.categoriesScanned === 10, 'scanned=' + bR.categoriesScanned)
check('★ 至少命中一类行为', Array.isArray(bR.categories) && bR.categories.length >= 1 && bR.apisFound >= 1,
  'categoriesFound=' + bR.categoriesFound + ' apisFound=' + bR.apisFound + ' cats=' + JSON.stringify((bR.categories || []).map((x) => x.category + ':' + x.found)))
check('分类行带 severity/found/apis', (bR.categories || []).every((x) => ['high', 'medium', 'low'].includes(x.severity) && typeof x.found === 'number' && Array.isArray(x.apis)),
  JSON.stringify((bR.categories || [])[0]?.severity))
const allApis = (bR.categories || []).flatMap((x) => x.apis)
check('每条 API 都带 sources 且取值合法', allApis.length > 0 && allApis.every((a) => Array.isArray(a.sources) && a.sources.length > 0 &&
  a.sources.every((s) => ['import', 'function', 'string'].includes(s))),
  JSON.stringify(allApis[0]))
check('★ 导入表来源被识别（sources 含 import）', allApis.some((a) => a.sources.includes('import')),
  JSON.stringify(allApis.filter((a) => a.sources.includes('import')).slice(0, 4).map((a) => a.api)))
check('★ 词边界生效：connect 没被连进 connection 之类', !allApis.some((a) => a.api === 'connect' && !String(a.string || '').toLowerCase().includes('connect')),
  'connect 命中=' + JSON.stringify(allApis.filter((a) => a.api === 'connect').slice(0, 2)))
check('severityCounts 三个键齐全', ['high', 'medium', 'low'].every((k2) => typeof bR.severityCounts?.[k2] === 'number'),
  JSON.stringify(bR.severityCounts))
const behOne = await call('ghidra_detect_malware_behaviors', { categories: 'c2-network' })
check('categories 过滤生效（只扫 1 类）', behOne.ok === true && behOne.result?.categoriesScanned === 1,
  'scanned=' + behOne.result?.categoriesScanned + ' found=' + behOne.result?.categoriesFound)
const behNone = await call('ghidra_detect_malware_behaviors', { categories: 'no-such-category' })
check('不存在的分类 → 空结果且不报错', behNone.ok === true && behNone.result?.categoriesFound === 0 && behNone.result?.categoriesScanned === 0,
  JSON.stringify({ c: behNone.result?.categoriesFound, s: behNone.result?.categoriesScanned }))
const behLim = await call('ghidra_detect_malware_behaviors', { categories: 'c2-network', limit: 2 })
check('limit 限制每类 API 条数', behLim.ok === true && (behLim.result?.categories || []).every((x) => x.apis.length <= 2),
  JSON.stringify((behLim.result?.categories || []).map((x) => x.apis.length)))
// ★ 双形状回归：oneOf 的数组形状也必须走到 Python 并被正确解析
const behArr = await call('ghidra_detect_malware_behaviors', { categories: ['c2-network'] })
check('★ categories 数组形状生效（oneOf）', behArr.ok === true && behArr.result?.categoriesScanned === 1,
  'scanned=' + behArr.result?.categoriesScanned + ' found=' + behArr.result?.categoriesFound)

// ---------------------------------------------------------------- D. 反分析（cmd.exe）
console.log('\n== D. ghidra_find_anti_analysis_techniques（cmd.exe） ==')
const anti = await call('ghidra_find_anti_analysis_techniques', {})
const aR = anti.result || {}
check('反分析扫描 ok', anti.ok === true, 'ok=' + anti.ok + ' err=' + (anti.error || aR.error || '-'))
check('★ 至少一条线索', Array.isArray(aR.indicators) && aR.indicators.length >= 1 && aR.indicatorCount === aR.indicators.length,
  'count=' + aR.indicatorCount + ' names=' + JSON.stringify((aR.indicators || []).map((x) => x.name)))
check('risk 取值合法', ['low', 'medium', 'high'].includes(aR.risk), 'risk=' + aR.risk)
check('指令计数三个键齐全', ['rdtsc', 'cpuid', 'int3'].every((k2) => typeof aR.counts?.[k2] === 'number'),
  JSON.stringify(aR.counts))
check('★ INT3 字节确实数到了（cmd.exe 里上万处）', aR.counts?.int3 > 100, 'int3=' + aR.counts?.int3)
check('★ 反调试 API 线索带地址', (aR.indicators || []).filter((x) => x.category === 'anti-debug').every((x) => (x.evidence || []).every((e) => typeof e.value === 'string' && typeof e.address === 'string')),
  JSON.stringify((aR.indicators || [])[0]?.evidence?.[0]))
const antiMax = await call('ghidra_find_anti_analysis_techniques', { max: 1 })
check('max 限制每条线索的证据条数', antiMax.ok === true && (antiMax.result?.indicators || []).every((x) => (x.evidence || []).length <= 1),
  JSON.stringify((antiMax.result?.indicators || []).map((x) => (x.evidence || []).length)))

// ---------------------------------------------------------------- E. IOC（certutil.exe 真阳性 + reg.exe 注册表）
// certutil.exe 为什么是 IOC 目标：字节级侦察 + 实测都确认它有 11 个 CT 日志域名、若干 URL、
// 5 个 DIMS/AUTOENRL 互斥体、1 条 c:\certutil\ 路径，以及 180 条点分十进制 OID 表项
//（2.5.29.14 之类）——最后这条正是补丁 12 的回归样本。
// 注册表键换到 reg.exe：cmd.exe 里根本没有 HKEY_* 字符串（原断言错，不是工具错）。
console.log('\n== E. ghidra_extract_iocs_with_context（certutil.exe / reg.exe） ==')
await open('certutil.exe', CERTUTIL)
const ioc = await call('ghidra_extract_iocs_with_context', { includeRawMemory: true, maxBytes: 2097152, max: 400 })
const iR = ioc.result || {}
check('IOC 抽取 ok', ioc.ok === true, 'ok=' + ioc.ok + ' err=' + (ioc.error || iR.error || '-'))
check('★ includeRawMemory 真的扫了字节（补丁 11 回归：_range_len 对 MemoryBlock 曾返回 0）',
  iR.bytesScanned > 1000000 && iR.rawBlocksScanned >= 5,
  'bytesScanned=' + iR.bytesScanned + ' rawBlocksScanned=' + iR.rawBlocksScanned)
check('★ 原始内存行并入了扫描源（stringsScanned 明显大于已定义字符串数）',
  iR.stringsScanned > 10000, 'stringsScanned=' + iR.stringsScanned)
check('覆盖 17 类类型', Array.isArray(iR.typesScanned) && iR.typesScanned.length === 17, 'types=' + iR.typesScanned?.length)
check('★ 真阳性：抽到 CT 日志域名', (iR.list || []).some((r) => r.type === 'domain' && r.value === 'ct.googleapis.com'),
  'domains=' + JSON.stringify((iR.list || []).filter((r) => r.type === 'domain').slice(0, 3).map((r) => r.value)))
check('★ 抽到 URL / 互斥体 / Windows 路径三类',
  (iR.byType?.url || 0) >= 1 && (iR.byType?.mutex || 0) >= 1 && (iR.byType?.winpath || 0) >= 1,
  JSON.stringify(iR.byType))
// 补丁 12 的回归点是「OID 表项不再灌进 ipv4」，不是「ipv4 必须为 0」：
// certutil 里有一个货真价实的 IPv4 形状版本串 5.1.0.0（第一弧 5 > 2，按 ITU-T 弧规则就不是 OID），
// 它归 ipv4 是对的。所以断「ipv4 稀少 + 不含任何 OID 形状的值」，而不是断死 0。
const v4Rows = (iR.list || []).filter((r) => r.type === 'ipv4')
const oidShapedInV4 = v4Rows.filter((r) => /^(?:[0-2]\.(?:[0-9]|[1-3][0-9])\.)/.test(r.value))
check('★ 补丁 12：OID 表项归 oid、不混进 ipv4',
  (iR.byType?.oid || 0) >= 20 && v4Rows.length <= 5 && oidShapedInV4.length === 0,
  'oid=' + iR.byType?.oid + ' ipv4=' + iR.byType?.ipv4 +
  ' v4=' + JSON.stringify(v4Rows.map((r) => r.value)) +
  ' oidShaped=' + JSON.stringify(oidShapedInV4.map((r) => r.value)))
check('每条 IOC 形状完整（type/value/source/address/string/count）',
  (iR.list || []).every((r) => typeof r.type === 'string' && typeof r.value === 'string' &&
    ['string', 'memory'].includes(r.source) && typeof r.address === 'string' &&
    typeof r.string === 'string' && typeof r.count === 'number' && r.count >= 1),
  JSON.stringify(iR.list?.[0]))
check('byType 计数与 list 一致', Object.values(iR.byType || {}).reduce((a, b) => a + b, 0) === iR.total,
  'sum=' + Object.values(iR.byType || {}).reduce((a, b) => a + b, 0) + ' total=' + iR.total)
check('同值去重（count 累加而不是重复出行）',
  new Set((iR.list || []).map((r) => r.type + '\u0000' + r.value)).size === (iR.list || []).length,
  'list=' + (iR.list || []).length + ' uniq=' + new Set((iR.list || []).map((r) => r.type + '\u0000' + r.value)).size)
const iocOne = await call('ghidra_extract_iocs_with_context', { types: 'domain' })
check('types 过滤生效', iocOne.ok === true && JSON.stringify(iocOne.result?.typesScanned) === '["domain"]' &&
  (iocOne.result?.list || []).every((r) => r.type === 'domain'),
  'types=' + JSON.stringify(iocOne.result?.typesScanned) + ' total=' + iocOne.result?.total)
// ★ 双形状回归：oneOf 的数组形状也必须走到 Python 并被正确解析。
// typesScanned 按表顺序回（_IOC_TYPES 顺序），断言用排序后的集合语义，别断输入顺序。
const iocArr = await call('ghidra_extract_iocs_with_context', { types: ['domain', 'url'], max: 20 })
const iArrT = (iocArr.result?.typesScanned || []).slice().sort()
check('★ types 数组形状生效（oneOf，真阳性）', iocArr.ok === true &&
  JSON.stringify(iArrT) === '["domain","url"]' && (iocArr.result?.total || 0) >= 1 &&
  (iocArr.result?.list || []).every((r) => r.type === 'domain' || r.type === 'url'),
  'types=' + JSON.stringify(iocArr.result?.typesScanned) + ' total=' + iocArr.result?.total)
const iocOid = await call('ghidra_extract_iocs_with_context', { types: 'oid', max: 40 })
check('types=oid 单独可用且条数可观', iocOid.ok === true && iocOid.result?.total >= 20 &&
  (iocOid.result?.list || []).every((r) => r.type === 'oid'),
  'total=' + iocOid.result?.total + ' 首条=' + JSON.stringify(iocOid.result?.list?.[0]?.value))
const iocV4 = await call('ghidra_extract_iocs_with_context', { types: 'ipv4' })
check('types=ipv4 不掺 OID（certutil 只剩版本串里的 5.1.0.0）',
  iocV4.ok === true && (iocV4.result?.list || []).every((r) => r.type === 'ipv4') &&
  !(iocV4.result?.list || []).some((r) => /^(?:[0-2]\.(?:[0-9]|[1-3][0-9])\.)/.test(r.value)),
  'total=' + iocV4.result?.total + ' list=' + JSON.stringify((iocV4.result?.list || []).map((r) => r.value)))
let iocBad = ''
try { await call('ghidra_extract_iocs_with_context', { types: 'ipv4,nonsense' }) } catch (e) { iocBad = String(e.message || e) }
check('未知类型被明确拒绝', iocBad.includes('未知类型'), JSON.stringify(iocBad.slice(0, 140)))
await open('reg.exe', REG)
const iocReg = await call('ghidra_extract_iocs_with_context', { types: 'registry', max: 20 })
const regHit = (iocReg.result?.list || []).find((r) => String(r.value).startsWith('HKEY_'))
check('★ 注册表键抽取（reg.exe 真阳性）', iocReg.ok === true && !!regHit, regHit ? regHit.value : JSON.stringify(iocReg.result))
const iocRegRaw = await call('ghidra_extract_iocs_with_context', { types: 'ipv4,domain', includeRawMemory: true, maxBytes: 65536 })
check('includeRawMemory 在小目标上也回传字节数', iocRegRaw.ok === true && Number(iocRegRaw.result?.bytesScanned) > 0 &&
  Number(iocRegRaw.result?.rawBlocksScanned) >= 1,
  'bytesScanned=' + iocRegRaw.result?.bytesScanned + ' rawBlocksScanned=' + iocRegRaw.result?.rawBlocksScanned)
// ★ 双形状回归：reg.exe 上数组形状同样被解析（reg.exe 没有 domain/url → total=0 是正确行为，
//   断言只断 typesScanned 的集合语义）
const iocArrReg = await call('ghidra_extract_iocs_with_context', { types: ['domain', 'url'], max: 20 })
const iArrRegT = (iocArrReg.result?.typesScanned || []).slice().sort()
check('★ types 数组形状在无命中目标上也正确解析', iocArrReg.ok === true &&
  JSON.stringify(iArrRegT) === '["domain","url"]',
  'types=' + JSON.stringify(iocArrReg.result?.typesScanned) + ' total=' + iocArrReg.result?.total)

// ---------------------------------------------------------------- F. 收尾
console.log('\n== F. close ==')
const closed = await call('ghidra_close')
check('ghidra_close ok', closed.ok === true && closed.result?.closed === true, JSON.stringify(closed.result))
await new Promise((r) => setTimeout(r, 1500))
const leftover = spawnSync('powershell', ['-NoProfile', '-Command',
  "(Get-CimInstance Win32_Process -Filter \"Name='java.exe' OR Name='python.exe' OR Name='py.exe'\" | Measure-Object).Count"],
  { encoding: 'utf8' })
check('系统里没有 Ghidra 残留进程', Number(String(leftover.stdout).trim() || '1') === 0, 'count=' + String(leftover.stdout).trim())

console.log('\n==== ' + pass + '/' + (pass + fail) + ' PASS ====  (' + Math.round((Date.now() - t0) / 1000) + 's)')
if (fail === 0) console.log('BATCH4_E2E_OK')
else { console.log('TOOLS_E2E_FAILED'); process.exitCode = 1 }
