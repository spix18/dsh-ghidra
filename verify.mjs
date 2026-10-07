// verify.mjs — 端到端验收 dsh-ghidra（直接驱动已安装副本的 lib，与 DSH 运行时同一份代码）
// 用法: node verify.mjs [被测二进制路径]
import { join } from 'node:path'
import { fileUrl, installedDir } from './lib/dev-env.mjs'

// 静态 import 不能接运行期表达式，而副本位置随机器而变 —— 所以这里必须用 await import。
const LIB = (name) => fileUrl(join(installedDir('web'), 'lib', name))
const { jsonRequest } = await import(LIB('socket.js'))
const {
  detectGhidraHome, readVersion, pyghidraInstalled, importBinary, startServer,
} = await import(LIB('ghidra.js'))
const { killPid } = await import(LIB('run.js'))

// 缺省样本二进制：原来写死 Windows 的 winver.exe，在 Linux/macOS 上必 ENOENT。
const BIN = process.argv[2] || (process.platform === 'win32' ? 'C:\\Windows\\System32\\winver.exe' : '/bin/ls')
const config = {
  ghidraHome: '', ghidraProjectDir: '', projectName: 'dsh', pythonVer: '3.13',
  analysisTimeoutSec: 600, serverStartupTimeoutMs: 180000, maxOutputChars: 100000, stream: true,
}

const log = (...a) => console.log(...a)
const fails = []
function check(label, cond, detail) {
  log((cond ? 'PASS  ' : 'FAIL  ') + label + (detail === undefined ? '' : '  :: ' + detail))
  if (!cond) fails.push(label)
}

let child = null
let srvPid = 0
try {
  // 1. 环境探测
  const gh = detectGhidraHome(config)
  check('detectGhidraHome 找到 Ghidra', !!gh, JSON.stringify(gh))
  if (!gh) throw new Error('no ghidra')
  const ver = readVersion(gh.home)
  check('readVersion 读到 12.1.4/PUBLIC', ver.version === '12.1.4' && ver.release === 'PUBLIC', JSON.stringify(ver))
  check('路径为纯 ASCII（不触发 log4j 绕行）', gh.nonAscii === false, 'nonAscii=' + gh.nonAscii)
  check("pyghidraInstalled('3.13') 为真", pyghidraInstalled('3.13') === true)

  // 2. 导入 + 分析
  const t0 = Date.now()
  const prog = await importBinary(gh, BIN, config, (m) => process.stdout.write('[import] ' + m))
  log('导入耗时 ' + Math.round((Date.now() - t0) / 1000) + 's，程序名=' + prog)
  check('importBinary 返回程序名', !!prog, prog)

  // 3. 常驻服务器
  const t1 = Date.now()
  const srv = await startServer(gh, prog, config, (m) => process.stdout.write('[server] ' + m))
  child = srv.child
  srvPid = srv.pid || 0
  check('startServer 就绪并返回端口', Number.isInteger(srv.port) && srv.port > 0,
    'port=' + srv.port + ' 耗时=' + Math.round((Date.now() - t1) / 1000) + 's')

  // 4. 逐个 op
  const call = async (body, ms) => {
    try { return await jsonRequest(srv.port, body, ms || 60000) }
    catch (e) { return { ok: false, error: String(e && e.message || e) } }
  }

  const ping = await call({ op: 'ping' }, 10000)
  check('op=ping', ping && ping.ok === true, JSON.stringify(ping).slice(0, 160))

  const info = await call({ op: 'info' })
  const ri = info && info.result
  check('op=info 返回函数/符号统计', !!ri && ri.functions > 0 && ri.symbols > 0,
    ri ? ('name=' + ri.program + ' lang=' + ri.language + ' funcs=' + ri.functions + ' syms=' + ri.symbols + ' blocks=' + ri.blocks.length) : JSON.stringify(info).slice(0, 200))

  const fns = await call({ op: 'functions', max: 5 })
  check('op=functions 返回列表', !!fns && fns.ok === true && fns.result.list.length > 0,
    fns && fns.result ? ('total=' + fns.result.total + ' first=' + (fns.result.list[0] || {}).name) : JSON.stringify(fns).slice(0, 200))

  const strs = await call({ op: 'strings', max: 5, minLength: 4 })
  check('op=strings 返回列表', !!strs && strs.ok === true,
    strs && strs.result ? ('count=' + strs.result.list.length + ' sample=' + JSON.stringify((strs.result.list[0] || {}).value)) : JSON.stringify(strs).slice(0, 200))

  // 选一个目标函数：优先 entry，其次第一个函数
  const eps = (ri && ri.entrypoints) || []
  const entry = eps.find((e) => /entry/i.test(e.name)) || eps[0] || null
  const target = entry ? entry.address : (fns && fns.result && fns.result.list[0] ? fns.result.list[0].address : null)
  check('拿到可反编译目标地址', !!target, target + ' (' + (entry ? entry.name : 'fallback') + ')')

  if (target) {
    const dec = await call({ op: 'decompile', target }, 120000)
    const rd = dec && dec.result
    check('op=decompile 返回 C 代码', !!rd && typeof rd.code === 'string' && rd.code.length > 40,
      rd ? ('fn=' + rd.function + ' sig=' + rd.signature + ' codeLen=' + rd.code.length) : JSON.stringify(dec).slice(0, 300))
    if (rd) log('--- decompile 预览 ---\n' + rd.code.split('\n').slice(0, 12).join('\n'))

    const xr = await call({ op: 'xrefs', target, direction: 'to', max: 10 })
    check('op=xrefs 不报未知错误', !!xr && xr.ok === true, xr && xr.result ? ('total=' + xr.result.total) : JSON.stringify(xr).slice(0, 200))
  }

  // 5. 干净关闭
  const bye = await call({ op: 'shutdown' }, 10000)
  check('op=shutdown', !!bye && bye.ok === true, JSON.stringify(bye).slice(0, 120))
} catch (e) {
  check('整体流程未抛异常', false, (e && e.stack) || String(e))
} finally {
  // 必须杀真正的 JVM pid：只杀 child.pid（pyghidra_launcher.py 的 wrapper）会留下孤儿 JVM，
  // 它会一直占着 Ghidra 项目锁，导致后续 open 全部失败。
  if (srvPid) { try { killPid(srvPid) } catch { /* ignore */ } }
  if (child && child.pid) { try { killPid(child.pid) } catch { /* ignore */ } }
}

log('')
log(fails.length === 0 ? '=== ALL CHECKS PASSED ===' : '=== FAILED: ' + fails.join(' | ') + ' ===')
process.exit(fails.length === 0 ? 0 : 1)
