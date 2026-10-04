// v0.4.0 路由探针：doctor（只读全跑）+ migrate-home 校验路径（400 分支）+ install 状态字段在 /status
// 不真跑 install（会启动 400MB 下载）与迁移复制（破坏性）——只验证接线与校验分支。
import { fileURLToPath, pathToFileURL } from 'node:url'
import { readFileSync } from 'node:fs'

const dir = process.argv[2] || fileURLToPath(new URL('.', import.meta.url))
const indexPath = dir.endsWith('index.js') ? dir : dir.replace(/[\\/]+$/, '') + '/index.js'
const dshTools = 'file:///C:/Users/Administrator/AppData/Roaming/npm/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-tools/lib/index.js'

const results = []
const check = (name, ok, detail) => { results.push({ name, ok, detail }); console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  :: ' + detail : '')) }

// mock 宿主：tools + jobs + webServer（exact/prefixes Map + register）
const routes = []
const mockCtx = {
  tools: { register(d) { routes.push({ tool: d }) ; return () => {} } },
  jobs: { background() { return 'job-x' } },
  inject(names, cb) {
    return cb({ webServer: { exact: new Map(), prefixes: new Map(), register(r) { routes.push(r); return () => {} } } })
  },
  effect(fn) { return fn() },
  on() { return () => {} },
}

// volatile 配置桩（全部字段 .get()）
const cfg = {}
for (const k of ['ghidraHome', 'ghidraProjectDir', 'projectName', 'pythonVer', 'analysisTimeoutSec', 'serverStartupTimeoutMs', 'maxOutputChars', 'stream', 'mcpPort', 'mcpStartupTimeoutSec', 'mcpTimeoutSec']) {
  cfg[k] = { get: () => undefined }
}
cfg.pythonVer = { get: () => '3.13' }

const mod = await import(pathToFileURL(indexPath).href + '?probe=' + Date.now())
check('apply 是函数', typeof mod.apply === 'function', String(typeof mod.apply))
try { mod.apply(mockCtx, cfg) } catch (e) { check('apply 未抛异常', false, String(e && e.message || e)) }

const webRoutes = routes.filter((r) => r.path && r.path.startsWith('/api/dsh-ghidra'))
const byPath = Object.fromEntries(webRoutes.map((r) => [r.path, r]))
check('7 条状态路由全部注册', webRoutes.length === 7,
  webRoutes.map((r) => r.path.replace('/api/dsh-ghidra/', '')).join(','))

// mock req/res
const mkReq = (method, body) => {
  const handlers = {}
  const req = {
    socket: { remoteAddress: '127.0.0.1' },
    method,
    on(ev, fn) { handlers[ev] = fn; return req },
  }
  setTimeout(() => { if (body !== undefined && handlers.data) handlers.data(body); if (handlers.end) handlers.end() }, 5)
  return req
}
const mkRes = () => {
  const res = { statusCode: 0, body: null, headers: null }
  res.writeHead = (s, h) => { res.statusCode = s; res.headers = h; return res }
  res.end = (b) => { res.body = b; return res }
  return res
}

// 1. doctor（GET，loopback）—— 只读，全跑
if (byPath['/api/dsh-ghidra/doctor']) {
  const res = mkRes()
  await byPath['/api/dsh-ghidra/doctor'].handler(mkReq('GET'), res)
  let body = null
  try { body = JSON.parse(res.body) } catch {}
  check('doctor 返回 200 + checks 数组', res.statusCode === 200 && Array.isArray(body?.checks) && body.checks.length >= 7,
    'status=' + res.statusCode + ' checks=' + (body?.checks || []).map((c) => c.name + '=' + (c.ok ? 'ok' : 'fail')).join(', '))
  check('doctor overall = essential 全过', typeof body?.essentialOk === 'number' && body.essentialOk === body?.essentialTotal,
    'essential=' + body?.essentialOk + '/' + body?.essentialTotal)
  const names = (body?.checks || []).map((c) => c.name)
  check('doctor 含 PyGhidra launcher + headless.bat 检查',
    names.some((n) => /launcher/i.test(n)) && names.some((n) => /headless\.bat/i.test(n)), names.join(' | '))
} else check('doctor 路由存在', false, 'missing')

// 2. migrate-home 校验分支：from == to → 400
if (byPath['/api/dsh-ghidra/migrate-home']) {
  const res = mkRes()
  await byPath['/api/dsh-ghidra/migrate-home'].handler(
    mkReq('POST', JSON.stringify({ from: 'C:\\same\\path', to: 'C:\\same\\path' })), res)
  let body = null
  try { body = JSON.parse(res.body) } catch {}
  check('migrate-home from==to → 400', res.statusCode === 400 && !body?.ok, 'status=' + res.statusCode + ' error=' + (body?.error || ''))
  // 相对路径 → 400
  const res2 = mkRes()
  await byPath['/api/dsh-ghidra/migrate-home'].handler(
    mkReq('POST', JSON.stringify({ from: 'rel/path', to: 'C:\\abs' })), res2)
  check('migrate-home 相对路径 → 400', res2.statusCode === 400, 'status=' + res2.statusCode)
  // GET → 405
  const res3 = mkRes()
  await byPath['/api/dsh-ghidra/migrate-home'].handler(mkReq('GET'), res3)
  check('migrate-home GET → 405', res3.statusCode === 405, 'status=' + res3.statusCode)
} else check('migrate-home 路由存在', false, 'missing')

// 3. install-ghidra：GET → 405（不真 POST，避免启动真实下载）
if (byPath['/api/dsh-ghidra/install-ghidra']) {
  const res = mkRes()
  await byPath['/api/dsh-ghidra/install-ghidra'].handler(mkReq('GET'), res)
  check('install-ghidra GET → 405', res.statusCode === 405, 'status=' + res.statusCode)
} else check('install-ghidra 路由存在', false, 'missing')

// 4. /status 含 install + migrate 字段
if (byPath['/api/dsh-ghidra/status']) {
  const res = mkRes()
  await byPath['/api/dsh-ghidra/status'].handler(mkReq('GET'), res)
  let body = null
  try { body = JSON.parse(res.body) } catch {}
  check('/status 工具计数三分类互斥（47/3/168=218）',
    body?.tools && body.tools.native === 47 && body.tools.lifecycle === 3 && body.tools.generated === 168 && body.tools.total === 218,
    JSON.stringify(body?.tools))
  check('/status 含 install+migrate 进度字段', !!(body?.install && body?.migrate),
    'install=' + JSON.stringify(body?.install || null).slice(0, 80) + ' migrate=' + JSON.stringify(body?.migrate || null).slice(0, 80))
} else check('status 路由存在', false, 'missing')

// 5. list-dir / mkdir：GET → 405；list-dir 无 path → 回驱动器列表
if (byPath['/api/dsh-ghidra/list-dir']) {
  const res = mkRes()
  await byPath['/api/dsh-ghidra/list-dir'].handler(mkReq('GET'), res)
  check('list-dir GET → 405', res.statusCode === 405, 'status=' + res.statusCode)
  const res2 = mkRes()
  await byPath['/api/dsh-ghidra/list-dir'].handler(mkReq('POST', JSON.stringify({ path: '' })), res2)
  let b2 = null; try { b2 = JSON.parse(res2.body) } catch {}
  check('list-dir 空路径回驱动器列表', res2.statusCode === 200 && Array.isArray(b2?.drives) && b2.drives.length > 0, 'drives=' + JSON.stringify(b2?.drives))
  const res3 = mkRes()
  await byPath['/api/dsh-ghidra/list-dir'].handler(mkReq('POST', JSON.stringify({ path: 'C:\\\\Users' })), res3)
  let b3 = null; try { b3 = JSON.parse(res3.body) } catch {}
  check('list-dir 列真实目录', res3.statusCode === 200 && b3?.ok === true && Array.isArray(b3.dirs), 'path=' + b3?.path + ' dirs=' + (b3?.dirs || []).length + ' dotSegment=' + b3?.dotSegment)
} else check('list-dir 路由存在', false, 'missing')
if (byPath['/api/dsh-ghidra/mkdir']) {
  const res = mkRes()
  await byPath['/api/dsh-ghidra/mkdir'].handler(mkReq('GET'), res)
  check('mkdir GET → 405', res.statusCode === 405, 'status=' + res.statusCode)
  const res2 = mkRes()
  await byPath['/api/dsh-ghidra/mkdir'].handler(mkReq('POST', JSON.stringify({ parent: 'C:\\\\Users', name: '.hidden' })), res2)
  check('mkdir 拒绝点开头目录名', res2.statusCode === 400, 'status=' + res2.statusCode)
} else check('mkdir 路由存在', false, 'missing')

console.log('')
const fails = results.filter((r) => !r.ok).length
console.log('=== ' + (fails ? 'PROBE FAILED: ' + fails + ' fail(s)' : 'PROBE PASSED: ' + results.length + '/' + results.length) + ' ===')
process.exit(fails ? 1 : 0)
