// probe-availability.mjs — 验收【工具可用性门控】（对照 REA 的 tool availability 契约）
// 要证明的三件事：
//   1) 桥与 REST 都没跑时，插件**不广告**那 213 个必然失败的工具，只留 5 个常驻入口；
//   2) REST 服务器起来后（这里用 stub /health 冒充），168 个生成工具**被注册进来**且名字与生成器输出一致；
//   3) 服务器停掉后它们**被真正撤掉**（不是只改计数）—— 否则 agent 会拿到一个调用必失败的 schema。
// 用法: node probe-availability.mjs [已装副本目录或 index.js 的路径]
import { createServer } from 'node:http'
import { fileUrl, installedDir, sourceDir } from './lib/dev-env.mjs'
import { join } from 'node:path'
import { createServer as createTcpServer } from 'node:net'

const arg = process.argv[2]
const PLUGIN = arg
  ? 'file:///' + arg.replace(/\\/g, '/').replace(/\/index\.js$/, '') + '/index.js'
  : fileUrl(join(installedDir('web'), 'index.js'))
const mod = await import(PLUGIN)
const { MCP_TOOLS } = await import(fileUrl(join(sourceDir(), 'lib', 'mcp-tools.js')))

const fails = []
const check = (label, cond, detail) => {
  console.log((cond ? 'PASS  ' : 'FAIL  ') + label + (detail === undefined ? '' : '  :: ' + detail))
  if (!cond) fails.push(label)
}

// ---- ctx 桩：注册表可增可删（同名重复注册要炸，这样「没撤干净」会被立刻抓到）----
const registered = new Map()
const duplicateAttempts = []
const routes = []
const webServer = { exact: new Map(), prefixes: new Map(), register(r) { routes.push(r); return () => {} } }
const ctx = {
  effect(fn) { return fn() },
  tools: {
    register(t) {
      if (registered.has(t.name)) { duplicateAttempts.push(t.name); throw new Error('tool "' + t.name + '" is already registered') }
      registered.set(t.name, t)
      return () => { registered.delete(t.name) }
    },
  },
  jobs: { start() { return { id: 'stub' } } },
  logger: console,
  inject(names, cb) {
    const p = {}
    for (const n of names) if (n === 'webServer') p.webServer = webServer
    return cb(p)
  },
}

// ---- stub 上游 REST 服务器：只需要 /health 答 200（mcpHealth 的判据）----
const stub = createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ status: 'healthy', version: '7.0.0-rc.1-stub', program_loaded: true, program_name: 'stub' }))
    return
  }
  res.writeHead(404).end('{}')
})
const port = await new Promise((resolve) => {
  const probe = createTcpServer()
  probe.listen(0, '127.0.0.1', () => { const p = probe.address().port; probe.close(() => resolve(p)) })
})
// undici 的 fetch 默认 keep-alive，光 close() 会等空闲连接自然过期（~4s）——先把连接掐掉再关
const startStub = () => new Promise((resolve) => stub.listen(port, '127.0.0.1', resolve))
const stopStub = () => new Promise((resolve) => { stub.closeAllConnections?.(); stub.close(() => resolve()) })

function callRoute(path) {
  const route = routes.find((r) => r.path === path)
  if (!route) return Promise.resolve(null)
  return new Promise((resolve) => {
    const req = { method: 'GET', socket: { remoteAddress: '127.0.0.1' }, on() {} }
    const res = { writeHead() {}, end(body) { try { resolve(JSON.parse(body)) } catch { resolve(null) } } }
    Promise.resolve(route.handler(req, res)).catch(() => resolve(null))
  })
}
const snapshot = async () => (await callRoute('/api/dsh-ghidra/status'))?.toolAvailability
const hiddenOf = (ta, group) => ta?.hidden?.find((h) => h.group === group)

// ---- 场景 1：什么都没跑 ----
mod.apply(ctx, mod.Config({ mcpPort: port }))
await new Promise((r) => setTimeout(r, 1200))
const ALWAYS_ON = ['ghidra_status', 'ghidra_open', 'ghidra_doctor', 'ghidra_mcp_start', 'ghidra_mcp_stop', 'ghidra_mcp_status']
let ta = await snapshot()
check('冷启动：只广告 6 个常驻工具', registered.size === 6 && ALWAYS_ON.every((n) => registered.has(n)),
  registered.size + ' 个: ' + [...registered.keys()].join(', '))
check('冷启动：advertised=6 / total=219', ta?.advertised === 6 && ta?.total === 219, JSON.stringify({ a: ta?.advertised, t: ta?.total }))
check('冷启动：桥门 45 + REST 门 168 都被隐藏且带 reason/remediation',
  hiddenOf(ta, 'bridge')?.count === 45 && hiddenOf(ta, 'bridge')?.reason === 'not_running' && !!hiddenOf(ta, 'bridge')?.remediation
  && hiddenOf(ta, 'mcp')?.count === 168 && hiddenOf(ta, 'mcp')?.reason === 'not_running' && !!hiddenOf(ta, 'mcp')?.remediation,
  JSON.stringify(ta?.hidden))
check('冷启动：没有 168 个 ghidra_mcp_* 工具中的任何一个', ![...registered.keys()].some((n) => n.startsWith('ghidra_mcp_') && !ALWAYS_ON.includes(n)),
  [...registered.keys()].filter((n) => n.startsWith('ghidra_mcp_')).join(', ') || '(none)')

// ---- 场景 2：REST 服务器上线 ----
await startStub()
ta = await snapshot()
const mcpNames = MCP_TOOLS.map((t) => t.name)
const liveMcp = mcpNames.filter((n) => registered.has(n))
check('服务器上线：168 个生成工具被注册', liveMcp.length === 168, liveMcp.length + '/168')
check('服务器上线：注册的名字与生成器输出完全一致（无多无少）',
  liveMcp.length === mcpNames.length && registered.size === 6 + 168,
  'registered=' + registered.size)
check('服务器上线：advertised=174，隐藏只剩桥门 45',
  ta?.advertised === 174 && ta?.hidden?.length === 1 && hiddenOf(ta, 'bridge')?.count === 45,
  JSON.stringify({ a: ta?.advertised, hidden: ta?.hidden }))
check('服务器上线：groups.mcp.available=true', ta?.groups?.mcp?.available === true, JSON.stringify(ta?.groups))
check('全程没有重复注册（撤门撤干净了）', duplicateAttempts.length === 0, JSON.stringify(duplicateAttempts))

// ---- 场景 3：工具入口本身也会同步门（agent 只调工具、不调路由）----
const statusTool = registered.get('ghidra_status')
let toolTa = null
try {
  const out = await statusTool.execute({})
  toolTa = out?.toolAvailability || out?.result?.toolAvailability
} catch (e) { check('ghidra_status.execute 未抛异常', false, String(e?.message || e)) }
check('ghidra_status 的返回里带 toolAvailability（agent 不用查路由也能知道）', !!toolTa && toolTa.total === 219, JSON.stringify({ a: toolTa?.advertised, t: toolTa?.total }))

// ---- 场景 4：服务器下线 → 工具必须被真正撤掉 ----
await stopStub()
ta = await snapshot()
check('服务器下线：168 个生成工具被撤掉', !mcpNames.some((n) => registered.has(n)),
  mcpNames.filter((n) => registered.has(n)).length + ' 个残留')
check('服务器下线：回到 advertised=6，隐藏恢复 45+168',
  registered.size === 6 && ta?.advertised === 6 && hiddenOf(ta, 'mcp')?.count === 168,
  JSON.stringify({ reg: registered.size, a: ta?.advertised, hidden: ta?.hidden?.map((h) => h.group + ':' + h.count) }))
check('服务器下线：仍无重复注册', duplicateAttempts.length === 0, JSON.stringify(duplicateAttempts))

// ---- 场景 5：反复横跳不能泄漏（disposer 幂等）----
for (let i = 0; i < 3; i++) {
  await startStub()
  await snapshot()
  await stopStub()
  await snapshot()
}
check('上线/下线横跳 3 轮后：注册表回到 6，无重复注册', registered.size === 6 && duplicateAttempts.length === 0,
  'registered=' + registered.size + ' dup=' + duplicateAttempts.length)

console.log('')
console.log(fails.length === 0
  ? '=== AVAILABILITY PROBE PASSED: 门控的开关、撤门与幂等全部成立 ==='
  : '=== AVAILABILITY PROBE FAILED: ' + fails.join(' | ') + ' ===')
process.exit(fails.length === 0 ? 0 : 1)
