// verify-load.mjs — 验收「DSH/cordis 能否加载 ghidra-bridge、注册工具、注册随包技能、开出状态路由」
// 用绝对 file:// URL 载入 **已安装副本**，这样插件内部的裸包名（@deepseek-ai/*）
// 按 node_modules 树正常解析，等价于 DSH 运行时的真实加载路径。
// 用法: node verify-load.mjs [已装副本目录或 index.js 的路径]
//       缺省 = web profile 的副本；传 headless 副本可证明两个 profile 一致。
//
// 2026-10-04 起工具注册是**门控**的（只广告当前真能调用的工具，对照 REA 的 tool availability 契约）：
// 桥 / REST 服务器都没跑时，apply 只会注册 6 个常驻工具，其余 213 个进 pending。
// 所以这里不再断言「注册了 219 个」，改成断言【定义总数 219 + 当前广告数 + 被隐藏的组与原因】。
import { join } from 'node:path'
import { fileUrl, installedDir, sourceDir } from './lib/dev-env.mjs'

const arg = process.argv[2]
const PLUGIN = arg
  ? 'file:///' + arg.replace(/\\/g, '/').replace(/\/index\.js$/, '') + '/index.js'
  : fileUrl(join(installedDir('web'), 'index.js'))

const mod = await import(PLUGIN)

const registered = new Map()   // name -> definition（register 的返回 disposer 会删掉自己）
const effects = []
const routes = []
const skills = []
// 最小 cordis ctx 桩：注入的服务名对（inject = ['tools','jobs']）就能驱动 apply。
// 三个软注入（skills / webServer）按名字分发 —— 真实 ctx 也是这么给的，缺服务时对应回调拿不到对象。
const webServer = {
  exact: new Map(),
  prefixes: new Map(),
  register(r) { routes.push(r); return () => { const t = r.kind === 'exact' ? this.exact : this.prefixes; t.delete(r.path) } },
}
const skillsService = {
  register(definition) {
    skills.push(definition)
    return () => { const i = skills.indexOf(definition); if (i >= 0) skills.splice(i, 1) }
  },
}
const ctx = {
  effect(fn) { const d = fn(); effects.push(typeof d); return d },
  tools: {
    register(t) {
      if (registered.has(t.name)) throw new Error('tool "' + t.name + '" is already registered in this scope')
      registered.set(t.name, t)
      return () => { registered.delete(t.name) }
    },
  },
  jobs: { start() { return { id: 'stub' } } },
  logger: console,
  inject(names, cb) {
    const provided = {}
    for (const n of names) {
      if (n === 'webServer') provided.webServer = webServer
      else if (n === 'skills') provided.skills = skillsService
    }
    return cb(provided)
  },
}

const fails = []
const check = (label, cond, detail) => {
  console.log((cond ? 'PASS  ' : 'FAIL  ') + label + (detail === undefined ? '' : '  :: ' + detail))
  if (!cond) fails.push(label)
}

// 状态路由 handler 的调用桩（回环地址 + 捕获 JSON 响应）
function callRoute(path, method = 'GET') {
  const route = routes.find((r) => r.path === path)
  if (!route) return Promise.resolve(null)
  return new Promise((resolve) => {
    const req = { method, socket: { remoteAddress: '127.0.0.1' }, on() {} }
    const res = { writeHead() {}, end(body) { try { resolve(JSON.parse(body)) } catch { resolve(null) } } }
    Promise.resolve(route.handler(req, res)).catch(() => resolve(null))
  })
}
// 找一个确定没人监听的端口 —— 否则本机真跑着 8123 时验收结果会随环境漂移
const net = await import('node:net')
const freePort = await new Promise((resolve) => {
  const s = net.createServer()
  s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)) })
})

check('name === ghidra-bridge', mod.name === 'ghidra-bridge', mod.name)
check("inject === ['tools','jobs']", JSON.stringify(mod.inject) === '["tools","jobs"]', JSON.stringify(mod.inject))
check('apply 是函数', typeof mod.apply === 'function')

let config = null
try { config = mod.Config({ mcpPort: freePort }) } catch (e) { /* 下面统一判定 */ }
// volatile 字段的默认值是 ref（.get() 恒答当前值）—— 读法与 index.js 的 resolveConfig 一致
const val = (x) => { const v = config ? config[x] : undefined; return typeof (v && v.get) === 'function' ? v.get() : v }
check('Config 填充出 12 个默认项', !!config && Object.keys(config).length === 12,
  config ? Object.keys(config).join('/') : 'Config 不可调用')
check('默认 pythonVer=3.13 / projectName=dsh / mcpMode=unified（mcpPort 由验收指定）',
  val('pythonVer') === '3.13' && val('projectName') === 'dsh' && val('mcpMode') === 'unified' && val('mcpPort') === freePort,
  'pythonVer=' + val('pythonVer') + ' projectName=' + val('projectName') + ' mcpPort=' + val('mcpPort') + ' mcpMode=' + val('mcpMode'))

try { mod.apply(ctx, config) } catch (e) { check('apply 未抛异常', false, String(e && e.message || e)) }
// apply 末尾的首次可用性判定是异步的（探 /health）—— 等它落地再断言
await new Promise((r) => setTimeout(r, 1500))

const names = [...registered.keys()]
// 常驻工具 = 不需要任何服务器就能跑的入口（含 3 个 lifecycle）：它们是 agent 发现可用性并补救的唯一手段。
// ghidra_doctor 必须在这儿 —— 它存在就是为了诊断「跑不起来」，若它本身要桥在跑才可见，
// 那么最需要它的那一种状态下反而调不到它。
const ALWAYS_ON = ['ghidra_status', 'ghidra_open', 'ghidra_doctor', 'ghidra_mcp_start', 'ghidra_mcp_stop', 'ghidra_mcp_status']
const baseExpected = ['ghidra_status', 'ghidra_open', 'ghidra_doctor', 'ghidra_info', 'ghidra_decompile',
  'ghidra_functions', 'ghidra_strings', 'ghidra_xrefs', 'ghidra_close',
  // 批次 1 读侧补齐
  'ghidra_segments', 'ghidra_imports', 'ghidra_exports', 'ghidra_search_strings',
  'ghidra_search_functions', 'ghidra_calls', 'ghidra_call_graph', 'ghidra_read_memory',
  'ghidra_disassemble', 'ghidra_variables', 'ghidra_pcode',
  // 批次 2 写侧
  'ghidra_get_comments', 'ghidra_set_comment', 'ghidra_rename', 'ghidra_label',
  'ghidra_set_prototype', 'ghidra_set_variables', 'ghidra_create_function',
  'ghidra_delete_function', 'ghidra_save', 'ghidra_tags',
  // 批次 3 分析自动化
  'ghidra_run_script_inline', 'ghidra_run_script_file', 'ghidra_list_analyzers',
  'ghidra_configure_analyzer', 'ghidra_run_analysis', 'ghidra_reanalyze',
  'ghidra_search_byte_patterns', 'ghidra_find_code_gaps', 'ghidra_find_dead_code',
  // 批次 3 后半：复合分析 / 指令搜索 / 哈希比较 / 数据流
  'ghidra_function_context', 'ghidra_search_instructions', 'ghidra_hash',
  'ghidra_compare_functions', 'ghidra_data_flow',
  // 批次 4 恶意代码分析
  'ghidra_detect_crypto_constants', 'ghidra_detect_malware_behaviors',
  'ghidra_extract_iocs_with_context', 'ghidra_find_anti_analysis_techniques',
  // 上游 GhidraMCP REST 桥 lifecycle（226 端点服务器的启动/停止/状态）
  'ghidra_mcp_start', 'ghidra_mcp_stop', 'ghidra_mcp_status']
// 上游 REST 桥 168 个生成工具 —— 期望清单来自 vendored 生成器输出（source of truth），
// 用于核对【已装副本】用的是生成器产出的那一套（副本与源不同步时会 FAIL）。
const { MCP_TOOLS } = await import(fileUrl(join(sourceDir(), 'lib', 'mcp-tools.js')))
const expected = [...baseExpected, ...MCP_TOOLS.map((t) => t.name)]
const bridgeGated = baseExpected.filter((n) => !ALWAYS_ON.includes(n))

check('定义总数 219 = 常驻 ' + ALWAYS_ON.length + ' + 桥门 ' + bridgeGated.length + ' + REST 门 ' + MCP_TOOLS.length,
  expected.length === 219 && baseExpected.length === 51 && bridgeGated.length === 45 && MCP_TOOLS.length === 168,
  'expected=' + expected.length + ' base=' + baseExpected.length + ' bridgeGated=' + bridgeGated.length + ' mcp=' + MCP_TOOLS.length)
check('桥/REST 都没跑时只注册 ' + ALWAYS_ON.length + ' 个常驻工具',
  names.length === ALWAYS_ON.length && ALWAYS_ON.every((n) => names.includes(n)),
  names.length + ' 个: ' + names.join(', '))
check('每个已注册工具都是合法 defineTool 形状(name/description/parameters/execute)',
  [...registered.values()].every((t) => t.name && t.description && t.parameters && typeof t.execute === 'function'),
  'bad=' + JSON.stringify([...registered.values()].filter((t) => !(t.name && t.description && t.parameters && typeof t.execute === 'function')).map((t) => t.name)))
check('ctx.effect 注册了 dispose 函数', effects.length === 1 && effects[0] === 'function', JSON.stringify(effects))

// 可用性上报：状态路由必须说清「总数 / 当前广告数 / 被隐藏的组 + 原因 + 补救办法」
const status = await callRoute('/api/dsh-ghidra/status')
const ta = status && status.toolAvailability
check('状态路由上报 toolAvailability', !!ta, JSON.stringify(ta))
check('toolAvailability.total=219 advertised=' + ALWAYS_ON.length,
  !!ta && ta.total === 219 && ta.advertised === ALWAYS_ON.length, ta ? JSON.stringify({ total: ta.total, advertised: ta.advertised }) : '-')
check('toolAvailability.hidden = 桥 45 + REST 168，各带 reason 与 remediation',
  !!ta && ta.hidden.length === 2
    && ta.hidden.some((h) => h.group === 'bridge' && h.count === 45 && h.reason === 'not_running' && !!h.remediation)
    && ta.hidden.some((h) => h.group === 'mcp' && h.count === 168 && h.reason === 'not_running' && !!h.remediation),
  ta ? JSON.stringify(ta.hidden) : '-')
check('广告集 + 隐藏集 = 219（没有工具在门控里丢失）',
  !!ta && ta.advertised + ta.hidden.reduce((s, h) => s + h.count, 0) === 219,
  ta ? String(ta.advertised + ta.hidden.reduce((s, h) => s + h.count, 0)) : '-')

// 随包技能：skills/dsh-ghidra/SKILL.md 必须在 apply 时注册进运行时技能注册表
const sk = skills[0]
check('注册了 1 个随包技能', skills.length === 1, skills.length + ' 个')
check('技能名 dsh-ghidra / source=runtime / 有 description 与正文',
  !!sk && sk.name === 'dsh-ghidra' && sk.source === 'runtime'
    && typeof sk.description === 'string' && sk.description.length > 0
    && typeof sk.content === 'string' && sk.content.length > 2000,
  sk ? 'name=' + sk.name + ' source=' + sk.source + ' desc=' + String(sk.description || '').length + ' content=' + String(sk.content || '').length : '-')
check('技能名符合 /^[a-z0-9]+(?:-[a-z0-9]+)*$/', !!sk && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(sk.name), sk ? sk.name : '-')
check('技能带 whenToUse（用于「什么时候该用/不该用」的路由）', !!sk && typeof sk.whenToUse === 'string' && sk.whenToUse.length > 0,
  sk ? String(sk.whenToUse || '').length + ' chars' : '-')
check('技能正文含「不要用本插件」的排除指引', !!sk && /not this plugin/i.test(sk.content), sk ? String(/not this plugin/i.test(sk.content)) : '-')

// 桥工具回归：MCP_TOOLS 条目（defineTool 会丢掉自定义键，所以查生成器输出本身，不查注册结果）
// 必须带 params 数组（name 字符串）—— 缺了它 lib/mcp.js 的 buildRequest 编不出 GET query /
// POST body（上游恒报 "X is required"）。
const mcpNoParams = MCP_TOOLS.filter((t) => !(Array.isArray(t.params) && t.params.every((p) => typeof p.name === 'string')))
check('桥工具全部带 params 数组（buildRequest 参数源）', mcpNoParams.length === 0,
  'missing params=' + JSON.stringify(mcpNoParams.map((t) => t.name)))
// 插件化回归：状态路由（webServer 软注入注册）+ volatile 配置（可热改）
const ROUTE_PATHS = ['/api/dsh-ghidra/status', '/api/dsh-ghidra/mcp-stop', '/api/dsh-ghidra/doctor', '/api/dsh-ghidra/install-ghidra', '/api/dsh-ghidra/migrate-home', '/api/dsh-ghidra/list-dir', '/api/dsh-ghidra/mkdir']
check('状态路由注册了 ' + ROUTE_PATHS.length + ' 条（status/mcp-stop/doctor/install/migrate/list-dir/mkdir）',
  routes.length === ROUTE_PATHS.length && routes.every((r) => typeof r.handler === 'function')
    && ROUTE_PATHS.every((p) => routes.some((r) => r.path === p)),
  routes.map((r) => (r.kind || '?') + ' ' + r.path + ' ' + (r.method || '')).join(' | '))
check('Config 字段全部 volatile（可热改）',
  !!config && Object.values(config).every((v) => typeof (v && v.get) === 'function'),
  config ? Object.keys(config).filter((k) => typeof (config[k] && config[k].get) !== 'function').join('/') || 'all-volatile' : '-')

console.log('')
console.log(fails.length === 0 ? '=== LOAD TEST PASSED ===' : '=== LOAD TEST FAILED: ' + fails.join(' | ') + ' ===')
process.exit(fails.length === 0 ? 0 : 1)
