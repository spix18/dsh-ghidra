// verify-load.mjs — 验收「DSH/cordis 能否加载 ghidra-bridge 并注册 29 个工具」
// 用绝对 file:// URL 载入 **已安装副本**，这样插件内部的裸包名（@deepseek-ai/*）
// 按 node_modules 树正常解析，等价于 DSH 运行时的真实加载路径。
// 用法: node verify-load.mjs [已装副本目录或 index.js 的路径]
//       缺省 = web profile 的副本；传 headless 副本可证明两个 profile 一致。
const arg = process.argv[2]
const PLUGIN = arg
  ? 'file:///' + arg.replace(/\\/g, '/').replace(/\/index\.js$/, '') + '/index.js'
  : 'file:///C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra/index.js'

const mod = await import(PLUGIN)

const registered = []
const effects = []
const routes = []
// 最小 cordis ctx 桩：注入的服务名对（inject = ['tools','jobs']）就能驱动 apply；
// inject + webServer 桩模拟宿主软注入（真实 ctx 有 inject，缺了它 apply 的状态路由会抛 TypeError）
const ctx = {
  effect(fn) { const d = fn(); effects.push(typeof d); return d },
  tools: { register(t) { registered.push(t) } },
  jobs: { start() { return { id: 'stub' } } },
  logger: console,
  inject(names, cb) { return cb({ webServer: { exact: new Map(), prefixes: new Map(), register(r) { routes.push(r) } } }) },
}

const fails = []
const check = (label, cond, detail) => {
  console.log((cond ? 'PASS  ' : 'FAIL  ') + label + (detail === undefined ? '' : '  :: ' + detail))
  if (!cond) fails.push(label)
}

check('name === ghidra-bridge', mod.name === 'ghidra-bridge', mod.name)
check("inject === ['tools','jobs']", JSON.stringify(mod.inject) === '["tools","jobs"]', JSON.stringify(mod.inject))
check('apply 是函数', typeof mod.apply === 'function')

let config = null
try { config = mod.Config({}) } catch (e) { /* 下面统一判定 */ }
// volatile 字段的默认值是 ref（.get() 恒答当前值）—— 读法与 index.js 的 resolveConfig 一致
const val = (x) => { const v = config ? config[x] : undefined; return typeof (v && v.get) === 'function' ? v.get() : v }
check('Config({}) 填充出 12 个默认项', !!config && Object.keys(config).length === 12,
  config ? Object.keys(config).join('/') : 'Config 不可调用')
check('默认 pythonVer=3.13 / projectName=dsh / mcpPort=8123 / mcpMode=unified',
  val('pythonVer') === '3.13' && val('projectName') === 'dsh' && val('mcpPort') === 8123 && val('mcpMode') === 'unified',
  'pythonVer=' + val('pythonVer') + ' projectName=' + val('projectName') + ' mcpPort=' + val('mcpPort') + ' mcpMode=' + val('mcpMode'))

try { mod.apply(ctx, config) } catch (e) { check('apply 未抛异常', false, String(e && e.message || e)) }

const names = registered.map((t) => t.name)
const baseExpected = ['ghidra_status', 'ghidra_open', 'ghidra_info', 'ghidra_decompile',
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
// 用于核对【已装副本】注册的就是生成器产出的那一套（副本与源不同步时会 FAIL）。
const { MCP_TOOLS } = await import('file:///C:/Users/Administrator/.dsh/plugins/ghidra-bridge/lib/mcp-tools.js')
const expected = [...baseExpected, ...MCP_TOOLS.map((t) => t.name)]
check('注册了 ' + expected.length + ' 个工具', names.length === expected.length, names.length + ' 个: ' + names.join(', '))
check('工具名与预期完全一致', expected.every((n) => names.includes(n)) && names.every((n) => expected.includes(n)),
  'missing=' + JSON.stringify(expected.filter((n) => !names.includes(n))) + ' extra=' + JSON.stringify(names.filter((n) => !expected.includes(n))))
check('每个工具都是合法 defineTool 形状(name/description/parameters/execute)',
  registered.every((t) => t.name && t.description && t.parameters && typeof t.execute === 'function'),
  'bad=' + JSON.stringify(registered.filter((t) => !(t.name && t.description && t.parameters && typeof t.execute === 'function')).map((t) => t.name)))
check('ctx.effect 注册了 dispose 函数', effects.length === 1 && effects[0] === 'function', JSON.stringify(effects))
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
