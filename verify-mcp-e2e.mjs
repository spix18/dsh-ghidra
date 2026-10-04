// MCP 桥真实 E2E：对 8123 上已运行的 ghidraMCPHeadless（winver.exe 已加载）
// 验证：mcpStart 采纳路径 → 只读工具 → 写工具（create_label）→ 读回 → 删除 → ghidra_mcp_stop 优雅退出
import { pathToFileURL } from 'node:url'
import { ok, strictEqual } from 'node:assert'

const dir = process.argv[2] || 'C:\\Users\\Administrator\\.dsh\\profiles\\web\\node_modules\\dsh-ghidra'
const mod = await import(pathToFileURL(dir.replace(/\\/g, '/').replace(/\/index\.js$/, '') + '/index.js').href)
const installed = mod.default?.name === 'ghidra-bridge' ? mod.default : mod

const toolsMap = new Map()
const effects = []
const ctx = {
  effect: (f) => effects.push(f),
  log: () => {},
  jobs: { start: async () => { throw new Error('no jobs in E2E') } },
  tools: { register(t) { toolsMap.set(t.name, t) } },
}
installed.apply(ctx, installed.Config({}))

const call = async (name, args) => {
  const tool = toolsMap.get(name)
  ok(tool, `tool ${name} not found`)
  return tool.execute(args)
}

// 1) ghidra_mcp_start（无 file）—— 采纳路径（服务器已在运行，winver 保留）
const st = await call('ghidra_mcp_start', {})
console.log('START ok=', st.ok, 'adopted=', st.adopted, 'pid=', st.pid, JSON.stringify(st.error ?? '').slice(0, 200))
ok(st.ok === true, 'mcp_start ok (adopt): ' + JSON.stringify(st.error ?? ''))
ok(st.adopted === true, 'adopted existing server')

// 1b) ghidra_mcp_status —— /health 快照
const hs = await call('ghidra_mcp_status', {})
console.log('STATUS running=', hs.result?.running, 'health=', JSON.stringify(hs.result?.health))
ok(hs.ok === true && hs.result?.running === true, 'status running')
strictEqual(hs.result.health.program_loaded, true, 'winver still loaded after adopt')
strictEqual(hs.result.health.program_name, 'winver.exe', 'program name winver.exe')

// 2) 只读：list_functions_enhanced
const lf = await call('ghidra_mcp_list_functions_enhanced', { limit: 5 })
console.log('LIST_FUNCTIONS_ENHANCED ok=', lf.ok, 'result=', JSON.stringify(lf.result).slice(0, 300))
ok(lf.ok === true, 'list_functions_enhanced ok')

// 3) 写：create_label @ 入口函数
const ep = await call('ghidra_mcp_get_entry_points', {})
const eps = ep.result?.entry_points ?? []
const epFn = eps.find((e) => e.kind === 'external_entry' && e.symbol_type === 'Function') ?? eps[0]
console.log('ENTRY_POINT=', JSON.stringify(epFn))
const addr = epFn?.address
ok(addr, 'entry point address')
const token = 'MCP-E2E-' + Date.now()
const created = await call('ghidra_mcp_create_label', { address: addr, name: token })
console.log('CREATE_LABEL ok=', created.ok, JSON.stringify(created.result ?? created.error).slice(0, 300))
ok(created.ok === true, 'create_label ok: ' + JSON.stringify(created.error ?? ''))

// 4) 读回：上游无 list_labels → get_function_labels（name 收函数名或地址）
const lst = await call('ghidra_mcp_get_function_labels', { name: addr })
console.log('GET_FUNCTION_LABELS ok=', lst.ok, JSON.stringify(lst.result ?? lst.error).slice(0, 300))
ok(lst.ok === true, 'get_function_labels ok: ' + JSON.stringify(lst.error ?? ''))
const arr = lst.result?.labels ?? lst.result?.list ?? (Array.isArray(lst.result) ? lst.result : [])
const found = arr.some((l) => String(l.name ?? l.label ?? l).includes(token))
ok(found, 'label readable back, got: ' + JSON.stringify(arr).slice(0, 300))
console.log('LABEL READBACK=', found)

// 5) 删除标签（清理）
const del = await call('ghidra_mcp_delete_label', { address: addr, name: token })
console.log('DELETE_LABEL ok=', del.ok, JSON.stringify(del.result ?? del.error).slice(0, 300))
ok(del.ok === true, 'delete_label ok: ' + JSON.stringify(del.error ?? ''))

console.log('=== MCP_E2E_OK ===')
