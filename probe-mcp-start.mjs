// probe-mcp-start.mjs — 验证 mcpStart 的 spawn 修复（Node 20.12+ .bat EINVAL → cmd.exe / shell:true）。
// 从【已装副本】fresh import（新进程 = 新模块加载，绕开运行中 DSH 的旧内存代码）。
// 无 --file：只起服务器不载程序。服务器在 probe 退出后作为孤儿存活，留给运行中会话的
// ghidra_mcp_* 工具直接用（ghidra_mcp_start 走采纳路径，不需要 spawn）。
import { pathToFileURL } from 'node:url'
import { installedDir } from './lib/dev-env.mjs'

const copy = process.argv[2] || installedDir('web')
const mod = await import(pathToFileURL(copy.replace(/\\/g, '/')).href + '/lib/mcp.js')

const t0 = Date.now()
// 镜像 index.js:1023-1028：bat 从 ghidra_status 检测结果拼（gh.home + support/ghidraMCPHeadless.bat）
const BAT = 'D:/tools/ghidra_12.1.4_PUBLIC/support/ghidraMCPHeadless.bat'
const r = await mod.mcpStart({ bat: BAT, timeoutMs: 180000 })
console.log('MCP_START ms=' + (Date.now() - t0))
console.log(JSON.stringify(r))

if (!r.ok) {
  console.log('START FAILED')
  process.exit(1)
}

// 全链路：起好的服务器上打一发只读端点（/server/status——注意是两级路径，不是 /server_status），
// 证明桥 + 上游都活着。
const s = await mod.mcpCall(r.port, { path: '/server/status', method: 'GET', params: [] }, {}, 30000)
console.log('SERVER_STATUS ok=' + s.ok)
console.log(JSON.stringify(s.result || s.error).slice(0, 400))
console.log(s.ok ? 'PROBE OK' : 'PROBE FAILED')
