// 端到端：用**实装副本**（新数据根里的 Ghidra）走一遍 openFlow（导入 → 启动常驻桥 → info），
// 证明搬到 node_modules\.dsh-ghidra\ghidra 的安装是可用的，而不是只"文件在那儿"。
import { join } from 'node:path'
import { fileUrl, installedDir } from './lib/dev-env.mjs'
const LIB = (name) => fileUrl(join(installedDir('web'), 'lib', name))
const { detectGhidraHome, importBinary, startServer, projectPaths } = await import(LIB('ghidra.js'))
const { jsonRequest } = await import(LIB('socket.js'))

const cfg = { pythonVer: '3.13', analysisTimeoutSec: 600, serverStartupTimeoutMs: 240000, stream: false }
// 样本二进制按平台选：原来写死 Windows 的 cmd.exe，非 Windows 上必 ENOENT。
const SAMPLE = process.argv[2] || (process.platform === 'win32' ? 'C:\\Windows\\System32\\cmd.exe' : '/bin/ls')
const log = (m) => process.stdout.write(String(m))

const gh = detectGhidraHome(cfg)
console.log('home   =', gh && gh.home, '| source =', gh && gh.source)
if (!gh) { console.error('no ghidra home'); process.exit(2) }
console.log('project=', JSON.stringify(projectPaths(cfg)))

let srv = null
try {
  const program = await importBinary(gh, SAMPLE, cfg, log)
  console.log('\nimported program =', program)
  srv = await startServer(gh, program, cfg, log)
  console.log('\nserver port =', srv.port, 'program =', srv.program)
  const info = await jsonRequest(srv.port, { op: 'info' }, 60000)
  console.log('info.ok =', info.ok, '| functions =', info.result && info.result.functions)
  const mcp = await jsonRequest(srv.port, { op: 'mcpServe', port: 8123 }, 120000)
  console.log('mcpServe =', JSON.stringify(mcp.result || mcp))
  const h = await fetch('http://127.0.0.1:8123/health').then((r) => r.json())
  console.log('REST /health =', JSON.stringify(h))
  const stop = await jsonRequest(srv.port, { op: 'mcpStop' }, 60000)
  console.log('mcpStop =', JSON.stringify(stop.result || stop))
  const shut = await jsonRequest(srv.port, { op: 'shutdown' }, 30000)
  console.log('shutdown =', JSON.stringify(shut))
  console.log('\n=== IN-TREE E2E OK (functions=' + (info.result && info.result.functions) + ', mcp=' + (h && h.program_name) + ') ===')
  process.exit(0)
} catch (e) {
  console.error('\nIN-TREE E2E FAILED:', String((e && e.message) || e))
  try { if (srv && srv.port) await jsonRequest(srv.port, { op: 'shutdown' }, 15000) } catch {}
  process.exit(1)
}
