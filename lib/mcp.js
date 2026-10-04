// lib/mcp.js — 上游 GhidraMCP headless 服务器的 HTTP 桥（bethington/ghidra-mcp 7.0.0-rc.1）
// 架构：上游发布物自带独立 headless 服务器（com.xebyte.headless.GhidraMCPHeadlessServer，
// 注册 226 个 REST 端点），这里把它当子进程拉起（<ghidraHome>/support/ghidraMCPHeadless.bat，
// 由 launch.bat fg GhidraMCP-Headless 把用户扩展加进 classpath），REST 调用走 HTTP：
// GET → query 参数、POST → JSON body（Content-Type application/json）。服务器按 Java 参数类型
// 自动转换（Param.java），所以 query 里一律传字符串、body 里保留原生 JSON 类型即可。
import { spawn, spawnSync } from 'node:child_process'
import { appendFileSync, mkdirSync, openSync, closeSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { killPid, pidAlive, sleep } from './run.js'
import { dataPaths } from './paths.js'

const HERE = path.dirname(fileURLToPath(import.meta.url))
export const MCP_DEFAULT_PORT = 8123
// 日志落在插件数据根（<…>/node_modules/.dsh-ghidra/logs），不再用 %TEMP%：
// 「关于这个插件的一切」都在插件树里，清理/备份只动一个目录。
const LOG_DIR = dataPaths().logDir
export const LOG_FILE = path.join(LOG_DIR, 'mcp-headless.log')

function baseUrl(port) { return 'http://127.0.0.1:' + port }

// GET /health —— 存活与就绪判据（{status:'healthy', version, program_loaded, program_name}）
export async function mcpHealth(port, timeoutMs = 5000) {
  try {
    const r = await fetch(baseUrl(port) + '/health', { signal: AbortSignal.timeout(timeoutMs) })
    const body = await r.json().catch(() => null)
    if (!r.ok) return { ok: false, error: 'HTTP ' + r.status + ': ' + JSON.stringify(body) }
    return { ok: true, body }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

// 把端点参数编进请求：GET → query（一律字符串化）；POST → JSON body（只带调用方给的参数）。
// 空串/undefined/null 跳过 —— 上游 required 校验会自己报缺参，报错文案比我们猜的准。
function buildRequest(port, ep, params) {
  if ((ep.method || 'GET') === 'GET') {
    const qs = new URLSearchParams()
    for (const p of ep.params || []) {
      const v = params ? params[p.name] : undefined
      if (v === undefined || v === null || v === '') continue
      qs.set(p.name, String(v))
    }
    const q = qs.toString()
    return { url: baseUrl(port) + ep.path + (q ? '?' + q : ''), init: { method: 'GET' } }
  }
  const body = {}
  for (const p of ep.params || []) {
    const v = params ? params[p.name] : undefined
    if (v === undefined || v === null) continue
    body[p.name] = v
  }
  return { url: baseUrl(port) + ep.path, init: { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } }
}

// 单次 REST 调用。永不 throw —— 返回 {ok:false,error}，由工具层决定呈现。
export async function mcpCall(port, ep, params, timeoutMs = 900000) {
  const { url, init } = buildRequest(port, ep, params)
  init.signal = AbortSignal.timeout(timeoutMs)
  let r
  try {
    r = await fetch(url, init)
  } catch (e) {
    const refused = /ECONNREFUSED|fetch failed|aborted/i.test(e.name + ' ' + e.message)
    return {
      ok: false,
      path: ep.path,
      error: refused
        ? 'MCP 服务器未运行或超时（port ' + port + '）— 先调 ghidra_mcp_start 启动（可带 file 参数自动加载程序），超时通常是首次启动/首次分析耗时较长'
        : 'MCP 调用失败: ' + e.message,
    }
  }
  const text = await r.text().catch(() => '')
  let body = null
  try { body = text ? JSON.parse(text) : null } catch { body = { raw: text } }
  if (!r.ok) {
    const msg = body && (body.error || body.message) ? (body.error || body.message) : text.slice(0, 500)
    const hint = /no program|not loaded|program_loaded/i.test(msg) ? ' — MCP 服务器里还没有加载程序：先调 ghidra_mcp_start（可带 file）或 ghidra_mcp_load_program' : ''
    return { ok: false, path: ep.path, error: 'HTTP ' + r.status + ': ' + msg + hint, result: body }
  }
  // 上游错误有两种形状：{success:false,error} 与裸 {error}（HTTP 仍 200）——都算失败；
  // 成功包络 {status:'success',message,warnings[]} 无 error 键，不受影响。
  const upErr = body && typeof body.error === 'string' && body.error ? body.error : (body && body.success === false ? String(body.error || body.message || '上游返回 success:false') : null)
  if (upErr) {
    return { ok: false, path: ep.path, error: upErr, result: body }
  }
  return { ok: true, path: ep.path, result: body }
}

// 拉起上游 headless 服务器。已在运行 → 采纳（服务器有状态：已加载的程序保留，重启会丢）。
// stdout/stderr 重定向到日志文件（照 lib/ghidra.js 模式）——服务器在管道断开后会存活但输出
// 丢失，必须落盘才能排查。成功判据 = /health 200；bat 自身退出不算失败。
// Node 20.12+ 在 Windows 上对 .bat/.cmd 直接 spawn（无 shell）一律抛 EINVAL（CVE-2024-27980
// 修复），必须走 shell:true + 单串命令；含空格的 token 手工加引号。child.pid 是 cmd.exe 的，
// 停止时 mcpStop 用 findPidByPort 找真正的 java PID。
export async function mcpStart(opts = {}) {
  const port = opts.port || MCP_DEFAULT_PORT
  const h = await mcpHealth(port, 3000)
  if (h.ok) {
    return { ok: true, port, adopted: true, body: h.body, note: 'MCP 服务器已在运行，直接采纳（已加载程序保留）' }
  }
  if (!opts.bat) return { ok: false, error: '缺少 ghidraMCPHeadless.bat 路径（ghidraHome 未配置或未检测到）' }
  mkdirSync(LOG_DIR, { recursive: true })
  appendFileSync(LOG_FILE, '==== ' + new Date().toISOString() + ' mcp-start port=' + port + (opts.file ? ' file=' + opts.file : '') + ' ====\n')
  const logFd = openSync(LOG_FILE, 'a')
  const args = ['--port', String(port)]
  if (opts.file) args.push('--file', opts.file)
  if (opts.project) args.push('--project', opts.project)
  const cmd = [opts.bat, ...args].map((a) => (/\s/.test(a) ? '"' + a + '"' : a)).join(' ')
  const child = spawn(cmd, {
    shell: true,
    windowsHide: true,
    stdio: ['ignore', logFd, logFd],
  })
  try { closeSync(logFd) } catch { /* ignore */ }
  const startupMs = opts.timeoutMs || 180000
  const deadline = Date.now() + startupMs
  while (Date.now() < deadline) {
    await sleep(1500)
    const h2 = await mcpHealth(port, 2000)
    if (h2.ok) return { ok: true, port, adopted: false, pid: child.pid, log: LOG_FILE, body: h2.body }
  }
  return { ok: false, port, pid: child.pid, log: LOG_FILE, error: 'MCP 服务器启动超时（' + Math.round(startupMs / 1000) + 's）— 日志: ' + LOG_FILE }
}

// netstat 找占用端口的 PID（Windows）
function findPidByPort(port) {
  try {
    const out = spawnSync('netstat', ['-ano'], { encoding: 'utf8', windowsHide: true })
    for (const line of (out.stdout || '').split(/\r?\n/)) {
      if (line.includes(':' + port + ' ') && /LISTENING/i.test(line)) {
        const parts = line.trim().split(/\s+/)
        const pid = Number(parts[parts.length - 1])
        if (pid > 0) return pid
      }
    }
  } catch { /* ignore */ }
  return 0
}

// 停止上游服务器：先 /save_all_programs + /exit_ghidra（优雅，保存已加载程序），轮询没退才按
// 端口/PID 强杀（gradle 部署配方同款顺序）。
export async function mcpStop(port, pid) {
  const started = Date.now()
  const alive = await mcpHealth(port, 3000)
  if (!alive.ok) {
    if (pid && pidAlive(pid)) { killPid(pid) }
    return { ok: true, port, pid, ms: Date.now() - started, note: '服务器已经不在了' }
  }
  // 优雅：保存并退出 Ghidra（服务器与 Ghidra 同 JVM，exit 后大概率一起退）
  await mcpCall(port, { path: '/save_all_programs', method: 'GET', params: [] }, {}, 60000)
  await mcpCall(port, { path: '/exit_ghidra', method: 'POST', params: [] }, {}, 60000)
  const deadline = Date.now() + 20000
  while (Date.now() < deadline) {
    await sleep(1000)
    const h = await mcpHealth(port, 2000)
    if (!h.ok) break
  }
  let still = (await mcpHealth(port, 2000)).ok
  const realPid = pid && pidAlive(pid) ? pid : findPidByPort(port)
  if (still && realPid) { killPid(realPid); still = false }
  return { ok: true, port, pid: realPid || pid, ms: Date.now() - started, graceful: !still }
}
