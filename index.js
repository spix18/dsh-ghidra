// dsh-ghidra — 让 DSH 操作 Ghidra 反编译（常驻 PyGhidra 服务器 + TCP JSON-RPC；外加上游 GhidraMCP headless REST 桥）
import { defineTool } from '@deepseek-ai/dsh-tools'
import Schema from '@deepseek-ai/schemastery'
import { basename, join, isAbsolute, dirname } from 'node:path'
import { existsSync, statSync, cpSync, rmSync, mkdirSync, readdirSync, createWriteStream } from 'node:fs'
import { jsonRequest } from './lib/socket.js'
import { detectGhidraHome, readVersion, pyghidraInstalled, importBinary, startServer, projectPaths } from './lib/ghidra.js'
import { killPid, pidAlive, sleep } from './lib/run.js'
import { mcpStart, mcpCall, mcpStop, mcpHealth, LOG_FILE as MCP_LOG_FILE, MCP_DEFAULT_PORT } from './lib/mcp.js'
import { MCP_TOOLS } from './lib/mcp-tools.js'
import { spawnSync, execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { Readable, Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { dataPaths, ensureDataPaths, pluginDataRoot } from './lib/paths.js'
import { loadSkillDefinition, SKILL_FILE } from './lib/skill.js'
const execFileP = promisify(execFile)

export const name = 'ghidra-bridge'
export const inject = ['tools', 'jobs']

export const Config = Schema.object({
  // 每个字段 .volatile()：apply 时是 ref（Loader 原地更新），插件管理页可写；写侧 reload entry 重跑 apply。
  ghidraHome: Schema.string().default('').description('Ghidra 安装目录（缺省自动探测 GHIDRA_HOME / 常见安装路径）').volatile(),
  ghidraProjectDir: Schema.string().default('').description('Ghidra 项目目录（缺省 <ghidraHome>\\Ghidra Projects，其次 %TEMP%）').volatile(),
  projectName: Schema.string().default('dsh').description('Ghidra 项目名（缺省 dsh）').volatile(),
  pythonVer: Schema.string().default('3.13').description('PyGhidra 的 Python 版本（缺省 3.13）').volatile(),
  analysisTimeoutSec: Schema.number().default(600).description('导入/分析超时（秒）').volatile(),
  serverStartupTimeoutMs: Schema.number().default(180000).description('PyGhidra 服务器启动超时（毫秒）').volatile(),
  maxOutputChars: Schema.number().default(100000).description('工具输出截断上限（字符）').volatile(),
  stream: Schema.boolean().default(true).description('导入/分析进度流式输出（后台任务）').volatile(),
  mcpPort: Schema.number().default(8123).description('上游 GhidraMCP headless 服务器端口（缺省 8123）').volatile(),
  mcpMode: Schema.string().default('unified').description('MCP 承载方式：unified=在 PyGhidra 桥的同一个 JVM 内启动上游 REST 服务器并绑定同一程序（单进程，推荐）；standalone=独立启动 ghidraMCPHeadless.bat（第二个 Ghidra 进程）').volatile(),
  mcpStartupTimeoutSec: Schema.number().default(180).description('GhidraMCP 服务器启动超时（秒）').volatile(),
  mcpTimeoutSec: Schema.number().default(900).description('GhidraMCP 工具调用超时（秒）').volatile(),
}).description('Ghidra 桥配置（字段全部可热改：保存后立即生效，无需重启 DSH）')

const OUT = {
  type: 'object',
  additionalProperties: false,
  properties: {
    kind: { type: 'string' },
    jobId: { type: 'string' },
    label: { type: 'string' },
    ok: { type: 'boolean' },
    error: { type: 'string' },
    note: { type: 'string' },
    port: { type: 'integer' },
    program: { type: 'string' },
    pid: { type: 'integer' },
    result: { type: 'json' },
  },
}

function render(_args, value) {
  const parts = []
  if (value.kind === 'background') {
    parts.push('后台任务已启动: ' + value.jobId + '（' + value.label + '）')
    parts.push('导入/分析进度会流式进入该任务；完成后我会收到通知，可 job_output 读取。')
    return [{ type: 'text', text: parts.join('\n') }]
  }
  parts.push('ok=' + value.ok + (value.port ? ' port=' + value.port : '') + (value.program ? ' program=' + value.program : ''))
  if (value.error) parts.push('错误: ' + value.error)
  const r = value.result
  if (r) {
    if (r.code) parts.push('--- 反编译 ---\n' + String(r.code).slice(0, 20000) + (String(r.code).length > 20000 ? '\n[已截断]' : ''))
    else if (r.list) parts.push('--- 列表 (' + r.total + ') ---\n' + JSON.stringify(r.list).slice(0, 8000))
    else parts.push('--- 结果 ---\n' + JSON.stringify(r).slice(0, 8000))
  }
  return [{ type: 'text', text: parts.join('\n\n') }]
}

// ---- 上游 GhidraMCP REST 桥（ghidra_mcp_* 工具族的输出 schema 与渲染） ----
const MCP_OUT = {
  type: 'object',
  additionalProperties: false,
  properties: {
    ok: { type: 'boolean' },
    error: { type: 'string' },
    note: { type: 'string' },
    path: { type: 'string' },
    port: { type: 'integer' },
    pid: { type: 'integer' },
    adopted: { type: 'boolean' },
    graceful: { type: 'boolean' },
    ms: { type: 'integer' },
    log: { type: 'string' },
    result: { type: 'json' },
    body: { type: 'json' },
  },
}

function renderMcp(_args, value) {
  const parts = []
  parts.push((value.path ? value.path + ' ' : '') + 'ok=' + value.ok + (value.port ? ' port=' + value.port : ''))
  if (value.error) parts.push('错误: ' + value.error)
  if (value.note) parts.push('提示: ' + value.note)
  if (value.result !== undefined && value.result !== null) {
    parts.push('--- 结果 ---\n' + JSON.stringify(value.result).slice(0, 12000))
  } else if (value.body !== undefined && value.body !== null) {
    parts.push('--- 服务器 ---\n' + JSON.stringify(value.body).slice(0, 2000))
  }
  return [{ type: 'text', text: parts.join('\n') }]
}

// ---- 模块级共享状态：volatile 配置写入会重跑 apply（Loader reload entry），
// 服务器状态跨 re-entry 保留（工具/路由重注册不丢运行中的桥）。----
const state = { child: null, port: null, program: null, serverPid: 0, binaryPath: null, mcpPid: 0 }
let currentConfig = null   // 最近一次 apply 解析出的配置快照（volatile ref 已解析成普通值）
let activeDisposers = null // 上一轮注册的工具/路由 disposer（re-entry 先拆解再重注册）
let currentGate = null     // 最近一次 apply 建的工具可用性门（见 apply 里的「可用性门控」）
const toolCounts = { native: 0, lifecycle: 0, generated: 0 }
// 不需要任何服务器就能跑的原生工具（其余 45 个原生工具都要 PyGhidra 桥在跑）。
// 这几个必须常驻：它们是 agent 用来【发现】当前可用性并把它拉起来的入口，
// 藏起来就等于把唯一的补救手段藏起来。
const ALWAYS_AVAILABLE = new Set(['ghidra_status', 'ghidra_open'])
// 三个 lifecycle 工具（其余 ghidra_mcp_* 都是生成的 REST 包装）
const LIFECYCLE_TOOL_NAMES = new Set(['ghidra_mcp_start', 'ghidra_mcp_stop', 'ghidra_mcp_status'])
// 后台任务状态（Ghidra 下载安装 / home 迁移）—— 跨 re-entry 共享，状态路由上报进度
const installState = { running: false, phase: '', pct: 0, bytes: 0, total: 0, error: '', home: null, log: '' }
const migrateState = { running: false, phase: '', error: '', from: null, to: null, ok: null }
// 随包技能（skills/dsh-ghidra/SKILL.md → ctx.skills.register）的注册结果，状态路由上报
const skillState = { registered: false, name: null, file: SKILL_FILE, error: '' }

// ---- Ghidra 下载安装（GitHub 最新 release → 下载 → PowerShell 解压 → 校验）----
// 后台执行（execFile 不阻塞宿主事件循环）；进度写 installState，状态路由上报。
async function runInstall(targetRoot, force) {
  const ua = { headers: { 'user-agent': 'dsh-ghidra-plugin', accept: 'application/vnd.github+json' } }
  try {
    installState.phase = 'resolving latest release'
    const rel = await fetch('https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest', ua)
    if (!rel.ok) throw new Error('GitHub API ' + rel.status + ' ' + rel.statusText)
    const meta = await rel.json()
    const asset = (meta.assets || []).find((a) => /ghidra_.*_PUBLIC_.*\.zip$/i.test(String(a.name || '')))
    if (!asset) throw new Error('no Ghidra *_PUBLIC_*.zip asset in release ' + (meta.tag_name || meta.name || '?'))
    const zipPath = join(targetRoot, 'dsh-ghidra-download.zip')
    installState.phase = 'downloading ' + asset.name
    installState.total = asset.size || 0
    installState.bytes = 0
    installState.log = asset.browser_download_url
    const zres = await fetch(asset.browser_download_url, { headers: { 'user-agent': 'dsh-ghidra-plugin' } })
    if (!zres.ok || !zres.body) throw new Error('download failed: HTTP ' + zres.status)
    let done = 0
    const counter = new Transform({
      transform(chunk, _enc, cb) {
        done += chunk.length
        installState.bytes = done
        if (installState.total) installState.pct = Math.round((done * 100) / installState.total)
        cb(null, chunk)
      },
    })
    await pipeline(Readable.fromWeb(zres.body), counter, createWriteStream(zipPath))
    // 解压：zip 根目录是 ghidra_<ver>_PUBLIC/；-Force 允许覆盖（reinstall 同版本）
    installState.phase = 'extracting'
    installState.pct = 0
    await execFileP('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'Expand-Archive -LiteralPath "' + zipPath + '" -DestinationPath "' + targetRoot + '" -Force'], { timeout: 900000 })
    // 探测解压出的 home：targetRoot 下最新修改的 ghidra_* 目录
    const dirs = readdirSync(targetRoot, { withFileTypes: true })
      .filter((d) => d.isDirectory() && /^ghidra_/i.test(d.name))
      .map((d) => { const p = join(targetRoot, d.name); return { p, mtime: statSync(p).mtimeMs } })
      .sort((a, b) => b.mtime - a.mtime)
    const newHome = dirs[0]?.p || null
    if (!newHome) throw new Error('extraction produced no ghidra_* directory in ' + targetRoot)
    if (!existsSync(join(newHome, 'support', 'ghidraMCPHeadless.bat'))) {
      throw new Error('extracted home missing support/ghidraMCPHeadless.bat — ' + newHome)
    }
    try { rmSync(zipPath, { force: true }) } catch {}
    installState.running = false
    installState.phase = 'done'
    installState.pct = 100
    installState.home = newHome
  } catch (e) {
    installState.running = false
    installState.phase = 'failed'
    installState.error = String(e?.message || e)
    throw e
  }
}

// ---- home 迁移（旧 home → 新目录：停双服务器 → 复制 → 校验 → 删旧）----
// 校验不过就保留旧 home（不删）；迁移是后台执行，进度写 migrateState，状态路由上报。
async function runMigrate(from, to) {
  try {
    migrateState.phase = 'stopping servers'
    await stopServer(20000).catch(() => {})
    try { await mcpStop(currentConfig?.mcpPort, state.mcpPid || 0) } catch {}
    state.mcpPid = 0
    migrateState.phase = 'copying'
    mkdirSync(to, { recursive: true })
    cpSync(from, to, { recursive: true, force: true })
    migrateState.phase = 'verifying'
    const launcher = existsSync(join(to, 'Ghidra', 'Features', 'PyGhidra', 'support', 'pyghidra_launcher.py'))
    const bat = existsSync(join(to, 'support', 'ghidraMCPHeadless.bat'))
    if (!launcher || !bat) throw new Error('verification failed (launcher=' + launcher + ' bat=' + bat + ') — old home kept')
    migrateState.phase = 'deleting old home'
    rmSync(from, { recursive: true, force: true, maxRetries: 3, retryDelay: 1000 })
    migrateState.running = false
    migrateState.phase = 'done'
    migrateState.ok = true
  } catch (e) {
    migrateState.running = false
    migrateState.phase = 'failed'
    migrateState.error = String(e?.message || e)
    migrateState.ok = false
    throw e
  }
}

// volatile ref → 普通值（volatile 字段在 apply 时是 ref；写侧 reload entry 重跑 apply，快照即最新）
function resolveConfig(config) {
  const out = {}
  for (const [k, v] of Object.entries(config ?? {})) {
    out[k] = (v !== undefined && v !== null && typeof v.get === 'function') ? v.get() : v
  }
  return out
}

// 模块级服务器状态机（killServer/stopServer 只读 state；跨 apply re-entry 共享）
const killServer = () => {
    // 必须先杀真正的 JVM（serverPid 由 DecompileBridge.py 上报）。pyghidra_launcher.py 拉起 Ghidra 后
    // 自己就退出了，只杀 child.pid 会留下孤儿 JVM 继续占端口与项目锁。
    if (state.serverPid) { killPid(state.serverPid); state.serverPid = 0 }
    if (state.child) { killPid(state.child.pid); state.child = null }
    state.port = null
    state.program = null
    state.binaryPath = null
  }

  // 优雅停止：先发 shutdown 让 DecompileBridge.py 的 main() return —— headless 只有在脚本
  // 正常结束时才会把改动写回项目；直接 taskkill /F 会让所有写侧操作白做。所以这里是
  // 「先请它自己退，宽限期内没退才强杀」。
  async function stopServer(graceMs = 30000) {
    const pid = state.serverPid
    const port = state.port
    const child = state.child
    const started = Date.now()
    if (port) {
      try { await jsonRequest(port, { op: 'shutdown' }, 5000) } catch { /* 服务器可能已经死了 */ }
    }
    let graceful = true
    if (pid) {
      const deadline = Date.now() + graceMs
      while (Date.now() < deadline && pidAlive(pid)) await sleep(500)
      graceful = !pidAlive(pid)
      if (!graceful) killPid(pid)
    }
    if (child) killPid(child.pid)
    // headless 是在【脚本 return 之后】才把改动写回项目的，所以要给收尾留一点时间再让新的
    // 服务器接管项目目录（新服务器启动时会 killStaleServers，抢跑就会打断保存）。
    if (pid && graceful) await sleep(1500)
    state.serverPid = 0
    state.child = null
    state.port = null
    state.program = null
    state.binaryPath = null
    // 桥没了 → 依赖它的工具必须立刻从模型视野里撤掉（unified 模式下 REST 服务器随桥一起死）
    void currentGate?.sync()
    return { graceful: graceful, ms: Date.now() - started, pid: pid }
  }

  // 进程被硬退出（DSH 重启 / 关窗，dispose 钩子可能来不及 await）时的同步兜底：
  // 'exit' 回调里不能 await，所以起一个同步子进程去发 shutdown 并等 JVM 自己退（超时才强杀）。
  // （模块级注册一次，跨 apply re-entry 保留。）
  const SYNC_STOP = [
    'const net=require("net");',
    'const t0=Date.now();',
    'const port=Number(process.argv[1])||0,p=Number(process.argv[2])||0;',
    'const s=net.connect(port,"127.0.0.1",()=>{s.write("{\\"op\\":\\"shutdown\\"}\\n")});',
    's.on("data",()=>{});s.on("error",()=>{});',
    'const waitMs=p?15000:8000;',
    'const iv=setInterval(()=>{let alive=true;if(p){try{process.kill(p,0)}catch{alive=false}}',
    'if(!alive||Date.now()-t0>waitMs){clearInterval(iv);s.destroy();process.exit(0)}},200);',
  ].join('')
  process.on('exit', () => {
    if (!state.port) return
    const pid = state.serverPid || (state.child && state.child.pid) || 0
    try {
      spawnSync(process.execPath, ['-e', SYNC_STOP, String(state.port), String(pid)], { timeout: 20000, stdio: 'ignore' })
    } catch { /* 兜底失败就退回强杀 */ }
    killServer()
  })
export function apply(ctx, config) {
  // ---- re-entry 拆解：volatile 配置写入会重跑 apply（Loader reload entry）——
  // 先卸掉上一轮注册的工具与路由，避免 duplicate 注册抛错（tool "X" is already registered in this scope）----
  if (activeDisposers) {
    const old = activeDisposers
    activeDisposers = null
    for (const d of old.reverse()) { try { d() } catch { /* 已卸载就跳过 */ } }
  }

  // ---- 配置解析：volatile 字段在 apply 时是 ref（held reference .get() 恒答当前值）；
  // 这里解析一次成普通值。配置写入会重跑 apply()，所以每次 apply 的快照即最新；
  // 其余代码照旧读 config.*，不感知 volatile 机制。----
  config = resolveConfig(config)
  currentConfig = config

  // 注册时收集 disposer（re-entry 统一拆解重注册）
  const disposers = activeDisposers = []
  toolCounts.native = 0
  toolCounts.lifecycle = 0
  toolCounts.generated = 0

  // ---- 可用性门控：只把【当前真的能调用】的工具注册给模型 ----
  // 动机（对照 REA 的 tool availability 契约）：把 168 个 ghidra_mcp_* 无条件注册出去，会让 agent
  // 看到一整族必然失败的 schema —— 既误导（以为 REST 引擎可用），又白占 prompt 预算。
  // 依赖不满足时它们只进 pending；条件满足的那一刻才 register，条件消失就 dispose。
  // dsh-tools 的 register() 返回 disposer，注销会发 tools/change（唯一代价：那一次 prompt 前缀失效）。
  const gate = {
    // bridge：PyGhidra 桥在跑 → 45 个原生分析工具
    bridge: { pending: [], live: [], ok: false, label: 'PyGhidra bridge', fix: 'call ghidra_open on a binary' },
    // mcp：上游 GhidraMCP REST 服务器可达 → 168 个生成工具
    mcp: { pending: [], live: [], ok: false, label: 'upstream GhidraMCP REST server', fix: 'call ghidra_mcp_start (unified mode needs ghidra_open first)' },
  }
  const setGate = (key, ok) => {
    const g = gate[key]
    if (g.ok === ok) return false
    g.ok = ok
    if (ok) {
      for (const def of g.pending) g.live.push(ctx.tools.register(def))
    } else {
      while (g.live.length) { try { g.live.pop()() } catch { /* disposer 可能已失效 */ } }
    }
    return true
  }
  // 重新判定两个门。幂等，且从工具体 / 状态路由 / open / stop 之后都能安全调用。
  async function syncAvailability() {
    const cfg = currentConfig || {}
    let changed = setGate('bridge', !!state.port)
    const h = await mcpHealth(cfg.mcpPort || MCP_DEFAULT_PORT, 1500)
    if (setGate('mcp', !!h.ok)) changed = true
    return changed
  }
  // 供状态路由/工具上报：总量、当前广告量、以及被隐藏的组 + 原因 + 补救办法
  const gateSnapshot = () => {
    const total = toolCounts.native + toolCounts.lifecycle + toolCounts.generated
    const gated = gate.bridge.pending.length + gate.mcp.pending.length
    const live = gate.bridge.live.length + gate.mcp.live.length
    const hidden = []
    for (const key of ['bridge', 'mcp']) {
      const g = gate[key]
      if (!g.ok && g.pending.length) hidden.push({ group: key, label: g.label, count: g.pending.length, reason: 'not_running', remediation: g.fix })
    }
    return {
      total,
      advertised: total - gated + live,
      hidden,
      groups: {
        bridge: { available: gate.bridge.ok, tools: gate.bridge.pending.length },
        mcp: { available: gate.mcp.ok, tools: gate.mcp.pending.length },
      },
    }
  }
  currentGate = { gate, setGate, sync: syncAvailability, snapshot: gateSnapshot }
  // re-entry 时把这一轮开着的门关掉（live disposer 只归门管，所以这里统一拆）
  disposers.push(() => {
    for (const key of ['bridge', 'mcp']) {
      const g = gate[key]
      while (g.live.length) { try { g.live.pop()() } catch { /* 已失效 */ } }
    }
  })

  const pushReg = (def, need) => {
    // 三分类必须互斥：168 个生成工具也叫 ghidra_mcp_*，若按前缀一律算 lifecycle，
    // 会把它们同时算进 lifecycle 与 generated（常量），总数虚高成 386。只有这 3 个是 lifecycle。
    if (LIFECYCLE_TOOL_NAMES.has(def.name)) toolCounts.lifecycle += 1
    else if (def.name.startsWith('ghidra_mcp_')) toolCounts.generated += 1
    else toolCounts.native += 1
    // 门控归属：显式 need 优先；否则原生工具里除 ALWAYS_AVAILABLE 之外都要桥。
    // lifecycle 三个（start/stop/status）常驻 —— 它们是 agent 发现可用性并补救的唯一入口，藏起来等于把补救手段藏起来。
    let key = need
    if (!key && !LIFECYCLE_TOOL_NAMES.has(def.name) && !ALWAYS_AVAILABLE.has(def.name)) key = 'bridge'
    if (key) gate[key].pending.push(def)
    else disposers.push(ctx.tools.register(def))
    return def
  }

  // 插件卸载时自动关服务器 —— 必须**优雅**停（发 shutdown 让 DecompileBridge.py 的 main() return），
  // 因为 headless 只在脚本正常结束后才把本次会话的改动写回项目。用 killServer() 硬杀会让整个会话的
  // 写侧操作白做（实测：会话内读得到、新进程读回是旧值），这是插件最容易踩的坑。
  // （每次 apply 都注册一个 dispose 钩子：re-entry 会叠加，stopServer 幂等，卸载时全部跑一遍无害。）
  ctx.effect(() => () => stopServer(20000))

  const gh = detectGhidraHome(config)

  async function socketOp(payload, timeoutMs) {
    if (!state.port) throw new Error('Ghidra 服务器未运行，请先调用 ghidra_open')
    const resp = await jsonRequest(state.port, payload, timeoutMs || 30000)
    if (!resp.ok) throw new Error('Ghidra 操作失败: ' + (resp.error || '未知错误'))
    return resp.result
  }

  // 打开流程：导入（如需）→ 启动服务器 → info
  async function openFlow(binaryPath, onProgress) {
    if (!gh) throw new Error('未找到 Ghidra 安装（需含 support/analyzeHeadless.bat）；可用配置 ghidraHome 指定')
    const v = readVersion(gh.home)
    onProgress('Ghidra ' + v.version + ' @ ' + gh.home + '\n')
    if (!pyghidraInstalled(config.pythonVer)) {
      throw new Error('Python ' + config.pythonVer + ' 未安装 pyghidra；请执行: py -' + config.pythonVer + ' -m pip install pyghidra')
    }
    await stopServer(30000)
    const program = await importBinary(gh, binaryPath, config, onProgress)
    const srv = await startServer(gh, program, config, onProgress)
    state.child = srv.child
    state.port = srv.port
    state.program = srv.program
    state.serverPid = srv.pid || 0
    state.binaryPath = binaryPath
    const info = await socketOp({ op: 'info' }, 30000)
    // 桥起来了 → 45 个原生分析工具此刻才注册给模型（见 apply 里的「可用性门控」）
    await syncAvailability()
    return { ok: true, port: srv.port, program: srv.program, pid: srv.pid || srv.child.pid, result: info }
  }

  // 后台任务版 open（流式）
  function startOpenJob(binaryPath, exec) {
    const label = 'ghidra: ' + basename(binaryPath)
    const buf = { text: '', pos: 0 }
    const push = (s) => { buf.text = (buf.text + s).slice(-config.maxOutputChars) }
    const jobId = ctx.jobs.start({
      kind: 'ghidra-open',
      label,
      owner: exec && exec.agent ? exec.agent : null,
      outputLimitBytes: config.maxOutputChars,
      run() {
        const done = (async () => {
          try {
            const res = await openFlow(binaryPath, push)
            push('[agent-bridge] === 服务器就绪 === port=' + res.port + ' program=' + res.program)
            return { status: 'completed', detail: 'port ' + res.port }
          } catch (e) {
            push('失败: ' + e.message)
            await stopServer(5000)
            return { status: 'failed', detail: e.message }
          }
        })()
        return {
          cancel(reason) { push('已取消: ' + reason); stopServer(5000) },
          done,
          readOutput() {
            const delta = buf.text.slice(buf.pos)
            buf.pos = buf.text.length
            return delta
          },
        }
      },
    })
    return { kind: 'background', jobId, label }
  }

  // ---- 工具注册 ----

  pushReg(defineTool({
    name: 'ghidra_status',
    description: '检查 Ghidra 安装（路径/版本）、Python+pyghidra 是否就绪、桥接服务器是否在运行，并报告当前【哪些工具真的可用】。调用其他 ghidra_* 工具前先看这里：被隐藏的工具族会在 toolAvailability 里给出原因与补救办法。',
    parameters: {},
    output: { schema: OUT, render },
    async execute() {
      // 自愈门控：桥被外部杀掉/外部拉起时，agent 查状态这一步就把可用性对齐
      await syncAvailability()
      return {
        ok: true,
        result: {
          ghidra: gh ? { home: gh.home, version: readVersion(gh.home), nonAscii: gh.nonAscii } : null,
          pyghidra: pyghidraInstalled(config.pythonVer) ? { pythonVer: config.pythonVer, installed: true } : { pythonVer: config.pythonVer, installed: false },
          server: state.port ? { running: true, port: state.port, program: state.program } : { running: false },
          toolAvailability: gateSnapshot(),
        },
      }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_open',
    description: '打开一个二进制文件：首次自动导入到 Ghidra 项目并完整分析，然后启动常驻桥接服务器；之后 ghidra_decompile / ghidra_functions / ghidra_strings / ghidra_xrefs / ghidra_info 均为毫秒级。stream=true（默认）时以后台任务方式运行（导入分析可能耗时数分钟，输出流式可见）；stream=false 则同步等待。同一时刻只服务一个程序。',
    parameters: {
      binaryPath: { type: 'string', required: true, description: '要分析的二进制文件绝对路径（PE/ELF/Mach-O 等）' },
      stream: { type: 'boolean', description: 'true（默认）= 后台任务流式；false = 同步等待' },
      timeoutMs: { type: 'integer', description: '等待上限（毫秒），仅同步模式生效' },
    },
    output: { schema: OUT, render },
    async execute(args, exec) {
      if (!args.binaryPath || !args.binaryPath.trim()) throw new Error('binaryPath 不能为空')
      const stream = args.stream === undefined ? config.stream : args.stream
      if (stream) {
        try {
          return startOpenJob(args.binaryPath, exec)
        } catch (e) {
          // jobs 不可用时退回同步
          const res = await openFlow(args.binaryPath, () => {})
          return { ...res, note: '后台任务不可用，已同步执行: ' + e.message }
        }
      }
      return openFlow(args.binaryPath, () => {})
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_info',
    description: '返回当前已打开程序的概要信息：语言/编译器/镜像基址/内存块/函数数/符号数/入口点。',
    parameters: {},
    output: { schema: OUT, render },
    async execute() { return { ok: true, result: await socketOp({ op: 'info' }) } },
  }))

  pushReg(defineTool({
    name: 'ghidra_decompile',
    description: '反编译指定函数为 C 伪代码。target 可以是函数名（如 main、FUN_140001008）或十六进制地址（如 0x140001008）。',
    parameters: {
      target: { type: 'string', required: true, description: '函数名或十六进制地址' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.target || !args.target.trim()) throw new Error('target 不能为空')
      return { ok: true, result: await socketOp({ op: 'decompile', target: args.target }, 120000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_functions',
    description: '列出程序中的函数（名称/地址/大小/thunk）。filter 按名称子串过滤；sort=name 按名称排序；max 限制条数（默认 200）。',
    parameters: {
      filter: { type: 'string', description: '按名称包含的子串过滤（可选）' },
      sort: { type: 'string', enum: ['name'], description: '排序方式（可选，目前仅 name）' },
      max: { type: 'integer', description: '最多返回条数，默认 200' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      return { ok: true, result: await socketOp({ op: 'functions', ...(args.filter ? { filter: args.filter } : {}), ...(args.sort ? { sort: args.sort } : {}), ...(args.max ? { max: args.max } : {}) }) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_strings',
    description: '列出程序中的已定义字符串。filter 按内容包含过滤；minLength 最短长度（默认 4）；max 条数（默认 200）。',
    parameters: {
      filter: { type: 'string', description: '按字符串内容包含的子串过滤（可选）' },
      minLength: { type: 'integer', description: '最短长度，默认 4' },
      max: { type: 'integer', description: '最多返回条数，默认 200' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      return { ok: true, result: await socketOp({ op: 'strings', ...(args.filter ? { filter: args.filter } : {}), ...(args.minLength ? { minLength: args.minLength } : {}), ...(args.max ? { max: args.max } : {}) }) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_xrefs',
    description: '查询对某函数/地址的交叉引用。direction=to 查谁引用了它（默认），from 查它引用了谁；max 条数（默认 100）。',
    parameters: {
      target: { type: 'string', required: true, description: '函数名或十六进制地址' },
      direction: { type: 'string', enum: ['to', 'from'], description: 'to=被谁引用（默认），from=引用了谁' },
      max: { type: 'integer', description: '最多返回条数，默认 100' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.target || !args.target.trim()) throw new Error('target 不能为空')
      return { ok: true, result: await socketOp({ op: 'xrefs', target: args.target, direction: args.direction || 'to', ...(args.max ? { max: args.max } : {}) }) }
    },
  }))

  // ---- 批次 1：读侧补齐（对照 bethington/ghidra-mcp v7.0.0 的端点语义）----

  pushReg(defineTool({
    name: 'ghidra_segments',
    description: '列出内存段（块）：名称/起止地址/大小/权限 rwx/是否已初始化/类型/是否易失。比 ghidra_info 的 blocks 多了权限与类型，用于判断哪些区域可读可写可执行。',
    parameters: {},
    output: { schema: OUT, render },
    async execute() { return { ok: true, result: await socketOp({ op: 'segments' }) } },
  }))

  pushReg(defineTool({
    name: 'ghidra_imports',
    description: '列出导入符号（该程序从外部 DLL/SO 引用的函数与数据），含所属库名。filter 按名称子串过滤（大小写不敏感）；max 条数（默认 200）。',
    parameters: {
      filter: { type: 'string', description: '按符号名包含的子串过滤（可选，大小写不敏感）' },
      max: { type: 'integer', description: '最多返回条数，默认 200' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      return { ok: true, result: await socketOp({ op: 'imports', ...(args.filter ? { filter: args.filter } : {}), ...(args.max ? { max: args.max } : {}) }) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_exports',
    description: '列出导出符号（外部入口点，即 DLL/SO 对外提供的函数），含名称与地址。filter 按名称子串过滤；max 条数（默认 200）。',
    parameters: {
      filter: { type: 'string', description: '按名称包含的子串过滤（可选，大小写不敏感）' },
      max: { type: 'integer', description: '最多返回条数，默认 200' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      return { ok: true, result: await socketOp({ op: 'exports', ...(args.filter ? { filter: args.filter } : {}), ...(args.max ? { max: args.max } : {}) }) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_search_strings',
    description: '用正则搜索已定义字符串（比 ghidra_strings 的子串过滤强，适合找 URL/IP/路径/格式串）。pattern 用 Python re 语法；返回 matched（命中总数，可能是下界）、offset/limit 支持翻页。想列出全部可传 ".*"。',
    parameters: {
      pattern: { type: 'string', required: true, description: '正则表达式（Python re 语法），如 "https?://|\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+"' },
      minLength: { type: 'integer', description: '最短长度，默认 4' },
      caseSensitive: { type: 'boolean', description: '区分大小写，默认 false' },
      offset: { type: 'integer', description: '跳过前 N 个命中，默认 0' },
      limit: { type: 'integer', description: '最多返回条数，默认 100' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.pattern || !args.pattern.length) throw new Error('pattern 不能为空')
      return { ok: true, result: await socketOp({ op: 'searchStrings', pattern: args.pattern, ...(args.minLength ? { minLength: args.minLength } : {}), ...(args.caseSensitive ? { caseSensitive: true } : {}), ...(args.offset ? { offset: args.offset } : {}), ...(args.limit ? { limit: args.limit } : {}) }, 120000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_search_functions',
    description: '用正则搜索函数名（比 ghidra_functions 的 filter 强，如 "^FUN_"、"Crypt|Aes"）。pattern 用 Python re 语法；返回 matched/offset/limit 支持翻页。',
    parameters: {
      pattern: { type: 'string', required: true, description: '正则表达式（Python re 语法）' },
      caseSensitive: { type: 'boolean', description: '区分大小写，默认 false' },
      offset: { type: 'integer', description: '跳过前 N 个命中，默认 0' },
      limit: { type: 'integer', description: '最多返回条数，默认 100' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.pattern || !args.pattern.length) throw new Error('pattern 不能为空')
      return { ok: true, result: await socketOp({ op: 'searchFunctions', pattern: args.pattern, ...(args.caseSensitive ? { caseSensitive: true } : {}), ...(args.offset ? { offset: args.offset } : {}), ...(args.limit ? { limit: args.limit } : {}) }, 120000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_calls',
    description: '查一个函数的调用关系：callers（谁调用它）/ callees（它调用了谁）/ both（默认）。callers 若函数关系为空会自动回退扫描指向入口的 call 引用。max 每侧条数（默认 100）。',
    parameters: {
      target: { type: 'string', required: true, description: '函数名或十六进制地址' },
      direction: { type: 'string', enum: ['callers', 'callees', 'both'], description: '默认 both' },
      max: { type: 'integer', description: '每侧最多返回条数，默认 100' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.target || !args.target.trim()) throw new Error('target 不能为空')
      return { ok: true, result: await socketOp({ op: 'calls', target: args.target, direction: args.direction || 'both', ...(args.max ? { max: args.max } : {}) }, 120000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_call_graph',
    description: '从某函数出发做有界调用图遍历（BFS），返回 nodes（含 depth）+ edges。direction=callees（默认，往下看它调用了什么）或 callers（往上看谁调用了它）；depth 层数（默认 2）；maxNodes 节点上限（默认 150，超出置 truncated）。',
    parameters: {
      target: { type: 'string', required: true, description: '函数名或十六进制地址' },
      direction: { type: 'string', enum: ['callers', 'callees'], description: '默认 callees' },
      depth: { type: 'integer', description: '遍历层数，默认 2' },
      maxNodes: { type: 'integer', description: '节点上限，默认 150' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.target || !args.target.trim()) throw new Error('target 不能为空')
      return { ok: true, result: await socketOp({ op: 'callGraph', target: args.target, direction: args.direction || 'callees', ...(args.depth ? { depth: args.depth } : {}), ...(args.maxNodes ? { maxNodes: args.maxNodes } : {}) }, 120000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_read_memory',
    description: '按地址读原始内存并返回 16 字节一行的 hex + ASCII 转储（读字节，不做反汇编）。length 默认 64，上限 4096；未初始化/越界区域会逐字节回退并在 note 里说明。address 也接受符号名。',
    parameters: {
      address: { type: 'string', required: true, description: '十六进制地址（如 0x140003000）或符号名' },
      length: { type: 'integer', description: '读取字节数，默认 64，上限 4096' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.address || !args.address.trim()) throw new Error('address 不能为空')
      return { ok: true, result: await socketOp({ op: 'readMemory', address: args.address, ...(args.length ? { length: args.length } : {}) }) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_disassemble',
    description: '反汇编：target 命中函数时反汇编整个函数体（scope 标明函数名），否则从该地址起反汇编 count 条。count 默认 500、上限 2000。返回每条指令的地址与文本。',
    parameters: {
      target: { type: 'string', required: true, description: '函数名或十六进制地址' },
      count: { type: 'integer', description: '非函数地址时最多反汇编条数，默认 500，上限 2000' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.target || !args.target.trim()) throw new Error('target 不能为空')
      return { ok: true, result: await socketOp({ op: 'disassemble', target: args.target, ...(args.count ? { count: args.count } : {}) }, 120000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_variables',
    description: '列出一个函数的参数与局部变量：名称/数据类型/存储位置（寄存器或栈偏移）/长度。看清函数签名与栈布局用。',
    parameters: {
      target: { type: 'string', required: true, description: '函数名或十六进制地址' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.target || !args.target.trim()) throw new Error('target 不能为空')
      return { ok: true, result: await socketOp({ op: 'variables', target: args.target }, 60000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_pcode',
    description: '导出函数的 P-code（Ghidra 中间表示）。mode=listing（默认，逐条指令的原始 p-code）或 high（反编译器的优化后 p-code，更接近语义但可能失败）。limit 为最多返回的项数（默认 60，上限 500）。输出噪声大，只在需要精确追踪数据流时用。',
    parameters: {
      target: { type: 'string', required: true, description: '函数名或十六进制地址' },
      mode: { type: 'string', enum: ['listing', 'high'], description: 'listing=指令级（默认），high=反编译器级' },
      limit: { type: 'integer', description: '最多返回项数，默认 60，上限 500' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.target || !args.target.trim()) throw new Error('target 不能为空')
      return { ok: true, result: await socketOp({ op: 'pcode', target: args.target, mode: args.mode || 'listing', ...(args.limit ? { limit: args.limit } : {}) }, 180000) }
    },
  }))

  // ---- 批次 2：写侧（会改动 Ghidra 数据库，改完需 ghidra_save 落盘）----

  pushReg(defineTool({
    name: 'ghidra_get_comments',
    description: '读注释：给出 address（单个）或 addresses（数组，批量），返回每个地址上的 plate/pre/eol/post/repeatable 各类型注释（只返回非空的）。onlyWithComments=true 时跳过没有任何注释的地址。',
    parameters: {
      address: { type: 'string', description: '单个地址或符号名' },
      addresses: { type: 'array', items: { type: 'string' }, description: '批量地址/符号名数组' },
      onlyWithComments: { type: 'boolean', description: '只返回确实带注释的地址' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.address && !(args.addresses && args.addresses.length)) throw new Error('需要 address 或 addresses')
      return { ok: true, result: await socketOp({ op: 'getComments', address: args.address, addresses: args.addresses, ...(args.onlyWithComments ? { onlyWithComments: true } : {}) }) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_set_comment',
    description: '写注释（会改数据库）。type 可为 plate（函数头大注释，默认）/pre/eol/post/repeatable；comment 为空字符串则清除该类型注释。也可用 comments 对象一次写多种类型（如 {plate:"...", eol:"..."}），或用 decompiler/pre 写反编译视图注释。addresses 数组可把同一批注释批量写到多个地址。改完记得 ghidra_save。',
    parameters: {
      address: { type: 'string', description: '单个地址或符号名' },
      addresses: { type: 'array', items: { type: 'string' }, description: '批量地址/符号名数组' },
      type: { type: 'string', enum: ['plate', 'pre', 'eol', 'post', 'repeatable'], description: '注释类型，默认 plate' },
      comment: { type: 'string', description: '注释内容；空字符串 = 清除该类型注释' },
      comments: { type: 'json', description: '一次写多种类型，如 {"plate":"函数说明","eol":"这里返回错误码"}' },
      plate: { type: 'string', description: '等价于 type=plate 的简写' },
      pre: { type: 'string', description: '等价于 type=pre 的简写（反编译视图里显示在语句前）' },
      eol: { type: 'string', description: '等价于 type=eol 的简写（行尾注释）' },
      post: { type: 'string', description: '等价于 type=post 的简写' },
      repeatable: { type: 'string', description: '等价于 type=repeatable 的简写' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const shorthands = ['plate', 'pre', 'eol', 'post', 'repeatable']
      const hasOne = args.comment !== undefined || (args.comments && Object.keys(args.comments).length) || shorthands.some((k) => args[k] !== undefined)
      if (!args.address && !(args.addresses && args.addresses.length)) throw new Error('需要 address 或 addresses')
      if (!hasOne) throw new Error('需要 comment+type、comments{} 或 plate/pre/eol/post/repeatable 之一')
      const payload = { op: 'setComment', address: args.address, addresses: args.addresses }
      if (args.type) payload.type = args.type
      if (args.comment !== undefined) payload.comment = args.comment
      if (args.comments) payload.comments = args.comments
      for (const k of shorthands) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_rename',
    description: '重命名符号（会改数据库）。kind=auto（默认）：target 落在函数入口就重命名函数，否则重命名该地址上的符号、没有符号就新建标签。target 可以是十六进制地址，也可以是现有函数名/符号名。变量改名请用 ghidra_set_variables。改完记得 ghidra_save。',
    parameters: {
      target: { type: 'string', required: true, description: '地址或现有的函数名/符号名' },
      newName: { type: 'string', required: true, description: '新名称（函数名需是合法标识符）' },
      kind: { type: 'string', enum: ['auto', 'function', 'symbol', 'label'], description: '默认 auto' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.target || !args.target.trim()) throw new Error('target 不能为空')
      if (!args.newName || !args.newName.trim()) throw new Error('newName 不能为空')
      return { ok: true, result: await socketOp({ op: 'rename', target: args.target, newName: args.newName, kind: args.kind || 'auto' }) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_label',
    description: '标签操作（create/delete 会改数据库）。action=list（默认，按 target 列出：target 是函数入口则列出函数体内所有符号，否则列出该地址上的符号；不给 target 则列出全部符号，可用 max 限制）、create（在 address 建 name 或 names[] 标签）、delete（按 address 删除符号，可给 name 只删指定那个）。改完记得 ghidra_save。',
    parameters: {
      action: { type: 'string', enum: ['list', 'create', 'delete'], description: '默认 list' },
      address: { type: 'string', description: 'list/create/delete 的地址或符号名' },
      target: { type: 'string', description: 'action=list 时的查询目标（函数入口地址则列出函数体内全部符号）' },
      name: { type: 'string', description: 'create 时的标签名 / delete 时要删除的符号名' },
      names: { type: 'array', items: { type: 'string' }, description: 'create 时一次建多个标签' },
      max: { type: 'integer', description: 'list 最多返回条数，默认 200' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const action = args.action || 'list'
      if (action === 'create') {
        if (!args.address && !args.target) throw new Error('create 需要 address')
        if (!args.name && !(args.names && args.names.length)) throw new Error('create 需要 name 或 names[]')
      } else if (action === 'delete') {
        if (!args.address && !args.target) throw new Error('delete 需要 address')
      }
      const payload = { op: 'labels', action }
      for (const k of ['address', 'target', 'name', 'names', 'max']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 120000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_set_prototype',
    description: '设置函数原型/调用约定/无返回标记（会改数据库）。prototype 用 C 语法，如 "int __stdcall foo(char *buf, int len)"（名字部分不生效，只取返回类型与参数类型）；callingConvention 如 "__stdcall"；noReturn=true/false 设置该函数不返回。三者可任选。改完记得 ghidra_save。',
    parameters: {
      target: { type: 'string', required: true, description: '函数名或地址' },
      prototype: { type: 'string', description: 'C 风格原型，如 "int foo(char *buf, int len)"' },
      callingConvention: { type: 'string', description: '调用约定名，如 __stdcall / __cdecl / __fastcall' },
      noReturn: { type: 'boolean', description: '是否标记为不返回（ExitProcess 这类）' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.target || !args.target.trim()) throw new Error('target 不能为空')
      if (!args.prototype && !args.callingConvention && args.noReturn === undefined) throw new Error('至少要给 prototype / callingConvention / noReturn 之一')
      const payload = { op: 'setPrototype', target: args.target }
      if (args.prototype) payload.prototype = args.prototype
      if (args.callingConvention) payload.callingConvention = args.callingConvention
      if (args.noReturn !== undefined) payload.noReturn = args.noReturn
      return { ok: true, result: await socketOp(payload, 120000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_set_variables',
    description: '批量设置函数变量的类型与名称（会改数据库，单事务）。variables 形如 [{"name":"local_8","newName":"count","newType":"int"}]（name=现有名，newName/newType 至少给一个）。优先走反编译器高层符号（能覆盖只在反编译结果里存在的栈变量），失败退回数据库层。返回 applied/failed 两组，逐个变量报结果。改完记得 ghidra_save。',
    parameters: {
      target: { type: 'string', required: true, description: '函数名或地址' },
      variables: { type: 'array', items: { type: 'json' }, required: true, description: '[{name, newName?, newType?}]，如 [{"name":"local_8","newName":"count","newType":"int"}]' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.target || !args.target.trim()) throw new Error('target 不能为空')
      if (!args.variables || !args.variables.length) throw new Error('variables 不能为空')
      return { ok: true, result: await socketOp({ op: 'setVariables', target: args.target, variables: args.variables }, 180000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_create_function',
    description: '在地址上创建函数（会改数据库）。默认先反汇编该地址再创建（disassembleFirst=false 可跳过）。name 可选，创建后重命名。用于处理 Ghidra 没自动识别出来的函数（如被间接调用的代码）。改完记得 ghidra_save。',
    parameters: {
      address: { type: 'string', required: true, description: '函数入口地址或符号名' },
      name: { type: 'string', description: '创建后重命名为该名称' },
      disassembleFirst: { type: 'boolean', description: '先反汇编该地址，默认 true' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.address || !args.address.trim()) throw new Error('address 不能为空')
      const payload = { op: 'createFunction', address: args.address }
      if (args.name) payload.name = args.name
      if (args.disassembleFirst !== undefined) payload.disassembleFirst = args.disassembleFirst
      return { ok: true, result: await socketOp(payload, 120000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_delete_function',
    description: '删除地址上的函数定义（会改数据库，不可逆）。用于误报的函数。改完记得 ghidra_save。',
    parameters: {
      address: { type: 'string', required: true, description: '函数入口地址或名称' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.address || !args.address.trim()) throw new Error('address 不能为空')
      return { ok: true, result: await socketOp({ op: 'deleteFunction', address: args.address }, 60000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_save',
    description: '把当前程序的改动真正落盘到 Ghidra 项目。headless 在程序外层持有事务，进程内 df.save() 拿不到锁，所以本工具走 flush 路径：优雅停止服务器（headless 这时才写回项目）→ 重新打开同一程序，返回新的 port/pid。耗时 40 秒以上。写侧工具改完请调用它；不调用的话改动只在内存里，ghidra_close 或切换目标时才会顺带落盘。',
    parameters: {},
    output: { schema: OUT, render },
    async execute() {
      const before = await socketOp({ op: 'save' }, 60000)
      if (before.saved || !before.changed) return { ok: true, result: before }
      const binary = state.binaryPath
      if (!binary) throw new Error('无法 flush：不知道当前二进制路径，请重新 ghidra_open')
      const stopInfo = await stopServer(60000)
      const res = await openFlow(binary, () => {})
      return { ok: true, result: { ...before, saved: true, flushed: true, port: res.port, pid: res.pid, stopMs: stopInfo.ms, stopGraceful: stopInfo.graceful } }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_tags',
    description: '函数标签（Ghidra FunctionTag）操作。action=list（列出全部标签定义与使用次数）、create（name + comment）、delete（name，会从所有函数上摘掉）、attach/detach（target + tag/tags[]，attach 时标签不存在会自动创建）、get（target 的标签）、search（tag，列出带该标签的函数）。attach/detach/create/delete 会改数据库，改完记得 ghidra_save。',
    parameters: {
      action: { type: 'string', required: true, enum: ['list', 'create', 'delete', 'attach', 'detach', 'get', 'search'], description: '操作类型' },
      target: { type: 'string', description: 'attach/detach/get 的函数名或地址' },
      function: { type: 'string', description: '同 target' },
      tag: { type: 'string', description: 'create/delete/search/attach/detach 的标签名' },
      tags: { type: 'array', items: { type: 'string' }, description: 'attach/detach 一次多个标签' },
      name: { type: 'string', description: 'create/delete 的标签名' },
      comment: { type: 'string', description: 'create 时的标签注释' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.action) throw new Error('action 不能为空')
      const payload = { op: 'tags', action: args.action }
      for (const k of ['target', 'function', 'tag', 'tags', 'name', 'comment']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 120000) }
    },
  }))

  // ---------------------------------------------------------- 批次 3：分析自动化
  pushReg(defineTool({
    name: 'ghidra_run_script_inline',
    description: '在 Ghidra 的 Python 上下文里直接执行一段 Python 源码（桥接脚本跑在 CPython 3.13 + JPype 上，不是 Jython）。命名空间里预置 currentProgram / program / monitor / println / print / getScriptArgs()；把结果赋给变量 result 会原样回传；Python 与 Java 两路 stdout 都会被捕获返回。写操作要 write=true（整段代码包在一个事务里）。脚本报错不会打断桥接服务器，错误与 traceback 会放在返回里。★这一件工具等于拿到完整的 Ghidra API，其余工具都只是它的便捷封装。',
    parameters: {
      code: { type: 'string', required: true, description: '要执行的 Python 源码' },
      write: { type: 'boolean', description: 'true = 整段包在写事务里（默认 false，只读）' },
      args: { type: 'array', items: { type: 'string' }, description: 'scriptArgs / getScriptArgs() 返回的内容' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.code || !String(args.code).trim()) throw new Error('code 不能为空')
      const payload = { op: 'runScriptInline', code: args.code, write: !!args.write }
      if (args.args) payload.args = args.args
      return { ok: true, result: await socketOp(payload, 600000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_run_script_file',
    description: '执行磁盘上的 Python 脚本文件（上下文与 ghidra_run_script_inline 相同，支持 .py/.pyw/.txt）。参数用 args 传，脚本里通过 getScriptArgs() 取。write=true 时整段包在事务里。Java/Groovy 脚本不支持——本桥是进程内执行，不走 headless 的 script provider。',
    parameters: {
      scriptPath: { type: 'string', required: true, description: '脚本文件绝对路径' },
      args: { type: 'array', items: { type: 'string' }, description: '传给脚本的参数' },
      write: { type: 'boolean', description: 'true = 整段包在写事务里（默认 false）' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.scriptPath || !args.scriptPath.trim()) throw new Error('scriptPath 不能为空')
      const payload = { op: 'runScript', scriptPath: args.scriptPath, write: !!args.write }
      if (args.args) payload.args = args.args
      return { ok: true, result: await socketOp(payload, 600000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_list_analyzers',
    description: '列出此程序注册的全部分析器（即 Ghidra「Analysis Options」里的条目）：名称、开关状态、类型、子选项数量、描述。filter 按名称子串过滤；onlyEnabled 只看开着的。',
    parameters: {
      filter: { type: 'string', description: '名称子串过滤（不区分大小写）' },
      onlyEnabled: { type: 'boolean', description: '只看已启用的分析器' },
      max: { type: 'integer', description: '最多返回条数，默认 200' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'analyzers' }
      for (const k of ['filter', 'onlyEnabled', 'max']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 60000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_configure_analyzer',
    description: '改分析器开关或分析选项（会改数据库，改完记得 ghidra_save）。name 用 ghidra_list_analyzers 里的完整选项名（分析器名本身，或 "分析器.子选项"）。enabled 改开关；value 改值，按选项真实类型自动用 setBoolean/setInt/setLong/setDouble/setString 写入（数字与 true/false 都按字符串传）。',
    parameters: {
      name: { type: 'string', required: true, description: '完整选项名，如 "ASCII Strings" 或 "ASCII Strings.Minimum String Length"' },
      enabled: { type: 'boolean', description: '改分析器主开关' },
      value: { type: 'string', description: '改选项值（按选项真实类型写）' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.name || !args.name.trim()) throw new Error('name 不能为空')
      const payload = { op: 'analyzerConfig', name: args.name }
      if (args.enabled !== undefined) payload.enabled = args.enabled
      if (args.value !== undefined) payload.value = args.value
      return { ok: true, result: await socketOp(payload, 120000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_run_analysis',
    description: '跑一遍自动分析（AutoAnalysisManager.startAnalysis）。force=true 会把已分析过的内容也重跑（慢很多）。返回分析各任务的耗时统计。大程序可能要几分钟，期间桥接服务器被占住。',
    parameters: {
      force: { type: 'boolean', description: 'true = 强制重跑全部分析器（默认 false，只补没分析过的）' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      return { ok: true, result: await socketOp({ op: 'runAnalysis', force: !!args.force }, 900000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_reanalyze',
    description: '重分析一块范围：target 给函数名/地址（命中函数就取整个函数体，否则只取该地址），或 all=true 重分析整个已初始化内存（很慢）。对范围调 reAnalyzeAll 后再跑一次分析。',
    parameters: {
      target: { type: 'string', description: '函数名或地址' },
      all: { type: 'boolean', description: 'true = 整个已初始化内存（与 target 互斥，优先 all）' },
      force: { type: 'boolean', description: '强制重跑（默认 false）' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'reanalyze' }
      for (const k of ['target', 'all', 'force']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 900000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_search_byte_patterns',
    description: '按字节模式搜索内存。pattern 支持整字节与半字节通配、以及用 | 分隔的多个模式：如 "48 8B ?? 4? C3"（?? 任意字节，4? 高半字节固定）、"48 8B ?? ?? | 48 8D ?? ??"。默认扫全部已初始化块，executable=true 只扫可执行块，start/end 限定范围（默认全程序）。limit 默认 100（上限 1000）。返回命中地址与所在块。',
    parameters: {
      pattern: { type: 'string', required: true, description: '字节模式，多个用 | 分隔' },
      start: { type: 'string', description: '起始地址（含）' },
      end: { type: 'string', description: '结束地址（含）' },
      executable: { type: 'boolean', description: '只搜可执行内存块' },
      limit: { type: 'integer', description: '最多命中数，默认 100，上限 1000' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.pattern || !args.pattern.trim()) throw new Error('pattern 不能为空')
      const payload = { op: 'searchBytes', pattern: args.pattern }
      for (const k of ['start', 'end', 'executable', 'limit']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 300000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_find_code_gaps',
    description: '找「代码空洞」：已初始化内存里没有任何指令/数据定义的区间（用 Listing.getUndefinedRanges 实现）。默认只看可执行块，includeData=true 连数据块一起看。minSize 过滤小碎片（默认 1），limit 默认 200。',
    parameters: {
      minSize: { type: 'integer', description: '最小空洞字节数，默认 1' },
      limit: { type: 'integer', description: '最多返回条数，默认 200，上限 2000' },
      includeData: { type: 'boolean', description: 'true = 数据块也算（默认只看可执行块）' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'codeGaps' }
      for (const k of ['minSize', 'limit', 'includeData']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 180000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_find_dead_code',
    description: '找死代码候选：没有任何调用者、又不是外部函数/thunk、也不在程序入口点集合里的函数。间接调用（函数指针表、虚表）在这套判据下看不见，所以这是候选而非定论。includeThunks/includeStubs 可把它们也算进来。',
    parameters: {
      limit: { type: 'integer', description: '最多返回条数，默认 200，上限 2000' },
      includeThunks: { type: 'boolean', description: '把 thunk 也算作候选' },
      includeStubs: { type: 'boolean', description: '把 stub 也算作候选' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'deadCode' }
      for (const k of ['limit', 'includeThunks', 'includeStubs']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 180000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_function_context',
    description: '一个函数的全貌（复合分析）：签名/参数/局部变量、callers/callees、指向入口的交叉引用、函数体内指向字符串的引用、指令数与 codeMd5/mnemonicMd5、反编译器给出的基本块数/pcode 操作数/分支数/圈复杂度，以及伪代码（includeCode=false 可不取）。比逐个调 decompile/variables/calls 更省往返，适合"这个函数干什么"这类问题。',
    parameters: {
      target: { type: 'string', required: true, description: '函数名或地址（命中函数入口）' },
      max: { type: 'integer', description: '每类列表最多返回条数，默认 50' },
      includeCode: { type: 'boolean', description: '是否附伪代码，默认 true（截断到 6000 字符）' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'functionContext' }
      for (const k of ['target', 'max', 'includeCode']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 300000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_search_instructions',
    description: '按指令搜索：mnemonic 是助记符子串（如 "call"），operand 是整条指令文本的子串（如 "rsp"），pattern 是对整条指令文本的正则（如 "^MOV .*\\[rip"）。三者至少要给一个，同时给就是 AND。给 target 可限定在某个函数体内。返回 {list:[{address,mnemonic,text,function}],total,scope,truncated}。',
    parameters: {
      mnemonic: { type: 'string', description: '助记符子串，如 call / jmp / xor' },
      operand: { type: 'string', description: '整条指令文本的子串，如 rsp / rip' },
      pattern: { type: 'string', description: '整条指令文本的正则' },
      caseSensitive: { type: 'boolean', description: '正则是否区分大小写，默认 false' },
      target: { type: 'string', description: '限定函数（名或地址），不给则搜全程序' },
      limit: { type: 'integer', description: '最多返回条数，默认 200，上限 2000' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'searchInstructions' }
      for (const k of ['mnemonic', 'operand', 'pattern', 'caseSensitive', 'target', 'limit']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 300000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_hash',
    description: '算哈希。scope=function（或给 target）：函数体的原始字节哈希 bytesHash + 整条指令文本哈希 codeHash + 只取助记符序列的结构哈希 mnemonicHash（改一个立即数，mnemonicHash 不变而 codeHash 变）。scope=program（或省略）：逐内存块哈希 + imageHash，并回传 Ghidra 记的 executableMD5/executableSHA256/executableFormat/executablePath。algorithm 支持 md5/sha1/sha256，默认 md5。',
    parameters: {
      target: { type: 'string', description: '函数名或地址（不给就是程序级）' },
      scope: { type: 'string', description: 'function 或 program' },
      algorithm: { type: 'string', description: 'md5 / sha1 / sha256，默认 md5' },
      maxBytes: { type: 'integer', description: '程序级最多读多少字节，默认 64MB' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'hash' }
      for (const k of ['target', 'scope', 'algorithm', 'maxBytes']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 300000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_compare_functions',
    description: '比较同一程序里的两个函数：各自大小/指令数/签名/参数表，指令条数差、整条指令文本相似度 textSimilarity、助记符相似度 mnemonicSimilarity（difflib，0~1）、助记符序列是否完全相同、参数与被调用函数的差集，以及逐条对齐后前 N 处差异。用于判断两个函数是不是同一段代码编译出来的、或改了哪里。只有一次只开一个程序，所以跨程序比较请各自 ghidra_hash 后对比。',
    parameters: {
      a: { type: 'string', required: true, description: '第一个函数（名或地址）' },
      b: { type: 'string', required: true, description: '第二个函数（名或地址）' },
      max: { type: 'integer', description: '最多列几处差异，默认 25' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      if (!args.a || !args.b) throw new Error('需要 a 与 b 两个函数')
      return { ok: true, result: await socketOp({ op: 'compareFunctions', a: args.a, b: args.b, max: args.max }, 300000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_data_flow',
    description: '用反编译器的高层 p-code 追一个变量的定义/使用链（Varnode.getDef / getDescendants 做 BFS）。direction=forward（这个值后来用在哪）/backward（这个值从哪来）/both，depth 默认 4（上限 12），max 默认 200。list=true 且不给 variable 时列出该函数全部高层变量（参数与局部）。返回每一步的 seqnum/深度/mnemonic/来源，以及各实例的定义地址。',
    parameters: {
      target: { type: 'string', required: true, description: '函数名或地址' },
      variable: { type: 'string', description: '变量名（不给则自动挑第一个有实例的高层变量）' },
      direction: { type: 'string', description: 'forward / backward / both，默认 both' },
      depth: { type: 'integer', description: 'BFS 深度，默认 4，上限 12' },
      max: { type: 'integer', description: '最多返回多少个 pcode op，默认 200，上限 2000' },
      list: { type: 'boolean', description: 'true 且不给 variable = 只列出该函数的全部高层变量' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'dataFlow' }
      for (const k of ['target', 'variable', 'direction', 'depth', 'max', 'list']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 300000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_detect_crypto_constants',
    description: '按已知常量签名找加密实现：AES S-box（整表/前 16 字节/逆表）、CRC32 与 CRC32C 表、MD5/SHA-1 初始向量与 T 表、SHA-256/SHA-512 轮常量、Keccak 轮常量、ChaCha/Salsa 的 "expand 32-byte k"、标准与 URL-safe Base64 字母表、Blowfish P-array、Curve25519/secp256k1/P-256 素域模数。全部签名由脚本在运行时算出（math/哈希表不是手抄的），命中即"这里有一张已知的表"。注意：表的出现不等于"这段代码在加密数据"，也可能来自静态链接的库。filter 可按名字/算法过滤，blockFilter 限定内存块。',
    parameters: {
      filter: { type: 'string', description: '按签名名/算法/说明过滤，如 "aes"、"sha-256"、"crc"' },
      blockFilter: { type: 'string', description: '只看名字含该子串的内存块，如 ".rdata"' },
      limit: { type: 'integer', description: '每条签名最多返回几处命中，默认 8，上限 64' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'detectCrypto' }
      for (const k of ['filter', 'blockFilter', 'limit']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 300000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_detect_malware_behaviors',
    description: '按"API 名 × 行为分类"扫导入表/函数名/已定义字符串：进程注入、执行、持久化、凭据访问、C2 网络、反调试规避、加密、收集外传、文件注册表操作、提权，共 10 类。每条命中都标明来源（import/function/string）、地址、所在函数与原文，所以这是**行为线索清单而不是判决**——同一个 VirtualAllocEx 在调试器、注入器和游戏外挂里都会出现。用 categories 只看某几类（逗号分隔），用 limit 限制每类条数。',
    parameters: {
      categories: {
        oneOf: [
          { type: 'string', description: '逗号分隔的分类名，如 "process-injection,c2-network"' },
          { type: 'array', items: { type: 'string' }, description: '分类名数组，如 ["process-injection","c2-network"]' },
        ],
        description: '只看某几类：逗号分隔字符串或字符串数组；不给则全查',
      },
      limit: { type: 'integer', description: '每类最多返回几条 API，默认 200，上限 1000' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'malwareBehaviors' }
      for (const k of ['categories', 'limit']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, 300000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_extract_iocs_with_context',
    description: '从已定义字符串（可选再加原始内存）抽 IOC：IPv4/OID/IPv6/URL/邮箱/域名/注册表键/Windows 路径/UNC 路径/Unix 路径/互斥体/比特币与以太坊地址/MD5/SHA-1/SHA-256/GUID，共 17 类。每条给出来源地址、所在函数与原文，同值只留首条并累加 count。点分十进制按 ITU-T 首弧规则区分为 ipv4 与 oid（证书类样本里 OID 表项极多，不区分会淹没 ipv4 通道）。includeRawMemory=true 会扫未定义数据（更全但慢、噪音多），扫描量由 maxBytes 限制。',
    parameters: {
      types: {
        oneOf: [
          { type: 'string', description: '逗号分隔的类型，如 "ipv4,domain,url"' },
          { type: 'array', items: { type: 'string' }, description: '类型名数组，如 ["ipv4","domain","url"]' },
        ],
        description: '要抽取的类型：逗号分隔字符串或字符串数组；不给则全查',
      },
      minLength: { type: 'integer', description: '字符串最短长度，默认 4' },
      max: { type: 'integer', description: '最多返回几条，默认 500，上限 5000' },
      includeRawMemory: { type: 'boolean', description: '是否同时扫原始内存里的可打印 ASCII 串' },
      maxBytes: { type: 'integer', description: 'includeRawMemory 时的扫描上限，默认 4MB' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'extractIocs' }
      for (const k of ['types', 'minLength', 'max', 'includeRawMemory', 'maxBytes']) if (args[k] !== undefined) payload[k] = args[k]
      return { ok: true, result: await socketOp(payload, args.includeRawMemory ? 600000 : 300000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_find_anti_analysis_techniques',
    description: '反分析线索：反调试 API（IsDebuggerPresent/NtQueryInformationProcess/OutputDebugString…）、反虚拟机与沙箱字符串（VMware/VirtualBox/VBOX 驱动名/QEMU/Xen/Sandboxie/Cuckoo/Wine…）、调试器与分析工具字符串（OllyDbg/x64dbg/IDA/WinDbg/Procmon/dbghelp/dnSpy…），以及字节级扫描出的 RDTSC(0F 31)/CPUID(0F A2)/INT3(CC) 数量。risk 只是把线索数量压成一个便于排序的标签，请回读地址处的上下文再下结论。',
    parameters: {
      max: { type: 'integer', description: '每类最多返回几条证据，默认 100，上限 500' },
    },
    output: { schema: OUT, render },
    async execute(args) {
      const payload = { op: 'antiAnalysis' }
      if (args.max !== undefined) payload.max = args.max
      return { ok: true, result: await socketOp(payload, 300000) }
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_close',
    description: '关闭 Ghidra 桥接服务器并释放项目锁。走优雅关闭：先让 headless 把改动落盘再退出，宽限期内没退出才强杀。切换分析目标并不需要先 close——直接 ghidra_open 另一个文件即可（内部同样会优雅停掉旧服务器）。',
    parameters: {},
    output: { schema: OUT, render },
    async execute() {
      const was = state.port ? { port: state.port, program: state.program } : null
      const stopInfo = await stopServer(60000)
      return { ok: true, result: { closed: !!was, was: was, graceful: stopInfo.graceful, stopMs: stopInfo.ms } }
    },
  }))

  // ---- 上游 GhidraMCP REST 桥（bethington/ghidra-mcp 7.0.0-rc.1；lib/mcp-tools.js 生成的 168 个工具 + 3 个 lifecycle） ----
  // 承载方式（config.mcpMode）：
  //  · unified（缺省）：REST 服务器跑在 PyGhidra 桥的**同一个 JVM** 内（DecompileBridge.py 的 mcpServe op，
  //    经 HeadlessProgramProvider.setCurrentProgram 绑定到桥当前程序）——单进程、同一程序，两边状态不分叉。
  //  · standalone：另起 ghidraMCPHeadless.bat（第二个 Ghidra 进程，独立程序，与桥无关）。
  const mcpBat = gh ? join(gh.home, 'support', 'ghidraMCPHeadless.bat') : null

  pushReg(defineTool({
    name: 'ghidra_mcp_start',
    description: '启动上游 GhidraMCP 服务器（bethington/ghidra-mcp，226 个 REST 端点）。默认 unified 模式：在 PyGhidra 桥的同一个 JVM 内启动 REST 服务器并把它绑定到桥当前打开的程序——于是 47 个原生工具与 168 个 ghidra_mcp_* 工具作用于同一个程序、同一个进程（先 ghidra_open，再 ghidra_mcp_start）。mcpMode=standalone 时回退为独立启动 ghidraMCPHeadless.bat（第二个 Ghidra 进程，可用 file 参数在启动时导入并分析一个二进制）。',
    parameters: {
      file: { type: 'string', description: 'standalone 模式：启动时自动加载的二进制绝对路径（可选；unified 模式下忽略，程序来自 ghidra_open）' },
      project: { type: 'string', description: 'Ghidra 项目路径（可选；缺省用服务器默认位置）' },
    },
    output: { schema: MCP_OUT, render: renderMcp },
    async execute(args) {
      const mode = config.mcpMode || 'unified'
      const wantsFile = !!(args && args.file)
      if (mode === 'unified' && !wantsFile) {
        if (!state.port) {
          return { ok: false, error: 'unified 模式需要 PyGhidra 桥在运行：先调用 ghidra_open 打开一个二进制（或用 mcpMode=standalone 独立启动）' }
        }
        try {
          const res = await socketOp({ op: 'mcpServe', port: config.mcpPort, bind: '127.0.0.1' },
            (config.mcpStartupTimeoutSec || 180) * 1000)
          // 起来了 → 168 个 ghidra_mcp_* 此刻才注册给模型
          await syncAvailability()
          return {
            ok: !!(res && res.ok),
            port: res ? res.port : config.mcpPort,
            mode: 'unified',
            result: res,
            note: 'unified：REST 服务器跑在 PyGhidra 桥的同一 JVM 内，作用于同一程序'
              + (res && res.reused ? '（复用已在跑的实例）' : ''),
          }
        } catch (e) {
          return { ok: false, mode: 'unified', error: 'unified 启动失败: ' + String(e?.message || e) }
        }
      }
      const r = await mcpStart({
        bat: mcpBat,
        port: config.mcpPort,
        file: args ? args.file : undefined,
        project: args ? args.project : undefined,
        timeoutMs: (config.mcpStartupTimeoutSec || 180) * 1000,
      })
      if (r.ok && r.pid) state.mcpPid = r.pid
      r.mode = 'standalone'
      await syncAvailability()
      return r
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_mcp_stop',
    description: '停止上游 GhidraMCP 服务器。unified 模式：停掉桥 JVM 内的 REST 服务器（桥本身继续运行）；standalone 模式：先 /save_all_programs + /exit_ghidra（优雅，保存已加载程序），没退才按端口/PID 强杀。',
    parameters: {},
    output: { schema: MCP_OUT, render: renderMcp },
    async execute() {
      const mode = config.mcpMode || 'unified'
      if (mode === 'unified' && state.port) {
        try {
          const res = await socketOp({ op: 'mcpStop' }, 30000)
          await syncAvailability()
          return { ok: !!(res && res.ok), mode: 'unified', result: res }
        } catch (e) {
          return { ok: false, mode: 'unified', error: String(e?.message || e) }
        }
      }
      const r = await mcpStop(config.mcpPort, state.mcpPid || 0)
      state.mcpPid = 0
      r.mode = 'standalone'
      // 停了 → 168 个生成工具立刻从模型视野里撤掉
      await syncAvailability()
      return r
    },
  }))

  pushReg(defineTool({
    name: 'ghidra_mcp_status',
    description: '查看上游 GhidraMCP 服务器状态：/health（status/version/program_loaded/program_name）+ 承载方式（unified=跑在 PyGhidra 桥 JVM 内 / standalone=独立进程）+ 本插件配置（端口、bat 路径、日志路径）。',
    parameters: {},
    output: { schema: MCP_OUT, render: renderMcp },
    async execute() {
      // 先自愈门控：外部启动/外部杀掉的服务器，靠这一步重新对齐（agent 查状态时顺手纠正）
      await syncAvailability()
      const h = await mcpHealth(config.mcpPort, 5000)
      const mode = config.mcpMode || 'unified'
      let inProcess = null
      if (mode === 'unified' && state.port) {
        try { inProcess = await socketOp({ op: 'mcpState' }, 10000) } catch { /* 桥不可达时忽略 */ }
      }
      const out = {
        ok: h.ok,
        result: {
          running: h.ok,
          health: h.ok ? h.body : null,
          mode,
          inProcess,
          unified: !!(inProcess && inProcess.running),
          sharedProgram: mode === 'unified' && h.ok ? (state.program || null) : null,
          port: config.mcpPort,
          bat: mcpBat,
          log: MCP_LOG_FILE,
          defaultPort: MCP_DEFAULT_PORT,
          // 当前哪些工具真的注册给了模型（对照 REA 的 tool availability：广告集 = 可调用集）
          toolAvailability: gateSnapshot(),
        },
      }
      if (!h.ok) out.error = h.error
      return out
    },
  }))

  for (const t of MCP_TOOLS) {
    // 第二个参数 'mcp' = 门控：REST 服务器不可达时这 168 个不注册给模型
    pushReg(defineTool({
      name: t.name,
      description: t.description,
      parameters: t.parameters,
      output: { schema: MCP_OUT, render: renderMcp },
      async execute(args) {
        return mcpCall(config.mcpPort, t, args, (config.mcpTimeoutSec || 900) * 1000)
      },
    }), 'mcp')
  }

  // 首次判定：apply 时桥可能已经在跑（volatile 配置写入会重跑 apply，运行中的服务器跨 re-entry 保留），
  // 也可能已经有外部启动的 REST 服务器 —— 两种情况都要立刻把对应的工具放出来。
  void syncAvailability()

  // ---- 随包技能：把 skills/dsh-ghidra/SKILL.md 注册进运行时技能注册表 ----
  // 为什么走 ctx.skills.register 而不是让用户自己配 customSkillDirs：
  // dsh-skill-filesystem 的默认根（project / user / bundled）**不扫 node_modules 里的插件目录**，
  // 所以放在包里的 SKILL.md 光有文件永远不会被发现 —— 技能必须跟着插件注册才活。
  // 软注入（同下面的 webServer）：headless 组合可能没挂 skills 服务，缺了就记一条日志跳过。
  skillState.registered = false
  skillState.error = ''
  ctx.inject(['skills'], (sctx) => {
    if (!sctx.skills || typeof sctx.skills.register !== 'function') {
      skillState.error = 'skills service unavailable'
      ctx.logger?.warn?.('[ghidra-bridge] ' + skillState.error)
      return
    }
    const definition = loadSkillDefinition()
    if (!definition) {
      skillState.error = 'SKILL.md missing or frontmatter incomplete: ' + SKILL_FILE
      ctx.logger?.warn?.('[ghidra-bridge] ' + skillState.error)
      return
    }
    try {
      disposers.push(sctx.skills.register(definition))
      skillState.registered = true
      skillState.name = definition.name
    } catch (e) {
      skillState.error = String(e?.message || e)
      ctx.logger?.warn?.('[ghidra-bridge] skill registration failed: ' + skillState.error)
    }
  })

  // ---- 插件管理页的状态路由（回环-only；headless 无 webServer 时软注入静默跳过）----
  ctx.inject(['webServer'], (wctx) => {
    const loopback = (req) => {
      const addr = String(req?.socket?.remoteAddress || '')
      return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1'
    }
    const writeJson = (res, status, body) => {
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify(body))
    }
    // 已注册就跳过（上一轮 apply 的路由可能还挂着）—— 路由 handler 只读模块级状态，泄漏无害
    const pushRoute = (route) => {
      const table = route.kind === 'exact' ? wctx.webServer.exact : wctx.webServer.prefixes
      if (table && table.has(route.path)) return
      disposers.push(wctx.webServer.register(route))
    }
    pushRoute({
      kind: 'exact',
      path: '/api/dsh-ghidra/status',
      handler: async (req, res) => {
        if (!loopback(req)) { writeJson(res, 403, { error: 'forbidden: loopback-only' }); return }
        if (req.method !== 'GET') { writeJson(res, 405, { error: 'method not allowed: ' + (req.method ?? '') }); return }
        const cfg = currentConfig || {}
        const mode = cfg.mcpMode || 'unified'
        // 面板轮询就是一次自愈机会：外部启停的服务器在这里被重新对齐（currentGate 是模块级的，
        // 路由 handler 跨 apply 复用也不会读到上一轮的门）
        await currentGate?.sync()
        const h = await mcpHealth(cfg.mcpPort, 2500).catch((e) => ({ ok: false, error: String(e?.message || e) }))
        let inProcess = null
        if (mode === 'unified' && state.port) {
          try { inProcess = await socketOp({ op: 'mcpState' }, 8000) } catch { /* 桥不可达时忽略 */ }
        }
        const body = {
          ok: true,
          plugin: 'ghidra-bridge',
          version: readVersion(gh ? gh.home : '').version || null,
          pyghidra: { running: !!state.port, port: state.port, program: state.program, serverPid: state.serverPid || null, binaryPath: state.binaryPath },
          mcp: {
            running: h.ok, port: cfg.mcpPort, health: h.ok ? h.body : null, pid: state.mcpPid || null,
            bat: mcpBat, log: MCP_LOG_FILE, defaultPort: MCP_DEFAULT_PORT,
            mode, inProcess, unified: !!(inProcess && inProcess.running),
            sharedProgram: mode === 'unified' && h.ok ? (state.program || null) : null,
          },
          tools: { native: toolCounts.native, lifecycle: toolCounts.lifecycle, generated: toolCounts.generated, total: toolCounts.native + toolCounts.lifecycle + toolCounts.generated },
          // 广告集 = 可调用集：total 是定义总数，advertised 是此刻真的注册给模型的数量
          toolAvailability: currentGate ? currentGate.snapshot() : null,
          skill: skillState,
          ghidraHome: gh ? gh.home : null,
          ghidraHomeSource: gh ? (gh.source || null) : null,
          dataRoot: pluginDataRoot(),
          install: { running: installState.running, phase: installState.phase, pct: installState.pct, bytes: installState.bytes, total: installState.total, error: installState.error, home: installState.home, log: installState.log },
          migrate: { running: migrateState.running, phase: migrateState.phase, error: migrateState.error, from: migrateState.from, to: migrateState.to, ok: migrateState.ok },
        }
        if (!h.ok) body.mcp.error = h.error
        writeJson(res, 200, body)
      },
    })
    pushRoute({
      kind: 'exact',
      path: '/api/dsh-ghidra/mcp-stop',
      handler: async (req, res) => {
        if (!loopback(req)) { writeJson(res, 403, { error: 'forbidden: loopback-only' }); return }
        if (req.method !== 'POST') { writeJson(res, 405, { error: 'method not allowed: ' + (req.method ?? '') }); return }
        const cfg = currentConfig || {}
        const result = await mcpStop(cfg.mcpPort, state.mcpPid || 0)
        state.mcpPid = 0
        // 面板上的「停止」也要立刻撤掉 168 个生成工具（与 ghidra_mcp_stop 工具同款行为）
        void currentGate?.sync()
        writeJson(res, 200, { ok: true, result: result })
      },
    })
    const readBody = (req) => new Promise((resolve) => {
      let data = ''
      req.on('data', (c) => { data += c; if (data.length > 65536) { req.destroy(); resolve('{}') } })
      req.on('end', () => resolve(data))
      req.on('error', () => resolve('{}'))
    })
    // ---- doctor：Ghidra + 工具健康检查（只读；overall = 前置条件全过，运行态为参考）----
    pushRoute({
      kind: 'exact',
      path: '/api/dsh-ghidra/doctor',
      handler: async (req, res) => {
        if (!loopback(req)) { writeJson(res, 403, { error: 'forbidden: loopback-only' }); return }
        if (req.method !== 'GET') { writeJson(res, 405, { error: 'method not allowed: ' + (req.method ?? '') }); return }
        const cfg = currentConfig || {}
        const checks = []
        // optional=true 的运行态/信息检查：服务器按需启动，未运行只作提示（IDLE），不算 FAIL
        const add = (name, ok, detail, optional) => checks.push({ name, ok: !!ok, detail: detail || '', optional: !!optional })
        const home = gh ? gh.home : null
        add('Ghidra home', !!home && existsSync(home), home ? String(home) + (gh && gh.source ? '  [' + gh.source + ']' : '') : 'not detected — set ghidraHome in config or use Download Ghidra')
        add('Plugin data root', existsSync(pluginDataRoot()), pluginDataRoot(), true)
        const launcher = home ? join(home, 'Ghidra', 'Features', 'PyGhidra', 'support', 'pyghidra_launcher.py') : null
        add('PyGhidra launcher', !!launcher && existsSync(launcher), launcher || 'missing')
        add('GhidraMCP headless.bat', !!mcpBat && existsSync(mcpBat), mcpBat || 'missing')
        let pyOk = false, pyDetail = ''
        try {
          const r = spawnSync('py', ['-' + (cfg.pythonVer || '3.13'), '--version'], { timeout: 15000, encoding: 'utf8' })
          pyOk = r.status === 0
          pyDetail = pyOk ? String(r.stdout || '').trim() : String(r.stderr || r.stdout || 'py launcher not found').trim()
        } catch (e) { pyDetail = String(e?.message || e) }
        add('Python ' + (cfg.pythonVer || '3.13'), pyOk, pyDetail)
        add('PyGhidra bridge', !!state.port, state.port ? 'running on port ' + state.port : 'idle (starts on first tool call)', true)
        const mcpPort = cfg.mcpPort || MCP_DEFAULT_PORT
        const h = await mcpHealth(mcpPort, 2500).catch((e) => ({ ok: false, error: String(e?.message || e) }))
        add('GhidraMCP server', h.ok, h.ok ? 'healthy on port ' + mcpPort : 'idle — nothing listening on port ' + mcpPort, true)
        let ver = null
        try { ver = home ? readVersion(home).version : null } catch {}
        add('Ghidra version', !!ver, ver ? String(ver) : 'unknown', true)
        const essential = checks.filter((c) => !c.optional)
        writeJson(res, 200, {
          ok: essential.every((c) => c.ok),
          essentialOk: essential.filter((c) => c.ok).length,
          essentialTotal: essential.length,
          runtimeIdle: checks.filter((c) => c.optional && !c.ok).length,
          checks,
        })
      },
    })
    // ---- Ghidra 下载安装（后台；进度在 /status 的 install 字段）----
    pushRoute({
      kind: 'exact',
      path: '/api/dsh-ghidra/install-ghidra',
      handler: async (req, res) => {
        if (!loopback(req)) { writeJson(res, 403, { error: 'forbidden: loopback-only' }); return }
        if (req.method !== 'POST') { writeJson(res, 405, { error: 'method not allowed: ' + (req.method ?? '') }); return }
        if (installState.running) { writeJson(res, 409, { error: 'install already running', phase: installState.phase, pct: installState.pct }); return }
        let body = {}
        try { body = JSON.parse((await readBody(req)) || '{}') } catch {}
        // 下载解压到插件数据根：<…>/node_modules/.dsh-ghidra/ghidra（「插件的一切都在插件树里」）
        const targetRoot = ensureDataPaths().ghidraDir
        installState.running = true
        installState.phase = 'resolving latest release'
        installState.pct = 0
        installState.bytes = 0
        installState.total = 0
        installState.error = ''
        installState.home = null
        installState.log = ''
        runInstall(targetRoot, !!body.force).catch(() => {})
        writeJson(res, 200, { ok: true, started: true, targetRoot })
      },
    })
    // ---- home 迁移（后台；结果在 /status 的 migrate 字段）----
    pushRoute({
      kind: 'exact',
      path: '/api/dsh-ghidra/migrate-home',
      handler: async (req, res) => {
        if (!loopback(req)) { writeJson(res, 403, { error: 'forbidden: loopback-only' }); return }
        if (req.method !== 'POST') { writeJson(res, 405, { error: 'method not allowed: ' + (req.method ?? '') }); return }
        if (migrateState.running) { writeJson(res, 409, { error: 'migration already running', phase: migrateState.phase }); return }
        let body = {}
        try { body = JSON.parse((await readBody(req)) || '{}') } catch {}
        const from = String(body.from || ''), to = String(body.to || '')
        const bad = (m) => { writeJson(res, 400, { ok: false, error: m }) }
        if (!isAbsolute(from) || !isAbsolute(to)) return bad('from/to must be absolute paths')
        if (from === to) return bad('from and to are the same path')
        if (!existsSync(from)) return bad('source home does not exist: ' + from)
        if (existsSync(to)) {
          let empty = false
          try { empty = readdirSync(to).length === 0 } catch {}
          if (!empty) return bad('target already exists and is not empty: ' + to)
        }
        migrateState.running = true
        migrateState.phase = 'stopping servers'
        migrateState.error = ''
        migrateState.from = from
        migrateState.to = to
        migrateState.ok = null
        runMigrate(from, to).catch(() => {})
        writeJson(res, 200, { ok: true, started: true })
      },
    })
    // ---- 应用内文件夹浏览器（回环-only，只读列目录 + 新建目录）----
    // 为什么不用原生对话框：宿主进程弹出的 PowerShell/WinForms 对话框在部分环境里根本不可见
    // （无交互 window station / windowsHide 的 CREATE_NO_WINDOW），表现为「点了没反应」且请求一直挂着。
    // 改为宿主只做「列目录」这件确定性的事，选择器由插件自己的 UI 渲染 —— 不依赖桌面会话。
    const listDirs = (dir) => {
      const out = []
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        let isDir = e.isDirectory()
        if (!isDir && e.isSymbolicLink()) {
          try { isDir = statSync(join(dir, e.name)).isDirectory() } catch { isDir = false }
        }
        if (isDir) out.push({ name: e.name, path: join(dir, e.name), dot: e.name.startsWith('.') })
      }
      out.sort((a, b) => a.name.localeCompare(b.name))
      return out
    }
    const dotSegmentOf = (p) => String(p).split(/[\\/]+/).filter(Boolean).find((seg) => seg.startsWith('.')) || null
    pushRoute({
      kind: 'exact',
      path: '/api/dsh-ghidra/list-dir',
      handler: async (req, res) => {
        if (!loopback(req)) { writeJson(res, 403, { error: 'forbidden: loopback-only' }); return }
        if (req.method !== 'POST') { writeJson(res, 405, { error: 'method not allowed: ' + (req.method ?? '') }); return }
        let body = {}
        try { body = JSON.parse((await readBody(req)) || '{}') } catch {}
        const want = String(body.path || '')
        // 未给路径（或路径无效）→ 回驱动器列表，作为浏览器起点
        const drives = []
        for (const L of 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
          const d = L + ':\\'
          try { if (existsSync(d)) drives.push(d) } catch { /* 跳过 */ }
        }
        if (!want) { writeJson(res, 200, { ok: true, path: '', parent: null, drives, dirs: [] }); return }
        if (!isAbsolute(want)) { writeJson(res, 400, { ok: false, error: 'path must be absolute', drives }); return }
        if (!existsSync(want)) { writeJson(res, 200, { ok: false, error: 'path does not exist', path: want, drives }); return }
        let isDir = false
        try { isDir = statSync(want).isDirectory() } catch { /* 视为非目录 */ }
        if (!isDir) { writeJson(res, 200, { ok: false, error: 'not a directory', path: want, drives }); return }
        try {
          const dirs = listDirs(want)
          const parent = dirname(want)
          writeJson(res, 200, {
            ok: true,
            path: want,
            parent: parent && parent !== want ? parent : null,
            dirs: dirs.slice(0, 500),
            truncated: dirs.length > 500,
            drives,
            dotSegment: dotSegmentOf(want),
          })
        } catch (e) {
          writeJson(res, 200, { ok: false, error: 'cannot read directory: ' + String(e?.message || e), path: want, drives })
        }
      },
    })
    // 新建目录（选择项目目录时常常需要就地建一个）；名字里不允许分隔符，也不允许点开头（Ghidra 会拒）
    pushRoute({
      kind: 'exact',
      path: '/api/dsh-ghidra/mkdir',
      handler: async (req, res) => {
        if (!loopback(req)) { writeJson(res, 403, { error: 'forbidden: loopback-only' }); return }
        if (req.method !== 'POST') { writeJson(res, 405, { error: 'method not allowed: ' + (req.method ?? '') }); return }
        let body = {}
        try { body = JSON.parse((await readBody(req)) || '{}') } catch {}
        const parent = String(body.parent || '')
        const name = String(body.name || '').trim()
        const bad = (m) => writeJson(res, 400, { ok: false, error: m })
        if (!isAbsolute(parent) || !existsSync(parent)) return bad('parent must be an existing absolute path')
        if (!name) return bad('name is required')
        if (/[\\/:*?"<>|]/.test(name)) return bad('name must not contain \\ / : * ? " < > |')
        if (name.startsWith('.')) return bad('name must not start with "." — Ghidra rejects dot-prefixed path elements')
        const target = join(parent, name)
        if (existsSync(target)) return bad('already exists: ' + target)
        try {
          mkdirSync(target, { recursive: true })
          writeJson(res, 200, { ok: true, path: target })
        } catch (e) {
          writeJson(res, 500, { ok: false, error: String(e?.message || e) })
        }
      },
    })
  })
}
