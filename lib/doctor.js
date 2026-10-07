// 跨平台自检（doctor）：把「本机到底被解析成了什么」逐项摊开，并给出**这个平台**的补救办法。
//
// 与 ghidra_status 的分工：
//   ghidra_status 报运行时状态 + 此刻哪些工具可用（给 agent 决定下一步做什么）；
//   ghidra_doctor 报环境解析结果 + 为什么不对 + 怎么改（给人修环境），且不要求任何服务器已经跑起来。
//
// 它存在的理由：本项目最初的 Windows-only 版本在 Linux 上会把每一处平台假设都翻译成同一句
// 「Ghidra not installed」，而真正的原因有七个不同（见 LINUX-PORT.md）。一个把 launcher 名、
// 解释器、settings 目录、扩展目录逐个打印出来的工具，比一句笼统的报错省掉一整轮排查。
import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, accessSync, constants } from 'node:fs'
import { join } from 'node:path'
import {
  hasHeadless, headlessLauncher, readVersion, pythonCommand, ghidraUserBaseDir,
  ghidraSettingsDir, ghidraUserExtensionDir,
} from './ghidra.js'

// 每个平台的补救办法。写具体命令，不写「请安装 Ghidra」——笼统的提示等于没有提示。
const SETUP = {
  win32: {
    ghidra: 'Unpack a Ghidra release zip (e.g. D:\\tools\\ghidra_12.1.4_PUBLIC), or use Download Ghidra in the plugin settings, or set ghidraHome in the plugin config.',
    python: 'Install Python 3.13 (python.org or the Microsoft Store) so the `py` launcher is on PATH, then: py -3.13 -m pip install pyghidra',
    java: 'Install a JDK 21+ (Temurin) and set JAVA_HOME.',
    extension: 'Install the GhidraMCP extension to %APPDATA%\\ghidra\\<versioned dir>\\Extensions\\GhidraMCP.',
  },
  darwin: {
    ghidra: 'brew install --cask ghidra (lands in /Applications/Ghidra.app), or unpack a release and set ghidraHome.',
    python: 'brew install python@3.13 && python3.13 -m pip install pyghidra — or point DSH_GHIDRA_PYTHON at a venv interpreter.',
    java: 'brew install openjdk@21 and set JAVA_HOME (Ghidra 12 needs 21+).',
    extension: 'Install GhidraMCP to ~/Library/ghidra/<versioned dir>/Extensions/GhidraMCP.',
  },
  linux: {
    ghidra: 'Unpack a Ghidra release to /opt/ghidra and export GHIDRA_INSTALL_DIR=/opt/ghidra, or set ghidraHome in the plugin config.',
    python: 'Create a venv (python3 -m venv ~/pyghidra-venv), pip install pyghidra into it, then set DSH_GHIDRA_PYTHON=~/pyghidra-venv/bin/python3.',
    java: 'Install a JDK 21+ and export JAVA_HOME (and PYGHIDRA_JAVA_HOME) — Ghidra 12 will not start on Java 17.',
    extension: 'Install GhidraMCP to $XDG_CONFIG_HOME/ghidra/<versioned dir>/Extensions/GhidraMCP — NOT ~/.ghidra. The versioned dir ends in _DEV or _PUBLIC per application.release.name, and installing to the wrong one fails silently.',
  },
}
const setup = () => SETUP[process.platform] || SETUP.linux

function writable(dir) {
  try { accessSync(dir, constants.W_OK); return true } catch { return false }
}

// 跑一条 --version 之类的短命令，返回首行；失败返回 null。
function firstLine(cmd, args, timeout = 15000) {
  try {
    const r = spawnSync(cmd, args, { encoding: 'utf8', timeout, windowsHide: true })
    const text = String(r.stdout || r.stderr || '').trim()
    return r.status === 0 && text ? text.split(/\r?\n/)[0] : null
  } catch {
    return null
  }
}

// GhidraMCP 扩展是否已安装到 Ghidra 会加载的位置（两个历史布局都认）。
function ghidraMcpJars(extensionsDir) {
  const dir = join(extensionsDir, 'GhidraMCP')
  const found = []
  for (const sub of ['lib', '.']) {
    try {
      for (const f of readdirSync(join(dir, sub))) {
        if (/\.jar$/i.test(f)) found.push(join(dir, sub, f))
      }
    } catch { /* 目录不存在 */ }
  }
  return found
}

/**
 * 收集跨平台自检项。
 * ctx: { config, gh, state, mcpBat, mcpHealth, dataRoot, projectDir }
 *   mcpHealth 传函数时按 (port, timeoutMs) 调用；传普通对象则直接采纳其结果。
 * 返回 { ok, essentialOk, essentialTotal, runtimeIdle, platform, checks } —— 与 /doctor 路由同形，
 * 面板与工具共用一份数据源，不会出现「面板说 OK、工具说 FAIL」。
 */
export async function runDoctor(ctx = {}) {
  const { config = {}, gh = null, state = {}, mcpBat = null, dataRoot = null, projectDir = null } = ctx
  const checks = []
  // optional=true 的运行态/信息项：服务器是**按需启动**的，没跑只算 IDLE，不算 FAIL。
  const add = (name, ok, detail, hint = '', optional = false) =>
    checks.push({ name, ok: !!ok, detail: detail || '', hint: hint || '', optional: !!optional })

  const home = gh ? gh.home : null
  const pyVer = config.pythonVer || '3.13'

  add('Platform', true, `${process.platform} ${process.arch} · Node ${process.version}`, '', true)

  // ---- 1. Ghidra 安装本体 ----
  add('Ghidra home', !!home && existsSync(home),
    home ? String(home) + (gh && gh.source ? '  [' + gh.source + ']' : '') : 'not detected',
    setup().ghidra)

  const launcher = home ? headlessLauncher(home) : null
  // 这一项单独列出来，是因为它正是 Linux 上整个插件失效的那一处：上游只认 analyzeHeadless.bat。
  add('Headless launcher', !!home && hasHeadless(home),
    launcher && existsSync(launcher) ? launcher : 'missing support/analyzeHeadless(.bat) under the Ghidra home',
    'Ghidra ships analyzeHeadless.bat on Windows and an extensionless analyzeHeadless elsewhere; set ghidraHome to the directory that contains support/.')

  const v = home ? readVersion(home) : { version: '?', release: '' }
  add('Ghidra version', !!home && v.version !== '?',
    v.version === '?' ? 'unknown (Ghidra/application.properties unreadable)' : v.version + ' ' + (v.release || ''),
    'Set ghidraHome to a real Ghidra install directory.', true)

  if (gh) {
    add('Install path encoding', true,
      gh.nonAscii ? 'non-ASCII — log4j redirect workaround engaged' : 'ASCII (no workaround needed)', '', true)
  }

  const pyLauncher = home ? join(home, 'Ghidra', 'Features', 'PyGhidra', 'support', 'pyghidra_launcher.py') : null
  add('PyGhidra launcher', !!pyLauncher && existsSync(pyLauncher),
    pyLauncher || 'missing — this Ghidra build has no PyGhidra feature',
    'PyGhidra ships inside Ghidra (Ghidra/Features/PyGhidra). A Ghidra build without it cannot host the bridge.')

  // ---- 2. 解释器与 pyghidra ----
  const py = pythonCommand(pyVer)
  const pyLabel = [py.cmd, ...py.args].join(' ')
  const pyVersion = firstLine(py.cmd, [...py.args, '--version'])
  add('Python ' + pyVer, !!pyVersion, pyVersion ? pyLabel + ' — ' + pyVersion : pyLabel + ' — not runnable', setup().python)

  let pyghidraOk = false
  try {
    const r = spawnSync(py.cmd, [...py.args, '-c', 'import pyghidra'], { encoding: 'utf8', timeout: 20000, windowsHide: true })
    pyghidraOk = r.status === 0
    add('pyghidra module', pyghidraOk, pyghidraOk ? 'importable' : String(r.stderr || r.stdout || 'import failed').trim().split(/\r?\n/).pop(),
      pyLabel + ' -m pip install pyghidra')
  } catch (e) {
    add('pyghidra module', false, String(e?.message || e), pyLabel + ' -m pip install pyghidra')
  }

  const javaHome = process.env.JAVA_HOME || ''
  const javaVersion = firstLine('java', ['-version'])
  add('Java runtime', !!javaVersion,
    (javaHome ? 'JAVA_HOME=' + javaHome + ' · ' : '') + (javaVersion || 'java not on PATH'),
    setup().java, true)

  // ---- 3. Ghidra 的 per-user 目录（settings / 扩展）----
  const settingsDir = home ? ghidraSettingsDir(home) : ghidraUserBaseDir()
  add('Ghidra user settings dir', existsSync(settingsDir) ? writable(settingsDir) : true,
    settingsDir + (existsSync(settingsDir) ? (writable(settingsDir) ? ' (writable)' : ' (NOT writable)') : ' (not created yet — will be created on first save)'),
    'Ghidra resolves this per platform: %APPDATA%\\ghidra on Windows, ~/Library/ghidra on macOS, $XDG_CONFIG_HOME/ghidra (or ~/.config/ghidra) on Linux.', true)

  const extDir = home ? ghidraUserExtensionDir(home) : null
  const jars = extDir ? ghidraMcpJars(extDir) : []
  add('GhidraMCP extension', jars.length > 0,
    jars.length ? jars.join(', ') : (extDir || 'unknown') + ' — no GhidraMCP jar',
    setup().extension, true)

  add('GhidraMCP headless launcher', !!mcpBat && existsSync(mcpBat),
    mcpBat ? String(mcpBat) + (existsSync(mcpBat) ? '' : ' (missing)') : 'miss',
    'Only standalone MCP mode needs this; unified mode (the default) serves REST from the bridge JVM.', true)

  // ---- 4. 运行态 ----
  add('PyGhidra bridge', !!state.port,
    state.port ? 'running on port ' + state.port + (state.program ? ' · ' + state.program : '') : 'idle (starts on the first tool call)',
    '', true)

  if (dataRoot) add('Plugin data root', existsSync(dataRoot), dataRoot, '', true)
  if (projectDir) add('Project dir', !existsSync(projectDir) || writable(projectDir),
    projectDir + (existsSync(projectDir) ? (writable(projectDir) ? ' (writable)' : ' (NOT writable)') : ' (not created yet — created on first import)'),
    'Ghidra rejects project paths containing a path element that starts with "."; the default lives in the OS temp dir.', true)

  const mcpPort = config.mcpPort || 8123
  let h = { ok: false }
  try {
    h = typeof ctx.mcpHealth === 'function' ? await ctx.mcpHealth(mcpPort, 2500) : (ctx.mcpHealth || { ok: false })
  } catch (e) {
    h = { ok: false, error: String(e?.message || e) }
  }
  add('GhidraMCP server', !!h.ok,
    h.ok ? 'healthy on port ' + mcpPort + (h.body && h.body.version ? ' · ' + h.body.version : '') : 'idle — nothing listening on port ' + mcpPort,
    'Start it with ghidra_mcp_start (unified mode) after ghidra_open.', true)

  const essential = checks.filter((c) => !c.optional)
  return {
    ok: essential.every((c) => c.ok),
    essentialOk: essential.filter((c) => c.ok).length,
    essentialTotal: essential.length,
    runtimeIdle: checks.filter((c) => c.optional && !c.ok).length,
    platform: process.platform,
    checks,
  }
}
