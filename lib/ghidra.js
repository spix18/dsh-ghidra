// Ghidra 环境探测 / 导入 / 常驻服务器生命周期
import { spawnSync, spawn } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync, appendFileSync, mkdirSync, readdirSync, statSync, rmSync, openSync, closeSync } from 'node:fs'
import { join, basename } from 'node:path'
import { tmpdir, homedir } from 'node:os'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { makeSpawnArgs, killPid, runProcess } from './run.js'
import { jsonRequest } from './socket.js'
import { dataPaths, ensureDataPaths, ghidraInDataRoot, defaultProjectDir } from './paths.js'

function hasNonAscii(p) {
  return /[^\x00-\x7F]/.test(p)
}

const LOG4J_CONFIG =
  '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<Configuration status="WARN">\n' +
  '  <Appenders>\n' +
  '    <Console name="console" target="SYSTEM_OUT">\n' +
  '      <PatternLayout pattern="%d{ISO8601} %-5p %c{1} - %m%n"/>\n' +
  '    </Console>\n' +
  '    <File name="runlog" fileName="${sys:dsh.log4j.file}" append="false">\n' +
  '      <PatternLayout pattern="%d{ISO8601} %-5p %c{1} - %m%n"/>\n' +
  '    </File>\n' +
  '  </Appenders>\n' +
  '  <Loggers>\n' +
  '    <Logger name="org.apache" level="warn"/>\n' +
  '    <Root level="info">\n' +
  '      <AppenderRef ref="console"/>\n' +
  '      <AppenderRef ref="runlog"/>\n' +
  '    </Root>\n' +
  '  </Loggers>\n' +
  '</Configuration>\n'

// [linux-port] Ghidra ships the headless launcher as `analyzeHeadless.bat` on Windows and as
// an extensionless executable script on Linux/macOS. The upstream check is .bat-only, so on
// every non-Windows platform detectGhidraHome() returned null and every ghidra_* tool
// reported "Ghidra not installed". Accept either name.
export function hasHeadless(home) {
  return existsSync(join(home, 'support', 'analyzeHeadless.bat'))
    || existsSync(join(home, 'support', 'analyzeHeadless'))
}

// [linux-port] Resolve the headless launcher that actually exists in this install.
export function headlessLauncher(home) {
  const win = join(home, 'support', 'analyzeHeadless.bat')
  return existsSync(win) ? win : join(home, 'support', 'analyzeHeadless')
}

// [cross-platform] Collect plausible Ghidra homes below `root`. Callers filter with hasHeadless(),
// so over-collecting costs a stat and nothing else. Covers the layouts that actually occur:
//   /opt/ghidra_12.1.4_PUBLIC                                   plain unpacked tarball
//   /opt/homebrew/Caskroom/ghidra/12.1.4/ghidra_12.1.4_PUBLIC   Homebrew cask
//   /Applications/Ghidra.app/Contents/Resources/ghidra          macOS app bundle
function collectGhidraHomes(root, out) {
  if (!root) return
  let names
  try { names = readdirSync(root) } catch { return } // 目录不存在或无权限
  for (const name of names) {
    if (!/^ghidra/i.test(name)) continue
    const p = join(root, name)
    out.push(p)
    if (/\.app$/i.test(name)) {
      out.push(join(p, 'Contents', 'Resources', 'ghidra'))
      continue
    }
    // One level deeper: Homebrew's Caskroom/<version>/ and tarballs unpacked inside a folder.
    try {
      for (const inner of readdirSync(p)) if (/^ghidra/i.test(inner)) out.push(join(p, inner))
    } catch { /* 不是目录 */ }
  }
}

export function detectGhidraHome(config) {
  // 显式配置优先
  if (config.ghidraHome && hasHeadless(config.ghidraHome)) {
    return { home: config.ghidraHome, nonAscii: hasNonAscii(config.ghidraHome), source: 'config' }
  }
  // 其次：插件自有数据根里的安装（<…>/node_modules/.dsh-ghidra/ghidra）——「插件的一切都待在插件树里」
  const local = ghidraInDataRoot()
  if (local && hasHeadless(local)) return { home: local, nonAscii: hasNonAscii(local), source: 'plugin-data' }
  // 最后：历史/外部安装（GHIDRA_HOME 与常见路径）
  const candidates = []
  // [linux-port] GHIDRA_INSTALL_DIR is the conventional Ghidra env var (and the one set on
  // Linux hosts); upstream only read GHIDRA_HOME. Check both, env-configured ones first.
  if (process.env.GHIDRA_INSTALL_DIR) candidates.push(process.env.GHIDRA_INSTALL_DIR)
  if (process.env.GHIDRA_HOME) candidates.push(process.env.GHIDRA_HOME)
  if (process.platform === 'win32') {
    candidates.push(
      'D:\\tools\\ghidra_12.1.3_PUBLIC',
      'D:\\配置文件\\ghidra_12.1.3_PUBLIC',
      'C:\\Program Files\\ghidra_12.1.3_PUBLIC',
      'C:\\Program Files (x86)\\ghidra_12.1.3_PUBLIC',
      'D:\\ghidra_12.1.3_PUBLIC'
    )
    for (const root of ['D:\\', 'D:\\tools', 'D:\\配置文件', 'C:\\Program Files', 'D:\\Program Files',
      process.env.USERPROFILE]) {
      collectGhidraHomes(root, candidates)
    }
  } else if (process.platform === 'darwin') {
    // [macos] Homebrew's cask extracts the tarball to <caskroom>/ghidra/<version>/<home>, a manual
    // install is a versioned directory in /Applications (~/Applications per-user), and the release
    // zip wraps the whole install in Ghidra.app/Contents/Resources/ghidra.
    candidates.push('/Applications/ghidra', '/opt/ghidra', '/usr/local/ghidra', join(homedir(), 'ghidra'))
    for (const root of ['/opt/homebrew/Caskroom', '/usr/local/Caskroom', '/Applications',
      join(homedir(), 'Applications'), '/opt', '/usr/local', homedir()]) {
      collectGhidraHomes(root, candidates)
    }
  } else {
    // [linux-port] Unix install locations: the three system prefixes plus $HOME, which is where a
    // hand-unpacked tarball usually ends up. Ghidra tarballs unpack to `ghidra_<ver>_<release>`.
    candidates.push('/opt/ghidra', '/usr/local/ghidra', '/usr/share/ghidra', join(homedir(), 'ghidra'))
    for (const root of ['/opt', '/usr/local', '/usr/share', '/usr/local/opt', homedir()]) {
      collectGhidraHomes(root, candidates)
    }
  }
  const ok = (c) => hasHeadless(c)
  const ascii = candidates.find((c) => ok(c) && !hasNonAscii(c))
  const any = candidates.find(ok)
  const home = ascii || any
  return home ? { home, nonAscii: hasNonAscii(home), source: 'external' } : null
}

export function readVersion(home) {
  try {
    const text = readFileSync(join(home, 'Ghidra', 'application.properties'), 'utf8')
    const m = /application\.version=(.+)/.exec(text)
    const r = /application\.release\.name=(.+)/.exec(text)
    return { version: m ? m[1].trim() : '?', release: r ? r[1].trim() : '' }
  } catch {
    return { version: '?', release: '' }
  }
}

// [linux-port] `py` is the Windows Python Launcher. It does not exist on Linux/macOS, so every
// call that shelled out to `py -3.13 ...` failed with ENOENT: the PyGhidra bridge could never
// start, and pyghidraInstalled() always reported false.
// On Windows keep `py -<ver>`; elsewhere resolve a real interpreter. Order:
//   1. explicit DSH_GHIDRA_PYTHON (full command, may contain spaces)
//   2. python<ver> (the version the config asks for), then python3 / python on PATH
//   3. the same names inside $VIRTUAL_ENV, ~/.venv and ~/pyghidra-venv
// Returns { cmd, args } where the version flag is already folded into args (Windows only).
function candidatePythons(pythonVer) {
  if (process.platform === 'win32') {
    return [{ cmd: 'py', args: ['-' + pythonVer] }]
  }
  const list = []
  const explicit = (process.env.DSH_GHIDRA_PYTHON || '').trim()
  if (explicit) {
    const parts = explicit.split(/\s+/)
    list.push({ cmd: parts[0], args: parts.slice(1) })
  }
  for (const name of ['python3', 'python']) list.push({ cmd: name, args: [] })
  // [cross-platform] Probe the version the config asks for before the generic names, so a host
  // carrying several interpreters selects the one the user named. `pythonVer` is like '3.13'.
  const ver = String(pythonVer ?? '').trim()
  const versioned = /^\d+\.\d+$/.test(ver) ? ['python' + ver] : []
  for (const name of versioned) list.push({ cmd: name, args: [] })
  for (const v of [process.env.VIRTUAL_ENV, join(homedir(), '.venv'), join(homedir(), 'pyghidra-venv')]) {
    if (!v) continue
    for (const name of [...versioned, 'python3', 'python']) list.push({ cmd: join(v, 'bin', name), args: [] })
  }
  return list
}

function pythonHasPyghidra(cand) {
  try {
    const r = spawnSync(cand.cmd, [...cand.args, '-c', 'import pyghidra'], {
      encoding: 'utf8', timeout: 20000, windowsHide: true,
    })
    return r.status === 0
  } catch {
    return false
  }
}

// Resolve the interpreter that actually has pyghidra. Cached, because probing one candidate costs
// a subprocess and the status panel renders often. The cache is keyed by pythonVer: a single
// unconditional slot made a config change (3.13 → 3.12) invisible until DSH restarted, which
// upstream did not do — it re-checked the requested version on every call.
let _pythonCache = null // { key, cand }
export function pythonCommand(pythonVer) {
  const key = String(pythonVer ?? '')
  if (_pythonCache && _pythonCache.key === key) return _pythonCache.cand
  const list = candidatePythons(pythonVer)
  const found = list.find(pythonHasPyghidra)
  // Fall back to the first candidate so error messages name a concrete command.
  _pythonCache = { key, cand: found || list[0] }
  return _pythonCache.cand
}

export function resetPythonCache() {
  _pythonCache = null
}

export function pyghidraInstalled(pythonVer) {
  try {
    return pythonHasPyghidra(pythonCommand(pythonVer))
  } catch {
    return false
  }
}

// [linux-port] PY_PYTHON is a Windows `py` launcher variable and is meaningless elsewhere.
// Export it only where it is honoured, so it cannot confuse the real interpreter.
export function envFor(home, nonAscii, tmpDir, logFile, pythonVer) {
  const env = { ...process.env }
  if (process.platform === 'win32') env.PY_PYTHON = pythonVer
  if (nonAscii) {
    const dir = join(tmpDir, 'dsh-ghidra')
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'log4j2.xml'), LOG4J_CONFIG)
    const opt = '-Dlog4j.configurationFile=' + join(dir, 'log4j2.xml') + ' -Ddsh.log4j.file=' + logFile
    env.GHIDRA_HEADLESS_JAVA_OPTIONS = opt
    env.PYGHIDRA_JAVA_OPTIONS = opt
  }
  return env
}

export function cleanLocks(projectDir, projectName) {
  // Ghidra 项目锁：进程异常退出后残留会阻塞后续启动
  for (const f of [projectName + '.lock', projectName + '.lock~']) {
    try { rmSync(join(projectDir, f), { force: true }) } catch { /* ignore */ }
  }
}

// 上一次运行 / DSH 崩溃遗留下来的 Ghidra JVM 会一直占着项目锁。Ghidra 用的是 Java Channel Lock，
// 删掉 .lock 文件并不能释放——活的 JVM 仍然持有。这时新的 launcher 会立刻 exit 0 且永远不写端口文件，
// 表面症状和「启动失败」一模一样。所以启动前必须先把真正的旧 JVM 干掉。
// [linux-port] Upstream returns 0 immediately off Windows, so stale JVMs holding a Java Channel
// Lock were never cleaned up on Linux: the next launcher exited 0 without writing a port file and
// every ghidra_* call failed with a misleading "bridge not running". Implement the same intent
// with pgrep -f (matches the project path in the command line), and skip our own pid.
function killProcessesUsing(needle) {
  if (process.platform === 'win32') {
    try {
      const esc = String(needle).replace(/'/g, "''")
      const ps = 'Get-CimInstance Win32_Process -Filter "Name=\'java.exe\' OR Name=\'python.exe\'" | ' +
        'Where-Object { $_.CommandLine -and $_.CommandLine.Contains(\'' + esc + '\') } | ' +
        'Select-Object -ExpandProperty ProcessId'
      const r = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps], { encoding: 'utf8', timeout: 30000 })
      const pids = String(r.stdout || '').split(/\s+/).filter((s) => /^\d+$/.test(s)).map(Number)
      for (const p of pids) killPid(p)
      return pids.length
    } catch {
      return 0
    }
  }
  try {
    const r = spawnSync('pgrep', ['-f', '--', String(needle)], { encoding: 'utf8', timeout: 30000 })
    const pids = String(r.stdout || '').split(/\s+/)
      .filter((s) => /^\d+$/.test(s))
      .map(Number)
      .filter((p) => p > 0 && p !== process.pid && p !== process.ppid)
    for (const p of pids) killPid(p)
    return pids.length
  } catch {
    return 0
  }
}

export function killStaleServers(projectDir, pidFile) {
  let killed = 0
  try {
    const pid = Number(String(readFileSync(pidFile, 'utf8')).trim())
    if (pid > 0) killPid(pid)
  } catch { /* 没有记录 */ }
  try { rmSync(pidFile, { force: true }) } catch { /* ignore */ }
  killed += killProcessesUsing(projectDir)
  return killed
}

export function projectPaths(config) {
  // 缺省项目目录：%TEMP%\dsh-ghidra-projects（**不能**放插件数据根 —— Ghidra 的项目路径校验
  // 禁止任何以 '.' 开头的路径元素，而 DSH_HOME 本身是 `.dsh`；详见 lib/paths.js 文件头）。
  const projectDir = config.ghidraProjectDir || defaultProjectDir()
  mkdirSync(projectDir, { recursive: true })
  return { projectDir, projectName: config.projectName || 'dsh' }
}

function markerFile(projectDir) {
  return join(projectDir, '.dsh-import.json')
}

function binaryStamp(p) {
  try {
    const st = statSync(p)
    return { size: st.size, mtimeMs: st.mtimeMs }
  } catch {
    return null
  }
}

export function needsImport(projectDir, binaryPath) {
  try {
    const m = JSON.parse(readFileSync(markerFile(projectDir), 'utf8'))
    if (m.binary !== binaryPath) return true
    const st = binaryStamp(binaryPath)
    return !st || m.size !== st.size || m.mtimeMs !== st.mtimeMs
  } catch {
    return true
  }
}

export async function importBinary(gh, binaryPath, config, onProgress) {
  const { projectDir, projectName } = projectPaths(config)
  cleanLocks(projectDir, projectName)
  if (!needsImport(projectDir, binaryPath)) {
    onProgress('项目已导入，跳过导入\n')
    return basename(binaryPath)
  }
  // [linux-port] use the launcher this install actually has (.bat on Windows, extensionless here)
  const headless = headlessLauncher(gh.home)
  const args = [projectDir, projectName, '-import', binaryPath, '-overwrite', '-analysisTimeoutPerFile', String(config.analysisTimeoutSec || 600)]
  const env = envFor(gh.home, gh.nonAscii, tmpdir(), join(projectDir, 'import.log'), config.pythonVer)
  onProgress('导入并分析 ' + basename(binaryPath) + '（首次可能耗时较长）\n')
  const r = await runProcess(headless, args, {
    cwd: projectDir,
    timeoutMs: (config.analysisTimeoutSec || 600) * 1000 + 120000,
    maxOutputChars: 50000,
    signal: undefined,
    env,
  })
  if (r.timedOut || r.exitCode !== 0) {
    throw new Error('导入失败 (exit=' + r.exitCode + '): ' + (r.stderr || r.stdout).slice(-800))
  }
  const st = binaryStamp(binaryPath)
  if (st) {
    try { writeFileSync(markerFile(projectDir), JSON.stringify({ binary: binaryPath, size: st.size, mtimeMs: st.mtimeMs })) } catch { /* ignore */ }
  }
  const summary = r.stdout.split('\n').filter((l) => /Import succeeded|Analysis succeeded|REPORT.*ERROR/i.test(l)).join('\n')
  onProgress((summary || r.stdout.slice(-400)) + '\n')
  return basename(binaryPath)
}

// [linux-port] Ghidra's PyGhidra feature stores the interpreter used to launch headless in
// `<ghidra settings>/python_command.save`, as two lines: the command, then its arguments.
// Upstream hardcoded 'py' + '-<ver>' and derived the settings directory from %APPDATA%, which does
// not exist off Windows. Write the interpreter we actually resolved, to the directory Ghidra reads.
//
// The base directory mirrors what Ghidra itself resolves — upstream-build.gradle's
// resolveGhidraUserDir uses the identical three-way split:
//   macOS   ~/Library/ghidra
//   Windows %APPDATA%\ghidra              (falls back to ~/AppData/Roaming/ghidra)
//   other   $XDG_CONFIG_HOME/ghidra       (falls back to ~/.config/ghidra)
// [linux-port-fix] The first cut of this port wrote to `~/.ghidra/.ghidra_<ver>_<rel>`, which is
// wrong twice over: off Windows Ghidra never uses `~/.ghidra`, and the versioned leaf carries no
// leading dot. Confirmed against the running JVM, whose user_settings_dir was
// `<home>/.config/ghidra/ghidra_12.1.2_DEV` — note `_DEV`, straight from application.release.name.
export function ghidraUserBaseDir() {
  if (process.platform === 'darwin') return join(homedir(), 'Library', 'ghidra')
  if (process.platform === 'win32') {
    return join(process.env.APPDATA || join(homedir(), 'AppData', 'Roaming'), 'ghidra')
  }
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'ghidra')
}

// The versioned leaf inside that base. Prefer a directory Ghidra already created for this version:
// the on-disk release suffix is not always what we would guess (_DEV, _PUBLIC, _BETA), and inventing
// one drops python_command.save into a directory Ghidra never reads.
export function ghidraSettingsDir(home) {
  const v = readVersion(home)
  const prefix = 'ghidra_' + v.version
  const base = ghidraUserBaseDir()
  try {
    const matches = readdirSync(base).filter((n) => n.startsWith(prefix)).sort()
    if (matches.length) return join(base, matches.find((n) => n.includes('PUBLIC')) || matches[matches.length - 1])
  } catch { /* base 尚未创建 */ }
  return join(base, v.release ? prefix + '_' + v.release : prefix + '_PUBLIC')
}

// Where a Ghidra extension has to be installed for Ghidra to load it. This is the trap recorded in
// LINUX-PORT.md §3.1: on Linux the path is under XDG, not ~/.ghidra, and installing to the wrong
// directory fails *silently* — Ghidra starts normally with the class simply absent from the
// classpath. ghidra_doctor reports the resolved path so the mistake is visible.
export function ghidraUserExtensionDir(home) {
  return join(ghidraSettingsDir(home), 'Extensions')
}

function writePythonSave(home, pythonVer) {
  const cand = pythonCommand(pythonVer)
  try {
    const settingsDir = ghidraSettingsDir(home)
    mkdirSync(settingsDir, { recursive: true })
    writeFileSync(join(settingsDir, 'python_command.save'), cand.cmd + '\n' + cand.args.join(' ') + '\n')
  } catch { /* 写失败不致命 */ }
}

export async function startServer(gh, programName, config, onProgress) {
  const { projectDir, projectName } = projectPaths(config)
  cleanLocks(projectDir, projectName)
  // 运行时中间件（端口文件 / pid 文件 / 桥日志 / 脚本副本）也放插件数据根：<…>/.dsh-ghidra/run
  const data = ensureDataPaths()
  const base = join(data.root, 'run')
  mkdirSync(base, { recursive: true })
  const pidFile = join(base, 'server.pid')
  const stale = killStaleServers(projectDir, pidFile)
  if (stale > 0) onProgress('清理了 ' + stale + ' 个残留的 Ghidra 进程（它们占着项目锁）\n')
  const scriptsDir = join(base, 'scripts')
  mkdirSync(scriptsDir, { recursive: true })
  const scriptSrc = await readFile(fileURLToPath(new URL('../scripts/DecompileBridge.py', import.meta.url)), 'utf8')
  writeFileSync(join(scriptsDir, 'DecompileBridge.py'), scriptSrc)

  const portFile = join(base, 'port.txt')
  const logFile = join(base, 'bridge.log')
  try { rmSync(portFile, { force: true }) } catch { /* ignore */ }

  writePythonSave(gh.home, config.pythonVer)
  const env = envFor(gh.home, gh.nonAscii, base, logFile, config.pythonVer)
  const py = pythonCommand(config.pythonVer)
  // 直接调用 pyghidra_launcher.py（绕过 pyghidraRun.bat 的 cmd 包装层，进程可追踪）
  const launcher = join(gh.home, 'Ghidra', 'Features', 'PyGhidra', 'support', 'pyghidra_launcher.py')
  const args = [launcher, gh.home, '-H', '--console', projectDir, projectName, '-process', programName, '-noanalysis',
    '-scriptPath', scriptsDir, '-postScript', 'DecompileBridge.py', portFile, logFile]

  onProgress('启动 Ghidra 服务器（JVM 初始化约 20-40 秒）...\n')
  // headless 自己的日志（含最关键的 "Save succeeded / Save FAILED"）必须留下来：
  // 写侧改动是否真的落盘，只有它能给出权威答案。之前用 stdio:'ignore' 把它丢了。
  const headlessLog = join(base, 'headless.log')
  let logFd = null
  try {
    appendFileSync(headlessLog, '\n==== ' + new Date().toISOString() + ' start ' + programName + ' ====\n'
      + '# argv: ' + [py.cmd, ...py.args, ...args].map((a) => (/\s/.test(a) ? JSON.stringify(a) : a)).join(' ') + '\n')
    logFd = openSync(headlessLog, 'a')
  } catch { logFd = null }
  // [linux-port] spawn the interpreter we actually resolved, not a hardcoded `py`
  const child = spawn(py.cmd, [...py.args, ...args], {
    cwd: projectDir,
    windowsHide: true,
    stdio: logFd === null ? ['ignore', 'ignore', 'ignore'] : ['ignore', logFd, logFd],
    env,
  })
  if (logFd !== null) { try { closeSync(logFd) } catch { /* ignore */ } }

  const startupMs = config.serverStartupTimeoutMs || 180000
  const deadline = Date.now() + startupMs
  let port = null
  let serverPid = 0
  // pyghidra_launcher.py 拉起真正的 Ghidra（py -m pyghidra.ghidra_launch）后会自己 exit 0，
  // 且退出时机不确定（实测在 DSH 里 ~0.7s 就退了，而 JVM 要到 ~6s 才写出端口文件）。
  // 因此 **wrapper 退出绝不能当作失败**：唯一成功的判据是「端口文件出现 + ping 通」。
  while (Date.now() < deadline) {
    try {
      const text = readFileSync(portFile, 'utf8')
      const m = /(\d+)(?:\s+(\d+))?/.exec(text)
      if (m) { port = Number(m[1]); serverPid = m[2] ? Number(m[2]) : 0; break }
    } catch { /* 还没写出来 */ }
    await sleep(700)
  }
  if (!port) {
    killPid(child.pid)
    const hint = child.exitCode !== null
      ? '（launcher 已退出 exit=' + child.exitCode + ' —— 这是 pyghidra_launcher.py 的正常行为，不代表失败）'
      : ''
    throw new Error('Ghidra 服务器在 ' + Math.round(startupMs / 1000) + 's 内未就绪（未生成端口文件）' + hint + '，日志: ' + logFile)
  }
  try {
    await jsonRequest(port, { op: 'ping' }, 10000)
  } catch {
    killPid(serverPid || child.pid)
    throw new Error('Ghidra 服务器 ping 失败（端口 ' + port + '）')
  }
  if (serverPid) { try { writeFileSync(pidFile, String(serverPid)) } catch { /* ignore */ } }
  onProgress('服务器就绪，端口 ' + port + (serverPid ? '（pid ' + serverPid + '）' : '') + '\n')
  return { child, port, pid: serverPid, program: programName }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}
