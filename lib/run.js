// 进程工具：进程树清理 + Windows .cmd/.bat 引号处理
import { spawn, spawnSync } from 'node:child_process'

// [linux-port] taskkill /T kills the whole tree; the bare process.kill() used off Windows only
// killed the direct child, orphaning the JVM it spawned. That JVM kept holding the Ghidra project
// lock, so the next start failed with a stale-lock error. Collect descendants with pgrep -P first,
// deepest-last so children die before parents re-parent and escape the walk.
function collectTree(pid) {
  const out = []
  try {
    const r = spawnSync('pgrep', ['-P', String(pid)], { encoding: 'utf8', timeout: 10000 })
    for (const s of String(r.stdout || '').split(/\s+/)) {
      if (/^\d+$/.test(s)) out.push(...collectTree(Number(s)))
    }
  } catch { /* pgrep missing or no children */ }
  out.push(pid)
  return out
}

export function killPid(pid) {
  if (!pid) return
  if (process.platform === 'win32') {
    try { process.kill(pid) } catch { /* 已退出 */ }
    try { spawn('taskkill', ['/pid', String(pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' }) } catch { /* ignore */ }
    return
  }
  // Snapshot the tree once: after SIGTERM the children may re-parent, so re-walking would miss them.
  const tree = collectTree(pid)
  for (const p of tree) {
    // SIGTERM first so Ghidra gets to flush and save; escalate only if it ignores us.
    try { process.kill(p, 'SIGTERM') } catch { /* 已退出 */ }
  }
  setTimeout(() => {
    for (const p of tree) {
      try { process.kill(p, 0); process.kill(p, 'SIGKILL') } catch { /* gone */ }
    }
  }, 3000).unref?.()
}

export function pidAlive(pid) {
  if (!pid) return false
  if (process.platform === 'win32') {
    try {
      const r = spawnSync('tasklist', ['/FI', 'PID eq ' + pid, '/NH'], { encoding: 'utf8', windowsHide: true })
      return String(r.stdout || '').includes(String(pid))
    } catch { return false }
  }
  try { process.kill(pid, 0); return true } catch { return false }
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function cmdQuote(a) {
  if (/[\s"&|<>^()%!]/.test(a)) return '"' + a.replace(/"/g, '\\"') + '"'
  return a
}

export function makeSpawnArgs(cmd, args) {
  if (process.platform === 'win32' && /\.(cmd|bat)$/i.test(cmd)) {
    const line = '"' + cmd + '"' + (args.length ? ' ' + args.map(cmdQuote).join(' ') : '')
    return { command: line, args: [], options: { shell: true } }
  }
  return { command: cmd, args, options: {} }
}

export function runProcess(cmd, args, { cwd, timeoutMs, signal, maxOutputChars = 100000, env }) {
  return new Promise((resolve, reject) => {
    const { command, args: cargs, options } = makeSpawnArgs(cmd, args)
    let child
    try {
      child = spawn(command, cargs, { cwd, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env: env || process.env, ...options })
    } catch (err) { reject(err); return }
    let stdout = '', stderr = '', truncated = false, settled = false
    const append = (buf, target) => {
      const s = buf.toString('utf8')
      if (target.length + s.length > maxOutputChars) { target += s.slice(0, Math.max(0, maxOutputChars - target.length)); truncated = true }
      else target += s
      return target
    }
    child.stdout.on('data', (d) => { stdout = append(d, stdout) })
    child.stderr.on('data', (d) => { stderr = append(d, stderr) })
    let timer = null
    if (timeoutMs && timeoutMs > 0) {
      timer = setTimeout(() => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        killPid(child.pid)
        resolve({ exitCode: -1, stdout, stderr, truncated, timedOut: true })
      }, timeoutMs)
    }
    const onAbort = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      killPid(child.pid)
      reject(new Error('aborted'))
    }
    if (signal) {
      if (signal.aborted) { onAbort(); return }
      signal.addEventListener('abort', onAbort, { once: true })
    }
    child.on('error', (err) => { if (settled) return; settled = true; clearTimeout(timer); if (signal) signal.removeEventListener('abort', onAbort); reject(err) })
    child.on('close', (code) => { if (settled) return; settled = true; clearTimeout(timer); if (signal) signal.removeEventListener('abort', onAbort); resolve({ exitCode: code, stdout, stderr, truncated, timedOut: false }) })
  })
}
