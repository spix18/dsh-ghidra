// sync-installed.mjs — 把 vendored 源同步到各 profile 的已装副本，并逐文件校验 SHA256。
// 用途：改完 plugins/ghidra-bridge 下的源后必须运行，否则验收脚本（它们刻意加载**已装副本**
// 以复现 DSH 的真实解析路径）测的还是旧代码 —— 曾因此误判「修复无效」。
import { copyFileSync, mkdirSync, readFileSync, existsSync, rmSync, readdirSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const SRC = dirname(fileURLToPath(import.meta.url))
const ROOT = 'C:/Users/Administrator/.dsh/profiles'
const PROFILES = ['web', 'headless']
const FILES = ['index.js', 'client.js', 'package.json', 'cordis.patch.yml', 'README.md', 'icon.svg',
  'locale/en.json', 'locale/zh.json',
  'lib/paths.js', 'lib/ghidra.js', 'lib/run.js', 'lib/socket.js', 'lib/mcp.js', 'lib/mcp-tools.js',
  'lib/skill.js', 'skills/dsh-ghidra/SKILL.md', 'probe-skill-registry.mjs',
  'scripts/DecompileBridge.py']
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex')

let mismatches = 0
let copied = 0
for (const prof of PROFILES) {
  const dst = join(ROOT, prof, 'node_modules/dsh-ghidra')
  if (!existsSync(dst)) { console.log('SKIP ' + prof + '（该 profile 未安装本插件）'); continue }
  for (const f of FILES) {
    const s = join(SRC, f)
    const d = join(dst, f)
    mkdirSync(dirname(d), { recursive: true })
    copyFileSync(s, d)
    copied++
    const ok = sha(s) === sha(d)
    if (!ok) mismatches++
    console.log((ok ? 'OK   ' : 'DIFF ') + prof + '/' + f)
  }
  // 别把 __pycache__ 带进副本（Python 版本变化时会加载陈旧字节码）
  const pyc = join(dst, 'scripts', '__pycache__')
  if (existsSync(pyc)) { rmSync(pyc, { recursive: true, force: true }); console.log('rm   ' + prof + '/scripts/__pycache__') }
}
const stale = join(SRC, 'scripts', '__pycache__')
if (existsSync(stale)) rmSync(stale, { recursive: true, force: true })
console.log('synced ' + copied + ' files across ' + PROFILES.length + ' profiles, mismatches=' + mismatches)
process.exit(mismatches === 0 ? 0 : 1)
