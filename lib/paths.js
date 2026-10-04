// 插件自有数据根 —— 让「关于这个插件的一切」都待在 DSH 插件树里：
//   <DSH_HOME>\profiles\<profile>\node_modules\dsh-ghidra-home\
//     ├── ghidra\        Ghidra 安装（Download Ghidra 解压到这里：ghidra_<ver>_PUBLIC）
//     ├── projects\      Ghidra 项目（导入缓存）
//     ├── logs\          MCP / 运行日志
//     └── run\           端口文件 / pid 文件 / 桥日志
//
// 为什么用 node_modules 下的兄弟目录（而不是包目录内部）：
//   dsh plugin add / npm install 会**替换** node_modules\dsh-ghidra 整个包目录，
//   放在包内的 Ghidra 安装会被下次插件更新抹掉；同级的 dsh-ghidra-home 不归 npm 管，
//   既满足「和别的 dsh 插件一起待在 node_modules」，又能跨插件升级存活。
//
// 为什么**项目目录不在这里**：Ghidra 的项目路径校验禁止任何以 '.' 开头的路径元素
//   （NamingUtilities.checkName → "Path element starting with '.' is not permitted"），
//   而 DSH_HOME 本身就叫 `.dsh` —— 因此**任何**位于 <DSH_HOME> 下的目录都不能当 Ghidra 项目目录
//   （实测：analyzeHeadless 直接 exit=1，报 ProjectLocator 校验失败）。
//   安装目录不受此限（Ghidra 只校验项目 locator），所以 Ghidra 安装、日志、运行时文件留在插件树里，
//   项目目录仍用 %TEMP%\dsh-ghidra-projects（或由 ghidraProjectDir 指定任意不含点元素的路径）。
import { existsSync, readdirSync, statSync, mkdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

export const DATA_DIR_NAME = 'dsh-ghidra-home'

// 本文件位于 <pluginDir>/lib/paths.js
const PLUGIN_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
// …/profiles/<profile>/node_modules
const OWN_NODE_MODULES = dirname(PLUGIN_DIR)

function dshHome() {
  if (process.env.DSH_HOME) return process.env.DSH_HOME
  const up = process.env.USERPROFILE || process.env.HOME || ''
  return up ? join(up, '.dsh') : ''
}

// web profile 的 node_modules 是跨 profile 的规范位置（用户指定：与其它 dsh 插件同处）
function webProfileRoot() {
  const h = dshHome()
  return h ? join(h, 'profiles', 'web', 'node_modules', DATA_DIR_NAME) : ''
}

/** 数据根：已存在的优先（自身 profile → web profile），否则在 web profile 下创建。 */
export function pluginDataRoot() {
  const own = join(OWN_NODE_MODULES, DATA_DIR_NAME)
  if (existsSync(own)) return own
  const web = webProfileRoot()
  if (web && existsSync(web)) return web
  // 缺省落点：web profile（用户指定）；web 不存在时退回自身 profile
  try {
    if (web && existsSync(dirname(web))) return web
  } catch { /* 忽略 */ }
  return own
}

/** 数据根下的标准子路径（不创建目录）。 */
export function dataPaths() {
  const root = pluginDataRoot()
  return {
    root,
    ghidraDir: join(root, 'ghidra'),
    logDir: join(root, 'logs'),
    runDir: join(root, 'run'),
  }
}

/** 缺省 Ghidra 项目目录：必须在 <DSH_HOME> 之外（见文件头：点元素会被 Ghidra 拒绝）。 */
export function defaultProjectDir() {
  return join(tmpdir(), 'dsh-ghidra-projects')
}

/** 确保数据根子目录存在，返回路径。 */
export function ensureDataPaths() {
  const p = dataPaths()
  for (const d of [p.root, p.ghidraDir, p.logDir, p.runDir]) {
    try { mkdirSync(d, { recursive: true }) } catch { /* 忽略 */ }
  }
  return p
}

const isHome = (p) => existsSync(join(p, 'support', 'analyzeHeadless.bat'))

/** 数据根里已安装的 Ghidra：ghidraDir 本身或其中最新的 ghidra_* 目录。 */
export function ghidraInDataRoot() {
  const { ghidraDir } = dataPaths()
  if (isHome(ghidraDir)) return ghidraDir
  try {
    const found = readdirSync(ghidraDir)
      .filter((n) => /^ghidra/i.test(n))
      .map((n) => join(ghidraDir, n))
      .filter(isHome)
      .map((p) => ({ p, m: statSync(p).mtimeMs }))
      .sort((a, b) => b.m - a.m)
    if (found.length) return found[0].p
  } catch { /* 目录还不存在 */ }
  return null
}
