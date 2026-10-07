// 开发/验收脚本共用的路径解析。
//
// 为什么需要它：verify-*.mjs / probe-*.mjs 刻意加载**已装副本**（profiles/<p>/node_modules/dsh-ghidra）
// 以复现 DSH 的真实解析路径，而不是加载源码树 —— 测源码树会给出假通过。于是每个脚本都得先
// 找到那个副本，而它们原本把 `C:/Users/<user>/.dsh/...` 写死在文件里：整套验收在
// Linux/macOS 上直接 ENOENT。这里把「DSH_HOME 从哪来、副本在哪、宿主 DSH 检出去哪找」收成一处。
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const DSH_HOME = process.env.DSH_HOME || join(process.env.USERPROFILE || homedir(), '.dsh')
export const PROFILES_ROOT = join(DSH_HOME, 'profiles')
const HERE = dirname(fileURLToPath(import.meta.url))
export const REPO_ROOT = dirname(HERE)

export const fileUrl = (p) => pathToFileURL(p).href

// 已装副本目录（DSH 真正 require 的那一份）。缺省 web profile。
export function installedDir(profile = 'web') {
  return join(PROFILES_ROOT, profile, 'node_modules', 'dsh-ghidra')
}

// vendored 源（生成器产出的那套），用作期望清单的 ground truth。
// 优先本机 plugins/ghidra-bridge 检出；纯 npm 安装的用户没有它，就回退到本仓库。
export function sourceDir() {
  const env = (process.env.DSH_GHIDRA_SOURCE || '').trim()
  if (env && existsSync(env)) return env
  const vendored = join(DSH_HOME, 'plugins', 'ghidra-bridge')
  return existsSync(vendored) ? vendored : REPO_ROOT
}

// 宿主 DSH 本人的检出位置。安装方式不同（全局 npm / nvm / pnpm / 发行版包），
// 所以逐个试，而不是写死一台机器的路径。可用 DSH_CHECKOUT 覆盖。
export function resolveDsh() {
  const env = (process.env.DSH_CHECKOUT || '').trim()
  if (env && existsSync(env)) return env
  const candidates = [
    process.env.APPDATA ? join(process.env.APPDATA, 'npm', 'node_modules', '@deepseek-ai', 'dsh') : '',
    join(homedir(), 'AppData', 'Roaming', 'npm', 'node_modules', '@deepseek-ai', 'dsh'),
    '/usr/lib/node_modules/@deepseek-ai/dsh',
    '/usr/local/lib/node_modules/@deepseek-ai/dsh',
    join(homedir(), '.npm-global', 'lib', 'node_modules', '@deepseek-ai', 'dsh'),
    join(homedir(), '.local', 'share', 'pnpm', 'global', '5', 'node_modules', '@deepseek-ai', 'dsh'),
  ].filter(Boolean)
  for (const c of candidates) if (existsSync(c)) return c
  return candidates[0]
}

// 宿主真实加载的 dsh-tools（probe 脚本要对着它验证 defineTool 的行为，不能用桩）。
export function dshToolsEntry() {
  return join(resolveDsh(), 'node_modules', '@deepseek-ai', 'dsh-tools', 'lib', 'index.js')
}
