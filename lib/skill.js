// lib/skill.js — 把随包的 skills/dsh-ghidra/SKILL.md 读成 ctx.skills.register() 的定义。
//
// 为什么随包注册而不是让用户自己配 customSkillDirs：
//   · 技能要跟着插件走 —— 装上插件就有技能，卸载就没了，不需要用户额外配置；
//   · dsh-skill-filesystem 的默认根（project / user / bundled）**不会扫 node_modules 里的插件目录**，
//     所以放在包里的 SKILL.md 光有文件是永远不会被发现的，必须走运行时注册。
// 对照：REA（morluto/rea）也把 skills/ 随包发，setup 时只登记它检测到的 agent 集成。
//
// frontmatter 只做行级解析：文件由本仓库维护，description/whenToUse 都保持单行，
// 因此不需要引入 YAML 依赖（避免为一个文件多一个运行时依赖）。
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
export const SKILL_NAME = 'dsh-ghidra'
export const SKILL_FILE = join(HERE, '..', 'skills', SKILL_NAME, 'SKILL.md')

const FRONTMATTER = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/

function field(frontmatter, key) {
  const m = new RegExp('^' + key + ':[ \\t]*(.*)$', 'm').exec(frontmatter)
  if (!m) return undefined
  let v = m[1].trim()
  if (v.length >= 2 && ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))) {
    v = v.slice(1, -1)
  }
  return v || undefined
}

/**
 * 读取并解析随包 SKILL.md。任何问题（文件缺失 / frontmatter 缺失 / 必填项为空）都返回 null ——
 * 调用方只记一条日志，绝不让技能问题拖垮插件加载。
 * @returns {{name: string, description: string, whenToUse?: string, content: string, source: string} | null}
 */
export function loadSkillDefinition() {
  let raw
  try { raw = readFileSync(SKILL_FILE, 'utf8') } catch { return null }
  const m = FRONTMATTER.exec(raw)
  if (!m) return null
  const name = field(m[1], 'name')
  const description = field(m[1], 'description')
  const content = raw.slice(m[0].length).trim()
  // 必填项与 dsh-skill 的 validateRuntimeSkill 对齐（name 还须匹配 /^[a-z0-9]+(?:-[a-z0-9]+)*$/）
  if (!name || !description || !content) return null
  const definition = { name, description, content, source: 'runtime' }
  const whenToUse = field(m[1], 'whenToUse')
  if (whenToUse) definition.whenToUse = whenToUse
  return definition
}
