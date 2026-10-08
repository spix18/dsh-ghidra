// probe-contrast.mjs — 对比度自动化守卫（WCAG AA）
//
// 为什么这样写：token 的「值」属于宿主（dsh-client-ui-theme），写死在探针里会随宿主漂移而失效。
// 所以本探针**在运行时从宿主主题 CSS 里解析 token 值**（light = body{}，dark = body[ds-dark-theme]{}），
// 顺着 var() 链与 color-mix() 解出真实颜色，再对插件 client.js 里实际使用的每组前景/背景算对比度，
// 断言 ≥ 4.5:1。宿主换色或插件改色，任一变化都会被这个探针重新评估。
//
// 关于 alpha（2026-10-08 修复）：宿主大量使用带 alpha 的 token，例如 --dsw-alias-border-l3 = #0000001f。
// 早先的实现遇到 8 位十六进制会 `v.slice(0, 7)` 把 alpha 字节丢掉，于是 12% 的黑色被当成纯黑算成 21:1 —— 
// **任何基于 alpha 回归都会静默通过**。现在解析结果一律携带 alpha，算对比度前先把前景按 alpha 合成到背景上。
//
// 关于控件边框（不计入断言）：宿主最强的边框 token 是 --dsw-alias-border-l4，合成后对卡片只有 1.45:1（light）
// / 1.91:1（dark），而且 light 下 bg-layer-1/2/3 与 bg-base 全是 #ffffff，输入框的填充与卡片完全无法区分。
// 也就是说 **3:1 的 WCAG 1.4.11 控件边界在宿主设计系统里根本达不到**，不是本插件能单方面修的（把边框改成
// label 级颜色会让插件长得不像宿主，那是更严重的问题）。因此这一段只**测量并打印**，供将来宿主改版时对比，
// 不产生 PASS/FAIL —— 断言一个宿主注定达不到的目标，只会逼后来者把探针改松。
//
// 用法：node probe-contrast.mjs [dshRoot] [pluginDir]
import { readFileSync, existsSync } from 'node:fs'
import { installedDir, resolveDsh } from './lib/dev-env.mjs'

const DSH_ROOT = (process.argv[2] || resolveDsh()).replace(/[\\/]+$/, '')
const PLUGIN = (process.argv[3] || installedDir('web')).replace(/[\\/]+$/, '')
const THEME = DSH_ROOT + '/node_modules/@deepseek-ai/dsh-client-ui-theme/lib/client.js'

const results = []
const check = (name, ok, detail) => { results.push({ name, ok }); console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  :: ' + detail : '')) }

// ---- 读宿主主题：把所有含 --dsw- 的 CSS 字符串字面量拼起来 ----
if (!existsSync(THEME)) {
  console.log('FAIL  找到宿主主题文件  :: ' + THEME)
  process.exit(1)
}
const raw = readFileSync(THEME, 'utf8')
const css = [...raw.matchAll(/"((?:[^"\\]|\\.)*)"/g)]
  .map((m) => m[1])
  .filter((s) => s.includes('--dsw-alias-'))
  .join('\n')
check('解析到宿主主题 CSS', css.length > 1000, css.length + ' chars')

const slice = (text, startMarker, endMarker) => {
  const i = text.indexOf(startMarker)
  if (i < 0) return null
  const j = endMarker ? text.indexOf(endMarker, i + startMarker.length) : text.indexOf('}', i)
  return text.slice(i, j < 0 ? text.length : j)
}
const decls = (text) => {
  const out = {}
  if (!text) return out
  for (const m of text.matchAll(/--([a-z0-9-]+)\s*:\s*([^;}]+)/g)) out['--' + m[1]] = m[2].trim()
  return out
}

const LIGHT = {
  ...decls(slice(css, 'body{--dsw-static-amber-100:', 'body[data-ds-dark-theme]{--dsw-static-amber-100:')),
  ...decls(slice(css, 'body{--dsw-alias-bg-base:', 'body[data-ds-dark-theme]{--dsw-alias-bg-base:')),
}
const DARK = {
  ...decls(slice(css, 'body[data-ds-dark-theme]{--dsw-static-amber-100:')),
  ...decls(slice(css, 'body[data-ds-dark-theme]{--dsw-alias-bg-base:')),
}
check('light 主题块解析出 token', Object.keys(LIGHT).length > 50, Object.keys(LIGHT).length + ' decls')
check('dark 主题块解析出 token', Object.keys(DARK).length > 50, Object.keys(DARK).length + ' decls')

// ---- 颜色解析：var() 链 + color-mix(in srgb, A N%, B)，结果一律带 alpha ----
// 颜色一律用 [r,g,b,a]（a ∈ [0,1]）表示；十六进制 3/4/6/8 位都支持。
const parseHex = (h) => {
  const s = h.replace('#', '')
  if (s.length === 3 || s.length === 4) {
    const f = s.split('').map((c) => c + c).join('')
    return [0, 2, 4].map((i) => parseInt(f.slice(i, i + 2), 16)).concat([s.length === 4 ? parseInt(f.slice(6, 8), 16) / 255 : 1])
  }
  return [0, 2, 4].map((i) => parseInt(s.slice(i, i + 2), 16)).concat([s.length === 8 ? parseInt(s.slice(6, 8), 16) / 255 : 1])
}
const rgb2hex = (c) => '#' + c.slice(0, 3).map((v) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0')).join('')
const fmt = (c) => rgb2hex(c) + (c[3] < 1 ? ' a=' + c[3].toFixed(2) : '')
// 把可能半透明的 fg 合成到（不透明或半透明的）bg 上
const over = (fg, bg) => fg.slice(0, 3).map((v, i) => v * fg[3] + bg[i] * (1 - fg[3]))
const lum = (c) => { const s = c.slice(0, 3).map((v) => v / 255).map((v) => (v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4))); return 0.2126 * s[0] + 0.7152 * s[1] + 0.0722 * s[2] }
const contrast = (fg, bg) => { const a = lum(over(fg, bg)), b = lum(bg); const [hi, lo] = a > b ? [a, b] : [b, a]; return (hi + 0.05) / (lo + 0.05) }

const resolve = (value, map, depth = 0) => {
  if (depth > 12 || value == null) return null
  const v = String(value).trim()
  const mix = v.match(/^color-mix\(in srgb,\s*(.+?)\s+([\d.]+)%\s*,\s*(.+)\)$/i)
  if (mix) {
    const a = resolve(mix[1], map, depth + 1)
    const b = resolve(mix[3], map, depth + 1)
    if (!a || !b) return null
    const p = parseFloat(mix[2]) / 100
    const alpha = a[3] * p + b[3] * (1 - p)
    if (alpha <= 0) return [0, 0, 0, 0]
    // 预乘再除：两个半透明色混合时，直接按分量插值会把未预乘的 rgb 混错
    const rgb = [0, 1, 2].map((i) => (a[i] * a[3] * p + b[i] * b[3] * (1 - p)) / alpha)
    return rgb.concat([alpha])
  }
  const va = v.match(/^var\((--[a-z0-9-]+)(?:\s*,\s*(.+))?\)$/i)
  if (va) {
    if (map[va[1]] !== undefined) return resolve(map[va[1]], map, depth + 1)
    return va[2] ? resolve(va[2], map, depth + 1) : null
  }
  if (/^#[0-9a-fA-F]{3,8}$/.test(v)) return parseHex(v)
  return null
}

// ---- 插件实际使用的颜色对（expr 必须在 client.js 里出现，防止探针与代码脱节）----
// need：文本 4.5（WCAG 1.4.3 AA），图标/非文本 3.0（1.4.11）。
const src = readFileSync(PLUGIN + '/client.js', 'utf8')
const PAIRS = [
  ['title / row value   label-primary on bg-layer-2', { t: 'label-primary' }, 'bg-layer-2', "color: 'var(--dsw-alias-label-primary)'", 4.5],
  ['hint / key / caption label-secondary on bg-layer-2', { t: 'label-secondary' }, 'bg-layer-2', "color: 'var(--dsw-alias-label-secondary)'", 4.5],
  ['badge               label-secondary on bg-layer-3', { t: 'label-secondary' }, 'bg-layer-3', "background: 'var(--dsw-alias-bg-layer-3)'", 4.5],
  ['OK / success text   success@55% + label-primary', { mix: ['state-success-primary', 55, 'label-primary'] }, 'bg-layer-2', 'color-mix(in srgb, var(--dsw-alias-state-success-primary) 55%, var(--dsw-alias-label-primary))', 4.5],
  ['error text          error@75% + label-primary', { mix: ['state-error-primary', 75, 'label-primary'] }, 'bg-layer-2', 'color-mix(in srgb, var(--dsw-alias-state-error-primary) 75%, var(--dsw-alias-label-primary))', 4.5],
  ['IDLE text           idle@40% + label-primary', { mix: ['state-idle-primary', 40, 'label-primary'] }, 'bg-layer-2', 'color-mix(in srgb, var(--dsw-alias-state-idle-primary) 40%, var(--dsw-alias-label-primary))', 4.5],
  ['dot badge           warn@70% + label-primary on bg-layer-3', { mix: ['state-warn-label', 70, 'label-primary'] }, 'bg-layer-3', 'color-mix(in srgb, var(--dsw-alias-state-warn-label) 70%, var(--dsw-alias-label-primary))', 4.5],
  ['primary button text fg on button-primary-fill', { t: 'label-primary-foreground' }, 'button-primary-fill', "color: 'var(--dsw-alias-label-primary-foreground)'", 4.5],
  // --- 2026-10-08 补测：三组原本被漏掉的组合 ---
  ['override badge      brand-primary on card bg-layer-2', { t: 'brand-primary' }, 'bg-layer-2', "color: 'var(--dsw-alias-brand-primary)'", 4.5],
  ['folder icon         menu-icon on card bg-layer-2', { t: 'menu-icon' }, 'bg-layer-2', "color: 'var(--dsw-alias-menu-icon)'", 3.0],
  ['input text          label-primary on input bg-layer-3', { t: 'label-primary' }, 'bg-layer-3', "color: 'var(--dsw-alias-label-primary)', flex: 1", 4.5],
]

const resolveSpec = (spec, map) => spec.t ? resolve('var(--dsw-alias-' + spec.t + ')', map) : resolve('color-mix(in srgb, var(--dsw-alias-' + spec.mix[0] + ') ' + spec.mix[1] + '%, var(--dsw-alias-' + spec.mix[2] + '))', map)

let failures = 0

// ---- 结构守卫：client.js 引用的每个 --dsw-alias-* token 都必须由宿主真实定义 ----
// 这条守卫专治「宿主只引用、从不定义」的幽灵 token：引用未定义 token 的声明会被浏览器整条丢弃，
// 颜色静默回退成继承值（--dsw-alias-label-error 就是这么被发现的）。
const used = [...new Set([...src.matchAll(/--dsw-alias-[a-z0-9-]+/g)].map((m) => m[0]))].sort()
const undefLight = used.filter((t) => LIGHT[t] === undefined)
const undefDark = used.filter((t) => DARK[t] === undefined)
check('client.js 引用的 ' + used.length + ' 个 token 全部由宿主定义（light）', undefLight.length === 0, undefLight.join(', ') || 'none missing')
check('client.js 引用的 ' + used.length + ' 个 token 全部由宿主定义（dark）', undefDark.length === 0, undefDark.join(', ') || 'none missing')
if (undefLight.length || undefDark.length) failures++

for (const [themeName, map] of [['light', LIGHT], ['dark', DARK]]) {
  console.log('')
  console.log('--- ' + themeName.toUpperCase() + ' ---')
  for (const [label, spec, bgToken, expr, need] of PAIRS) {
    if (!src.includes(expr)) { check('[' + themeName + '] 代码仍在使用该表达式', false, expr); failures++; continue }
    const fg = resolveSpec(spec, map)
    const bg = resolve('var(--dsw-alias-' + bgToken + ')', map)
    if (!fg || !bg) { check('[' + themeName + '] ' + label, false, 'token 未定义或无法解析: fg=' + (fg && fmt(fg)) + ' bg=' + (bg && fmt(bg))); failures++; continue }
    const r = contrast(fg, bg)
    const ok = r >= need
    if (!ok) failures++
    check('[' + themeName + '] ' + label + '  ' + fmt(fg) + ' on ' + fmt(bg), ok, r.toFixed(2) + ':1' + (ok ? '' : '  < ' + need + ':1'))
  }

  // ---- 测量但不断言：控件边界对比度（WCAG 1.4.11 参考线 3:1）----
  // 见文件头：宿主最强的边框 token 也够不到 3:1，这不是本插件能单方面解决的问题。
  console.log('  -- info: control boundary (WCAG 1.4.11 reference 3:1, NOT asserted) --')
  const card = resolve('var(--dsw-alias-bg-layer-2)', map)
  const inputBg = resolve('var(--dsw-alias-bg-layer-3)', map)
  if (card && inputBg) {
    console.log('     input fill vs card fill            ' + contrast(inputBg, card).toFixed(2) + ':1   (' + fmt(inputBg) + ' vs ' + fmt(card) + ')')
    for (const bt of ['border-l1', 'border-l2', 'border-l3', 'border-l4']) {
      const b = resolve('var(--dsw-alias-' + bt + ')', map)
      if (!b) continue
      console.log('     ' + bt.padEnd(10) + ' over card / over input   ' + contrast(b, card).toFixed(2) + ':1 / ' + contrast(b, inputBg).toFixed(2) + ':1   (' + fmt(b) + ')')
    }
  }
}

console.log('')
console.log('=== ' + (failures ? 'CONTRAST PROBE FAILED: ' + failures + ' fail(s)' : 'CONTRAST PROBE PASSED: ' + results.length + '/' + results.length + ' (all asserted pairs meet their bar in both themes)') + ' ===')
process.exit(failures ? 1 : 0)
