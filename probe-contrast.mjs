// probe-contrast.mjs — 对比度自动化守卫（WCAG AA）
//
// 为什么这样写：token 的「值」属于宿主（dsh-client-ui-theme），写死在探针里会随宿主漂移而失效。
// 所以本探针**在运行时从宿主主题 CSS 里解析 token 值**（light = body{}，dark = body[data-ds-dark-theme]{}），
// 顺着 var() 链与 color-mix() 解出真实颜色，再对插件 client.js 里实际使用的每组前景/背景算对比度，
// 断言 ≥ 4.5:1。宿主换色或插件改色，任一变化都会被这个探针重新评估。
//
// 用法：node probe-contrast.mjs [dshRoot] [pluginDir]
import { readFileSync, existsSync } from 'node:fs'

const DSH_ROOT = (process.argv[2] || 'C:/Users/Administrator/AppData/Roaming/npm/node_modules/@deepseek-ai/dsh').replace(/[\\/]+$/, '')
const PLUGIN = (process.argv[3] || 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra').replace(/[\\/]+$/, '')
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

// ---- 颜色解析：var() 链 + color-mix(in srgb, A N%, B) ----
const hex2rgb = (h) => { const s = h.replace('#', ''); const f = s.length === 3 ? s.split('').map((c) => c + c).join('') : s; return [0, 2, 4].map((i) => parseInt(f.slice(i, i + 2), 16)) }
const rgb2hex = (c) => '#' + c.map((v) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0')).join('')
const lum = (hex) => { const c = hex2rgb(hex).map((v) => v / 255).map((v) => (v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4))); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2] }
const contrast = (a, b) => { const l1 = lum(a), l2 = lum(b); const [hi, lo] = l1 > l2 ? [l1, l2] : [l2, l1]; return (hi + 0.05) / (lo + 0.05) }

const resolve = (value, map, depth = 0) => {
  if (depth > 12 || value == null) return null
  const v = String(value).trim()
  const mix = v.match(/^color-mix\(in srgb,\s*(.+?)\s+([\d.]+)%\s*,\s*(.+)\)$/i)
  if (mix) {
    const a = resolve(mix[1], map, depth + 1)
    const b = resolve(mix[3], map, depth + 1)
    if (!a || !b) return null
    const p = parseFloat(mix[2]) / 100
    const A = hex2rgb(a), B = hex2rgb(b)
    return rgb2hex(A.map((x, i) => x * p + B[i] * (1 - p)))
  }
  const va = v.match(/^var\((--[a-z0-9-]+)(?:\s*,\s*(.+))?\)$/i)
  if (va) {
    if (map[va[1]] !== undefined) return resolve(map[va[1]], map, depth + 1)
    return va[2] ? resolve(va[2], map, depth + 1) : null
  }
  if (/^#[0-9a-fA-F]{3,8}$/.test(v)) return v.length === 9 ? v.slice(0, 7) : v
  return null
}

// ---- 插件实际使用的颜色对（expr 必须在 client.js 里出现，防止探针与代码脱节）----
const src = readFileSync(PLUGIN + '/client.js', 'utf8')
const PAIRS = [
  ['title / row value   label-primary on bg-layer-2', { t: 'label-primary' }, 'bg-layer-2', "color: 'var(--dsw-alias-label-primary)'"],
  ['hint / key / caption label-secondary on bg-layer-2', { t: 'label-secondary' }, 'bg-layer-2', "color: 'var(--dsw-alias-label-secondary)'"],
  ['badge               label-secondary on bg-layer-3', { t: 'label-secondary' }, 'bg-layer-3', "background: 'var(--dsw-alias-bg-layer-3)'"],
  ['OK / success text   success@55% + label-primary', { mix: ['state-success-primary', 55, 'label-primary'] }, 'bg-layer-2', 'color-mix(in srgb, var(--dsw-alias-state-success-primary) 55%, var(--dsw-alias-label-primary))'],
  ['error text          error@75% + label-primary', { mix: ['state-error-primary', 75, 'label-primary'] }, 'bg-layer-2', 'color-mix(in srgb, var(--dsw-alias-state-error-primary) 75%, var(--dsw-alias-label-primary))'],
  ['IDLE text           idle@40% + label-primary', { mix: ['state-idle-primary', 40, 'label-primary'] }, 'bg-layer-2', 'color-mix(in srgb, var(--dsw-alias-state-idle-primary) 40%, var(--dsw-alias-label-primary))'],
  ['dot badge           warn@70% + label-primary on bg-layer-3', { mix: ['state-warn-label', 70, 'label-primary'] }, 'bg-layer-3', 'color-mix(in srgb, var(--dsw-alias-state-warn-label) 70%, var(--dsw-alias-label-primary))'],
  ['primary button text fg on button-primary-fill', { t: 'label-primary-foreground' }, 'button-primary-fill', "color: 'var(--dsw-alias-label-primary-foreground)'"],
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
  for (const [label, spec, bgToken, expr] of PAIRS) {
    if (!src.includes(expr)) { check('[' + themeName + '] 代码仍在使用该表达式', false, expr); failures++; continue }
    const fg = resolveSpec(spec, map)
    const bg = resolve('var(--dsw-alias-' + bgToken + ')', map)
    if (!fg || !bg) { check('[' + themeName + '] ' + label, false, 'token 未定义或无法解析: fg=' + fg + ' bg=' + bg); failures++; continue }
    const r = contrast(fg, bg)
    const ok = r >= 4.5
    if (!ok) failures++
    check('[' + themeName + '] ' + label + '  ' + fg + ' on ' + bg, ok, r.toFixed(2) + ':1' + (ok ? '' : '  < 4.5:1'))
  }
}

console.log('')
console.log('=== ' + (failures ? 'CONTRAST PROBE FAILED: ' + failures + ' fail(s)' : 'CONTRAST PROBE PASSED: ' + results.length + '/' + results.length + ' (all pairs >= 4.5:1 in both themes)') + ' ===')
process.exit(failures ? 1 : 0)
