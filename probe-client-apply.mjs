// 浏览器半回归：apply 必须绑定 configForms transport（历史上漏调 installFormTransport →
// formStore.ready 永远 false → Settings 分区配置区卡在 Loading…、字段不可编辑）。
// 用最小 React/模块加载器桩驱动 factory + apply，断言：
//   1) 模块加载不抛；2) apply 不抛；3) configForms.get('ghidra-bridge') 被调用（transport 已绑定）；
//   4) settings.section 注册成功（id/order/label 正确）；5) subscribe/effect 被登记（可响应更新）。
import { pathToFileURL } from 'node:url'

const dir = (process.argv[2] || 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra').replace(/[\\/]+$/, '')
const results = []
const check = (name, ok, detail) => { results.push({ name, ok }); console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  :: ' + detail : '')) }

// ---- 桩：React（createElement + useState/useEffect 直通）----
const React = {
  createElement: (type, props, ...children) => ({ type, props: props || {}, children }),
  useState: (init) => [typeof init === 'function' ? init() : init, () => {}],
  useEffect: () => {},
  useMemo: (fn) => fn(),
  useRef: (v) => ({ current: v }),
}
const fakeRequire = (name) => {
  if (name === 'react') return React
  throw new Error('unexpected require: ' + name)
}

// ---- 桩：模块加载器 ----
let mod = null
let docLayoutRegistered = null
const listeners = []
globalThis.window = {
  __ModuleLoader__: {
    load: ({ id, factory }) => {
      if (id !== 'dsh-ghidra') throw new Error('unexpected bundle id: ' + id)
      mod = factory(fakeRequire)
    },
  },
  document: { head: { appendChild() {}, contains: () => true } },
}

// ---- 桩：宿主 ctx ----
const calls = { configFormsGet: [], slotsInject: [], slotsRegister: [], effects: [] }
const fakeScope = {
  subscribe(fn) { listeners.push(fn); return () => {} },
  getSnapshot: () => ({ status: 'ready', writable: true, value: { pythonVer: '3.13' }, base: {}, user: {} }),
  set: async () => true,
  unset: async () => true,
}
const ctx = {
  slots: {
    inject(name, cb) { calls.slotsInject.push(name); return cb() },
    register(meta, comp) { calls.slotsRegister.push({ meta, comp }); return () => {} },
  },
  configForms: { get(ns) { calls.configFormsGet.push(ns); return fakeScope } },
  effect(fn) { calls.effects.push(fn); const d = fn(); return () => { try { d && d() } catch {} } },
  on: () => () => {},
}

// ---- 加载浏览器半 ----
try {
  await import(pathToFileURL(dir + '/client.js').href + '?probe=' + Date.now())
  check('浏览器半加载并注册 bundle', !!mod, mod ? Object.keys(mod).join(',') : 'no module')
} catch (e) {
  check('浏览器半加载并注册 bundle', false, String(e && e.message || e))
}

check('exports 含 inject/apply', !!mod && Array.isArray(mod.inject) && typeof mod.apply === 'function',
  mod ? 'inject=' + JSON.stringify(mod.inject) : '-')

if (mod && typeof mod.apply === 'function') {
  try {
    mod.apply(ctx)
    check('apply 未抛异常', true, '')
  } catch (e) {
    check('apply 未抛异常', false, String(e && e.message || e))
  }
  // 1) transport 绑定（本次修复点）
  check('configForms.get 以 ghidra-bridge 调用（transport 已绑定）',
    calls.configFormsGet.includes('ghidra-bridge'), 'calls=' + JSON.stringify(calls.configFormsGet))
  check('scope.subscribe 被登记（表单状态可响应）', listeners.length > 0, 'listeners=' + listeners.length)
  // 2) Settings 分区注册
  const reg = calls.slotsRegister.find((r) => r.meta && r.meta.name === 'settings.section')
  check('注册 settings.section slot', !!reg,
    reg ? 'id=' + reg.meta.id + ' order=' + reg.meta.order + ' label=' + reg.meta.label : 'missing')
  check('分区 id/order/label 正确', !!reg && reg.meta.id === 'ghidra' && reg.meta.label === 'Ghidra' && reg.meta.order === 210,
    reg ? JSON.stringify({ id: reg.meta.id, order: reg.meta.order, label: reg.meta.label }) : '-')
  check('不再注册 plugins.bundle.config（已迁出插件管理页）',
    !calls.slotsRegister.some((r) => r.meta && r.meta.name === 'plugins.bundle.config'), '')
  check('slots.inject 目标为 settings.section', calls.slotsInject.includes('settings.section'), JSON.stringify(calls.slotsInject))
  // 3) 组件可渲染（不抛）
  if (reg && typeof reg.comp === 'function') {
    try {
      const tree = reg.comp({ useGhidraStatus: (s) => s && s.status, useGhidraForm: (s) => s })
      check('分区组件可渲染', !!tree, 'root=' + (tree && tree.type))
    } catch (e) {
      check('分区组件可渲染', false, String(e && e.message || e))
    }
  }
}

console.log('')
const fails = results.filter((r) => !r.ok).length
console.log('=== ' + (fails ? 'CLIENT PROBE FAILED: ' + fails + ' fail(s)' : 'CLIENT PROBE PASSED: ' + results.length + '/' + results.length) + ' ===')
process.exit(fails ? 1 : 0)
