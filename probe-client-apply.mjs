// 浏览器半回归：apply 必须绑定 configForms transport（历史上漏调 installFormTransport →
// formStore.ready 永远 false → Settings 分区配置区卡在 Loading…、字段不可编辑）。
// 用最小 React/模块加载器桩驱动 factory + apply，断言：
//   1) 模块加载不抛；2) apply 不抛；3) configForms.get('ghidra-bridge') 被调用（transport 已绑定）；
//   4) settings.section 注册成功（id/order/label 正确）；5) subscribe/effect 被登记（可响应更新）。
import { pathToFileURL } from 'node:url'
import { readFileSync } from 'node:fs'

const dir = (process.argv[2] || 'C:/Users/Administrator/.dsh/profiles/web/node_modules/dsh-ghidra').replace(/[\\/]+$/, '')
const results = []
const check = (name, ok, detail) => { results.push({ name, ok }); console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  :: ' + detail : '')) }

// ---- 桩：React（createElement + useState/useEffect 直通；effect 真的跑，ref 真的挂）----
const dom = { showModal: 0, close: 0, cleanups: [], effectError: null, pending: [] }
const flushEffects = () => {
  const q = dom.pending.splice(0)
  for (const fn of q) {
    try {
      const c = fn()
      if (typeof c === 'function') dom.cleanups.push(c)
    } catch (e) { dom.effectError = String(e && e.message || e) }
  }
}
const React = {
  createElement: (type, props, ...children) => {
    const node = { type, props: props || {}, children }
    // 函数组件真的被调用（否则 BrowseDialog/IconFolder 这类嵌套组件不会渲染出 DOM 节点）
    if (typeof type === 'function') return type(node.props)
    // 原生 <dialog> 的 DOM 替身：只实现真实 HTMLDialogElement 有的 showModal/close/open
    if (type === 'dialog' && node.props.ref) {
      const el = {
        open: false,
        showModal() { dom.showModal++; this.open = true },
        close() { dom.close++; this.open = false },
      }
      node.props.ref.current = el
    }
    return node
  },
  useState: (init) => [typeof init === 'function' ? init() : init, () => {}],
  // 真实 React 时序：effect 在 commit（ref 已挂）之后才跑，所以先入队，由 flushEffects() 统一执行
  useEffect: (fn) => { dom.pending.push(fn) },
  useMemo: (fn) => fn(),
  useRef: (v) => ({ current: v }),
  memo: (c) => c,
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
  // 3) 组件可渲染（不抛）——用宿主真实的 props 形状（renderSlot 只传 { close }）
  if (reg && typeof reg.comp === 'function') {
    try {
      const tree = reg.comp({ close: () => {} })
      check('分区组件可渲染', !!tree, 'root=' + (tree && tree.type))
    } catch (e) {
      check('分区组件可渲染', false, String(e && e.message || e))
    }
  }
  // 3b) 原生对话框生命周期（行为级：点 Browse… → 重渲染 → <dialog> 挂载并 showModal）
  const walk = (node, visit) => {
    if (!node || typeof node !== 'object') return
    visit(node)
    for (const c of node.children || []) {
      if (Array.isArray(c)) c.forEach((x) => walk(x, visit))
      else walk(c, visit)
    }
  }
  const findButton = (tree, text) => {
    let found = null
    walk(tree, (n) => {
      if (found || n.type !== 'button') return
      const label = (n.children || []).filter((x) => typeof x === 'string').join('')
      if (label.includes(text)) found = n
    })
    return found
  }
  if (reg && typeof reg.comp === 'function') {
    const tree1 = reg.comp({ close: () => {} }); flushEffects()
    const browseBtn = findButton(tree1, 'Browse')
    check('配置区渲染出 Browse… 按钮', !!browseBtn, browseBtn ? '' : 'not found')
    if (browseBtn) {
      dom.showModal = 0
      try { browseBtn.props.onClick() } catch (e) { /* ignore */ }
      const tree2 = reg.comp({ close: () => {} }); flushEffects()
      let dialogNode = null
      walk(tree2, (n) => { if (!dialogNode && n.type === 'dialog') dialogNode = n })
      check('打开后渲染原生 <dialog>', !!dialogNode, dialogNode ? '' : 'no dialog node')
      check('挂载即调用 showModal()（陷阱/Esc/焦点归还交给浏览器）', dom.showModal === 1, 'showModal=' + dom.showModal)
      check('对话框 effect 未抛错', !dom.effectError, dom.effectError || '')
      const cancelBtn = findButton(tree2, 'Cancel')
      if (cancelBtn) { try { cancelBtn.props.onClick() } catch (e) { /* ignore */ } }
      let stillOpen = false
      walk(reg.comp({ close: () => {} }), (n) => { if (n.type === 'dialog') stillOpen = true })
      check('Cancel 关闭对话框（状态回到关闭）', !stillOpen, stillOpen ? 'dialog still mounted' : '')
    }
  }
  // 4) 第三轮 /audit 回归守卫（源码级：无 DOM 桩，断言结构性契约不被改回去）
  let src = ''
  try { src = readFileSync(dir + '/client.js', 'utf8') } catch (e) { src = '' }
  check('模态用原生 <dialog> 元素', /h\('dialog'/.test(src), '')
  check('模态走 showModal()（原生焦点陷阱/Esc/焦点归还）', /\.showModal\(\)/.test(src), '')
  check('不再手写 Tab 焦点陷阱（回归守卫）', !/e\.key === 'Tab'/.test(src) && !/lastFocusRef/.test(src), '')
  check('粗指针命中区 44px 规则存在', /pointer: coarse/.test(src) && /min-height:44px/.test(src), '')
  check('useSnap 支持 selector（细粒度订阅）', /useSnap = \(store, selector\)/.test(src), '')
  check('目录行 memo 比较器忽略回调身份', /React\.memo/.test(src) && /a\.path === b\.path/.test(src), '')
  check('零硬编码颜色（只走 --dsw-alias-* token）', !/#[0-9a-fA-F]{3,8}\b/.test(src) && !/rgba?\(/.test(src), '')
  check('字号全部 rem（无 px 字号）', !/fontSize: \d/.test(src) && /fontSize: '[0-9.]+rem'/.test(src), '')
  check('无 props.X || 闭包 死代码兜底', !/props\.[a-zA-Z]+ \|\|/.test(src), '')
  check('状态色走 color-mix 保证对比度', /color-mix\(in srgb, var\(--dsw-alias-state-success-primary\)/.test(src), '')
  check('dialog padding 已移出（遮罩点击区只含真遮罩）', /padding: 0, borderRadius/.test(src), '')
}

console.log('')
const fails = results.filter((r) => !r.ok).length
console.log('=== ' + (fails ? 'CLIENT PROBE FAILED: ' + fails + ' fail(s)' : 'CLIENT PROBE PASSED: ' + results.length + '/' + results.length) + ' ===')
process.exit(fails ? 1 : 0)
