// dsh-ghidra 浏览器半 —— Settings 顶级分区（侧边栏 设置 → Ghidra）：状态 + 可热改配置
// 契约：window.__ModuleLoader__.load({ id: '<包名>', factory(require) {...} })；
// 不 require 任何 @deepseek-ai/dsh-client-* 包（plain-JS 插件无类型检查，抛错会 blank slot entry）；
// React 来自 browser module table（require('react') 是标准方式）；样式只用 --dsw-alias-* 主题 token。

window.__ModuleLoader__.load({
  id: 'dsh-ghidra',
  factory: (require) => {
    const React = require('react')
    const h = React.createElement

    const SETTINGS_NS = 'ghidra-bridge' // configForms.get(ns) = plugin name/row id

    // ---- 配置字段规格（与 index.js 的 Config 对齐）----
    const FIELDS = [
      { field: 'ghidraHome', label: 'Ghidra install directory (optional)', kind: 'text', browse: true, help: 'Not needed — the plugin uses the Ghidra installed in its own data dir (<node_modules>\\dsh-ghidra-home\\ghidra). Set this only to use an external install instead' },
      { field: 'ghidraProjectDir', label: 'Ghidra project directory', kind: 'text', browse: true, help: 'Press Browse… to pick a folder. Must NOT be under the DSH home: Ghidra rejects project paths with a dot-prefixed element and the DSH home is ".dsh". Default: %TEMP%\\dsh-ghidra-projects' },
      { field: 'projectName', label: 'Project name', kind: 'text', help: 'Ghidra project name, default dsh' },
      { field: 'pythonVer', label: 'Python version', kind: 'text', help: 'Python version for PyGhidra, default 3.13' },
      { field: 'analysisTimeoutSec', label: 'Analysis timeout (sec)', kind: 'number' },
      { field: 'serverStartupTimeoutMs', label: 'Server startup timeout (ms)', kind: 'number' },
      { field: 'maxOutputChars', label: 'Output truncation limit (chars)', kind: 'number' },
      { field: 'stream', label: 'Stream progress output', kind: 'boolean', help: 'Import/analysis progress runs as a background job' },
      { field: 'mcpPort', label: 'GhidraMCP port', kind: 'number', help: 'Upstream ghidraMCPHeadless server port, default 8123' },
      { field: 'mcpMode', label: 'MCP hosting mode', kind: 'text', help: 'unified = run the upstream REST server inside the PyGhidra bridge JVM on the same program (single process, recommended); standalone = separate ghidraMCPHeadless.bat process' },
      { field: 'mcpStartupTimeoutSec', label: 'MCP startup timeout (sec)', kind: 'number' },
      { field: 'mcpTimeoutSec', label: 'MCP call timeout (sec)', kind: 'number' },
    ]

    const numField = (max) => ({
      format: (v) => (v === undefined || v === null ? '' : String(v)),
      parse: (text) => {
        const t = String(text ?? '').trim()
        if (!t) return undefined
        const n = Number(t)
        if (!Number.isFinite(n)) throw new Error('Not a number: ' + t)
        const v = Math.round(n)
        if (v < 1) throw new Error('Must be >= 1')
        if (max !== undefined && v > max) throw new Error('Must be <= ' + max)
        return v
      },
    })
    const textField = () => ({
      format: (v) => (v === undefined || v === null ? '' : String(v)),
      parse: (text) => {
        const t = String(text ?? '').trim()
        return t || undefined
      },
    })
    const boolField = () => ({
      format: (v) => (v ? 'true' : 'false'),
      parse: (text) => {
        const t = String(text ?? '').trim().toLowerCase()
        if (t === 'true' || t === '1' || t === 'yes' || t === 'on') return true
        if (t === 'false' || t === '0' || t === 'no' || t === 'off' || t === '') return false
        throw new Error('Only true/false accepted')
      },
    })
    const spec = (f) =>
      f.kind === 'number'
        ? numField(f.field === 'mcpPort' ? 65535 : undefined)
        : f.kind === 'boolean'
          ? boolField()
          : textField()

    // ---- 最小 snapshot store（zustand 风格：getSnapshot/subscribe）----
    const createSnap = (initial) => {
      let snap = initial
      const listeners = new Set()
      return {
        getSnapshot: () => snap,
        subscribe: (fn) => {
          listeners.add(fn)
          return () => listeners.delete(fn)
        },
        update: (mutator) => {
          snap = { ...snap, ...mutator }
          listeners.forEach((fn) => { try { fn() } catch {} })
        },
      }
    }

    const statusStore = createSnap({ loading: true, error: '', status: null })
    const formStore = createSnap({ ready: false, unavailable: false, snapshot: null, drafts: {}, invalid: {}, saving: false, failed: false, message: '', error: '' })
    const doctorStore = createSnap({ running: false, result: null, error: '' })
    const installStore = createSnap({ running: false, phase: '', pct: 0, error: '', home: null })
    // 应用内文件夹浏览器（原生对话框在部分环境不可见，改由插件自己渲染）
    const browseStore = createSnap({ open: false, field: null, path: '', parent: null, dirs: [], drives: [], error: '', busy: false, newName: '', dotSegment: null, message: '' })

    let formScope = null

    // ---- 状态：/api/dsh-ghidra/status（节点半注册的路由）----
    const refreshStatus = async () => {
      statusStore.update({ loading: true })
      try {
        const r = await fetch('/api/dsh-ghidra/status', { method: 'GET' })
        const body = await r.json()
        statusStore.update({ loading: false, status: body, error: body && body.ok ? '' : (body && body.error) || 'Status request failed' })
      } catch (e) {
        statusStore.update({ loading: false, error: String((e && e.message) || e) })
      }
    }

    const stopMcp = async () => {
      try { await fetch('/api/dsh-ghidra/mcp-stop', { method: 'POST' }) } catch {}
      refreshStatus()
    }

    // ---- doctor：健康检查（Ghidra home / launcher / bat / Python / 双服务器运行态）----
    const runDoctor = async () => {
      doctorStore.update({ running: true, error: '' })
      try {
        const r = await fetch('/api/dsh-ghidra/doctor', { method: 'GET' })
        const body = await r.json()
        doctorStore.update({ running: false, result: body, error: body && body.checks ? '' : 'Doctor request failed' })
      } catch (e) {
        doctorStore.update({ running: false, error: String((e && e.message) || e) })
      }
    }

    // ---- 应用内文件夹浏览器：宿主只列目录（/list-dir），选择器由本 UI 渲染 ----
    const loadDir = async (path) => {
      browseStore.update({ busy: true, error: '', message: '' })
      try {
        const r = await fetch('/api/dsh-ghidra/list-dir', {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ path: String(path || '') }),
        })
        const body = await r.json()
        if (!r.ok || body.ok === false) {
          browseStore.update({
            busy: false,
            error: (body && body.error) || ('HTTP ' + r.status),
            drives: (body && body.drives) || [],
            path: (body && body.path) || path || '',
            parent: (body && body.parent) || null,
            dirs: (body && body.dirs) || [],
          })
          return
        }
        browseStore.update({
          busy: false, error: '', path: body.path || '', parent: body.parent || null,
          dirs: body.dirs || [], drives: body.drives || [], dotSegment: body.dotSegment || null,
        })
      } catch (e) {
        browseStore.update({ busy: false, error: String((e && e.message) || e) })
      }
    }

    const openBrowser = (field) => {
      const s = formStore.getSnapshot()
      const cur = (s.drafts && s.drafts[field]) !== undefined ? s.drafts[field]
        : (s.snapshot && s.snapshot.value ? s.snapshot.value[field] : '')
      browseStore.update({ open: true, field, newName: '', error: '', message: '' })
      loadDir(String(cur || ''))
    }

    const closeBrowser = () => browseStore.update({ open: false, field: null, error: '', message: '' })

    const browseUp = () => {
      const s = browseStore.getSnapshot()
      loadDir(s.parent || '')
    }

    const chooseFolder = () => {
      const s = browseStore.getSnapshot()
      if (!s.field || !s.path) return
      if (s.dotSegment) {
        browseStore.update({ error: 'This folder path contains ".' + s.dotSegment + '" — Ghidra rejects project paths with a dot-prefixed element. Pick a folder outside the DSH home.' })
        return
      }
      edit(s.field, s.path)
      formStore.update({ message: 'Picked ' + s.path + ' — press Save to apply', failed: false, error: '' })
      closeBrowser()
    }

    const createFolder = async () => {
      const s = browseStore.getSnapshot()
      if (!s.path || !s.newName.trim()) return
      try {
        const r = await fetch('/api/dsh-ghidra/mkdir', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ parent: s.path, name: s.newName.trim() }),
        })
        const body = await r.json()
        if (!r.ok || body.ok === false) { browseStore.update({ error: (body && body.error) || ('HTTP ' + r.status) }); return }
        browseStore.update({ newName: '', message: 'Created ' + body.path })
        loadDir(s.path)
      } catch (e) {
        browseStore.update({ error: String((e && e.message) || e) })
      }
    }

    // ---- home 迁移：POST → 轮询 /status 的 migrate 字段直到完成 ----
    const migrateHome = async (from, to) => {
      try {
        const r = await fetch('/api/dsh-ghidra/migrate-home', {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ from, to }),
        })
        const body = await r.json()
        if (!r.ok || body.ok === false) return { ok: false, error: (body && body.error) || 'HTTP ' + r.status }
        for (let i = 0; i < 900; i++) {
          await new Promise((res) => setTimeout(res, 1000))
          const s = await fetch('/api/dsh-ghidra/status', { method: 'GET' }).then((x) => x.json()).catch(() => null)
          const mg = s && s.migrate
          if (!mg || !mg.running) {
            return { ok: mg ? mg.ok === true : false, error: (mg && mg.error) || '' }
          }
        }
        return { ok: false, error: 'migration timed out' }
      } catch (e) { return { ok: false, error: String((e && e.message) || e) } }
    }

    // ---- Ghidra 下载安装：POST → 轮询 /status 的 install 字段；完成后切 home（save 流程内迁移）----
    const installGhidra = async () => {
      installStore.update({ running: true, phase: 'starting', pct: 0, error: '', home: null })
      try {
        const r = await fetch('/api/dsh-ghidra/install-ghidra', {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ force: true }),
        })
        const body = await r.json()
        if (!r.ok || body.ok === false) {
          installStore.update({ running: false, error: (body && body.error) || 'HTTP ' + r.status })
          return
        }
        for (let i = 0; i < 1800; i++) {
          await new Promise((res) => setTimeout(res, 1000))
          const s = await fetch('/api/dsh-ghidra/status', { method: 'GET' }).then((x) => x.json()).catch(() => null)
          const ins = s && s.install
          if (ins) installStore.update({ running: !!ins.running, phase: ins.phase || '', pct: ins.pct || 0, error: ins.error || '', home: ins.home || null })
          if (!ins || !ins.running) {
            if (ins && ins.phase === 'done' && ins.home) {
              edit('ghidraHome', ins.home)
              await save() // save 流程检测 ghidraHome 变更 → 迁移（版本切换：删旧 home）
              installStore.update({ running: false, phase: 'installed', error: '' })
            } else {
              installStore.update({ running: false, error: (ins && ins.error) || 'install failed' })
            }
            refreshStatus()
            return
          }
        }
        installStore.update({ running: false, error: 'install timed out' })
      } catch (e) {
        installStore.update({ running: false, error: String((e && e.message) || e) })
      }
    }

    // ---- 配置表单 transport（与 skill-hub settings-form.ts 同款契约）----
    const installFormTransport = (ctx) => {
      const scope = ctx.configForms && ctx.configForms.get && ctx.configForms.get(SETTINGS_NS)
      if (!scope) { formStore.update({ ready: true, unavailable: true }); return null }
      formScope = scope
      const refresh = () => {
        try {
          formStore.update({ ready: true, snapshot: scope.getSnapshot(), error: '' })
        } catch (e) {
          formStore.update({ ready: true, error: String((e && e.message) || e) })
        }
      }
      ctx.effect(() => scope.subscribe(refresh))
      refresh()
      return scope
    }

    // ---- face：staged edits（drafts）→ save() 逐条写 + 读回验收 ----
    const edit = (field, text) => {
      const s = formStore.getSnapshot()
      const drafts = { ...s.drafts, [field]: text }
      const f = FIELDS.find((x) => x.field === field)
      const invalid = { ...(s.invalid || {}) }
      if (f) {
        try { spec(f).parse(text); delete invalid[field] }
        catch (e) { invalid[field] = String((e && e.message) || e) }
      }
      formStore.update({ drafts, invalid })
    }

    const discard = () => formStore.update({ drafts: {}, invalid: {}, failed: false, message: '', error: '' })

    const planDrafts = () => {
      const s = formStore.getSnapshot()
      const snap = s.snapshot
      if (!snap) return { plan: [], failures: ['Config not loaded'] }
      const plan = []
      const failures = []
      for (const f of FIELDS) {
        if (!(f.field in s.drafts)) continue
        const sp = spec(f)
        try {
          const next = sp.parse(s.drafts[f.field])
          const cur = sp.format(snap.value && snap.value[f.field])
          const base = sp.format(snap.base && snap.base[f.field])
          const changed = next === undefined ? cur !== base : String(next) !== cur
          if (changed) plan.push({ field: f.field, label: f.label, next })
        } catch (e) {
          failures.push(f.label + '：' + String((e && e.message) || e))
        }
      }
      return { plan, failures }
    }

    const save = async () => {
      const s = formStore.getSnapshot()
      const snap = s.snapshot
      if (!snap || !snap.writable || !formScope) return
      const { plan, failures } = planDrafts()
      if (failures.length) { formStore.update({ failed: true, message: '', error: failures.join('；') }); return }
      if (!plan.length) { formStore.update({ failed: false, message: 'No changes', drafts: {}, invalid: {}, error: '' }); return }
      formStore.update({ saving: true, failed: false, message: '', error: '' })
      const errs = []
      for (const p of plan) {
        try {
          const ok = p.next === undefined ? await formScope.unset(p.field) : await formScope.set(p.field, p.next)
          if (!ok) errs.push(p.label + ' (write rejected)')
        } catch (e) {
          errs.push(p.label + '：' + String((e && e.message) || e))
        }
      }
      // 验收：读回 Host，确认每个写入字段都在 userRecord 里且与写入值一致
      let after = null
      try { after = formScope.getSnapshot() } catch {}
      const missing = plan
        .filter((p) => !after || (p.next !== undefined && (!after.user || after.user[p.field] !== p.next)))
        .map((p) => p.label)
      const bad = errs.concat(missing.map((m) => m + ' (read-back mismatch)'))
      // ghidraHome 变更且写入已落 → 迁移旧 home（复制/版本切换 → 校验 → 删旧）；失败不回滚配置，仅报错
      let migErr = ''
      const homePlan = plan.find((p) => p.field === 'ghidraHome')
      if (homePlan && homePlan.next !== undefined && after && after.user && after.user.ghidraHome === homePlan.next) {
        const st = (statusStore.getSnapshot().status) || {}
        formStore.update({ message: 'Migrating Ghidra home…' })
        const m = await migrateHome(st.ghidraHome || '', String(homePlan.next))
        if (!m.ok) migErr = 'Migration failed: ' + (m.error || 'unknown')
      }
      const failed = bad.length > 0 || !!migErr
      formStore.update({
        saving: false,
        failed,
        message: failed ? '' : 'Saved ' + plan.length + ' item(s)',
        error: bad.concat(migErr ? [migErr] : []).join('；'),
        snapshot: after || snap,
        drafts: failed ? s.drafts : {},
        invalid: failed ? s.invalid : {},
      })
      if (!failed) refreshStatus()
    }

    const resetField = async (field) => {
      const s = formStore.getSnapshot()
      if (!s.snapshot || !s.snapshot.writable || !formScope) return
      try { await formScope.unset(field) } catch (e) {
        formStore.update({ failed: true, error: String((e && e.message) || e) })
        return
      }
      const drafts = { ...s.drafts }
      delete drafts[field]
      let after = null
      try { after = formScope.getSnapshot() } catch {}
      formStore.update({ drafts, snapshot: after || s.snapshot, failed: false, message: '', error: '' })
      refreshStatus()
    }

    // ---- 样式（只用 --dsw-alias-* / --dsw-radius-* 主题 token）----
    // 需要 :hover / :focus-visible 的部分注入一张小样式表（inline style 表达不了伪类）。
    const STYLE_ID = 'dsh-ghidra-ui'
    const ensureStyle = () => {
      try {
        if (!document || !document.head) return
        if (document.getElementById(STYLE_ID)) return
        const el = document.createElement('style')
        el.id = STYLE_ID
        el.textContent = [
          '.dshg-btn:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover)}',
          '.dshg-btn:active:not(:disabled){background:var(--dsw-alias-interactive-bg-active)}',
          '.dshg-primary:hover:not(:disabled){background:var(--dsw-alias-button-primary-hover)}',
          '.dshg-btn:focus-visible,.dshg-input:focus-visible,.dshg-row:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:1px}',
          '.dshg-row:hover{background:var(--dsw-alias-interactive-bg-hover)}',
          '.dshg-row:focus-visible{background:var(--dsw-alias-interactive-bg-hover)}',
          // 原生模态的遮罩走 top-layer 伪元素（不再需要自绘 overlay div）
          '.dshg-dialog::backdrop{background:var(--dsw-alias-bg-mask-1)}',
          // 触屏/粗指针：把控件抬到 44px 命中区（鼠标环境保持宿主的 28px 紧凑密度）
          '@media (pointer: coarse){.dshg-btn,.dshg-input,.dshg-row{min-height:44px}}',
          '@media (prefers-reduced-motion: reduce){.dshg-btn,.dshg-row{transition:none}}',
        ].join('')
        document.head.appendChild(el)
      } catch { /* 无 DOM 时忽略（测试环境） */ }
    }

    const S = {
      card: { border: '1px solid var(--dsw-alias-border-l2)', background: 'var(--dsw-alias-bg-layer-2)', borderRadius: 'var(--dsw-radius-md)', padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 12 },
      head: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' },
      title: { fontSize: '0.875rem', fontWeight: 600, color: 'var(--dsw-alias-label-primary)', margin: 0 },
      badge: { fontSize: '0.6875rem', padding: '1px 7px', borderRadius: 999, border: '1px solid var(--dsw-alias-border-l2)', color: 'var(--dsw-alias-label-secondary)', background: 'var(--dsw-alias-bg-layer-3)' },
      sectionTitle: { fontSize: '0.6875rem', fontWeight: 600, letterSpacing: '0.06em', color: 'var(--dsw-alias-label-secondary)', margin: '2px 0 0' },
      row: { display: 'flex', gap: 8, fontSize: '0.75rem', color: 'var(--dsw-alias-label-secondary)', lineHeight: 1.6 },
      key: { color: 'var(--dsw-alias-label-secondary)', minWidth: 110, flexShrink: 0 },
      val: { color: 'var(--dsw-alias-label-primary)', wordBreak: 'break-all' },
      ok: { color: 'color-mix(in srgb, var(--dsw-alias-state-success-primary) 55%, var(--dsw-alias-label-primary))', fontSize: '0.75rem' },
      err: { color: 'color-mix(in srgb, var(--dsw-alias-state-error-primary) 75%, var(--dsw-alias-label-primary))', fontSize: '0.75rem', wordBreak: 'break-all' },
      idle: { color: 'color-mix(in srgb, var(--dsw-alias-state-idle-primary) 40%, var(--dsw-alias-label-primary))', fontSize: '0.75rem' },
      hint: { fontSize: '0.75rem', color: 'var(--dsw-alias-label-secondary)', margin: 0, lineHeight: 1.5 },
      caption: { fontSize: '0.6875rem', color: 'var(--dsw-alias-label-secondary)', margin: 0, lineHeight: 1.4 },
      buttonRow: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' },
      button: { fontSize: '0.75rem', minHeight: 28, padding: '0 12px', borderRadius: 'var(--dsw-radius-sm)', border: '0.5px solid var(--dsw-alias-border-l3)', background: 'transparent', color: 'var(--dsw-alias-label-primary)', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 4 },
      buttonPrimary: { fontSize: '0.75rem', minHeight: 28, padding: '0 12px', borderRadius: 'var(--dsw-radius-sm)', border: 'none', background: 'var(--dsw-alias-button-primary-fill)', color: 'var(--dsw-alias-label-primary-foreground)', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 4 },
      input: { fontSize: '0.75rem', minHeight: 28, padding: '0 8px', borderRadius: 'var(--dsw-radius-sm)', border: '0.5px solid var(--dsw-alias-border-l3)', background: 'var(--dsw-alias-bg-layer-3)', color: 'var(--dsw-alias-label-primary)', flex: 1, minWidth: 140 },
      inputInvalid: { fontSize: '0.75rem', minHeight: 28, padding: '0 8px', borderRadius: 'var(--dsw-radius-sm)', border: '0.5px solid var(--dsw-alias-state-error-primary)', background: 'var(--dsw-alias-bg-layer-3)', color: 'var(--dsw-alias-label-primary)', flex: 1, minWidth: 140 },
      fieldRow: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' },
      fieldLabel: { fontSize: '0.75rem', color: 'var(--dsw-alias-label-secondary)', minWidth: 150, flexShrink: 0 },
      fieldError: { fontSize: '0.6875rem', color: 'color-mix(in srgb, var(--dsw-alias-state-error-primary) 75%, var(--dsw-alias-label-primary))', flexBasis: '100%', margin: 0 },
      overrideBadge: { fontSize: '0.625rem', padding: '0 6px', borderRadius: 999, border: '1px solid var(--dsw-alias-brand-primary)', color: 'var(--dsw-alias-brand-primary)', flexShrink: 0 },
      // 原生 <dialog> + showModal()：top-layer 堆叠、焦点陷阱、Esc 关闭、焦点归还全由浏览器负责
      dialog: { width: 620, maxWidth: '92vw', maxHeight: '80vh', margin: 'auto', padding: 0, borderRadius: 'var(--dsw-radius-md)', border: '1px solid var(--dsw-alias-border-l2)', background: 'var(--dsw-alias-bg-layer-2)', color: 'var(--dsw-alias-label-primary)', display: 'flex', flexDirection: 'column', gap: 10 },
      crumb: { fontSize: '0.75rem', color: 'var(--dsw-alias-label-secondary)', wordBreak: 'break-all', flex: 1, minWidth: 120 },
      list: { display: 'flex', flexDirection: 'column', gap: 2, overflowY: 'auto', maxHeight: '46vh', border: '1px solid var(--dsw-alias-border-l2)', borderRadius: 'var(--dsw-radius-sm)', padding: 6, background: 'var(--dsw-alias-bg-layer-3)' },
      listRow: { display: 'flex', alignItems: 'center', gap: 8, minHeight: 32, padding: '0 8px', borderRadius: 'var(--dsw-radius-sm)', cursor: 'pointer', fontSize: '0.75rem', color: 'var(--dsw-alias-label-primary)', background: 'transparent', border: 'none', textAlign: 'left', width: '100%' },
      dotBadge: { fontSize: '0.625rem', padding: '0 5px', borderRadius: 999, border: '1px solid color-mix(in srgb, var(--dsw-alias-state-warn-primary) 70%, var(--dsw-alias-label-primary))', color: 'color-mix(in srgb, var(--dsw-alias-state-warn-label) 70%, var(--dsw-alias-label-primary))', flexShrink: 0 },
      icon: { flexShrink: 0, color: 'var(--dsw-alias-menu-icon)' },
    }

    // 内联 SVG 图标（不用 emoji：跨平台渲染不一致，且无法继承 currentColor）
    const IconFolder = () => h('svg', { width: 14, height: 14, viewBox: '0 0 16 16', 'aria-hidden': 'true', focusable: 'false', style: S.icon },
      h('path', { d: 'M1.5 4.2c0-.6.5-1.1 1.1-1.1h3.1l1.2 1.4h6.5c.6 0 1.1.5 1.1 1.1v6.2c0 .6-.5 1.1-1.1 1.1H2.6c-.6 0-1.1-.5-1.1-1.1V4.2z', fill: 'none', stroke: 'currentColor', strokeWidth: 1.2, strokeLinejoin: 'round' }))
    const IconUp = () => h('svg', { width: 14, height: 14, viewBox: '0 0 16 16', 'aria-hidden': 'true', focusable: 'false', style: S.icon },
      h('path', { d: 'M8 12.5V3.5M4 7.5 8 3.5l4 4', fill: 'none', stroke: 'currentColor', strokeWidth: 1.2, strokeLinecap: 'round', strokeLinejoin: 'round' }))

    // 目录行：memo + 自定义比较器（只比数据，不比回调身份）——
    // 过滤框每敲一个字都重渲染整张列表时，只有真正变化的行会重画。
    const memoize = React.memo || ((c) => c)
    const FolderRow = memoize(function FolderRow(props) {
      return h('button', {
        className: 'dshg-row',
        style: S.listRow,
        title: props.dot ? props.path + '  — dot-prefixed; Ghidra rejects these as project paths' : props.path,
        onClick: () => props.onOpen(props.path),
      }, h(IconFolder), h('span', { style: { flex: 1, wordBreak: 'break-all' } }, props.name),
      props.dot ? h('span', { style: S.dotBadge, title: 'Dot-prefixed — not usable as a Ghidra project path' }, 'dot') : null)
    }, (a, b) => a.path === b.path && a.name === b.name && a.dot === b.dot)

    const Row = (props) => h('div', { style: S.row },
      h('span', { style: S.key }, props.k),
      h('span', { style: S.val }, props.v),
    )

    // React 原生响应式兜底：订阅 snapshot store（无 hooks 仓 props 时分区仍实时刷新）
    // selector 可选：只订阅需要的切片，切片没变就不触发重渲染（细粒度订阅）
    const useSnap = (store, selector) => {
      const sel = selector || ((s) => s)
      const [snap, setSnap] = React.useState(() => sel(store.getSnapshot()))
      React.useEffect(() => {
        const off = store.subscribe(() => {
          const next = sel(store.getSnapshot())
          setSnap((prev) => (Object.is(prev, next) ? prev : next))
        })
        return () => { try { off() } catch {} }
      }, [])
      return snap
    }

    const GhidraCard = (props) => {
      // hooks compartment 成员 → use<Key> hook；否则 React 原生订阅兜底（无条件调用，hooks 规则合规）

      const status = useSnap(statusStore)
      const form = useSnap(formStore)
      const doctor = useSnap(doctorStore)
      const install = useSnap(installStore)
      // 细粒度订阅：卡片只关心「开/关」这一个布尔切片，
      // 目录里翻来翻去（browse 快照每次都变）不再让整张卡片重渲染。
      const browseOpen = useSnap(browseStore, (b) => !!(b && b.open))
      // 模态的焦点陷阱 / Esc / 焦点归还都交给原生 <dialog>.showModal()（见 BrowseDialog），
      // 这里不再手写 keydown 监听。

      // 操作：只用闭包动作（组件不再读 props）。
      // 已核实的宿主契约：settings.section 的调用点是
      //   renderSlot("settings.section", { close: onClose }, { only: active })
      // —— 显式 props 只有 { close }。渲染器确实会解析注册项的 inject
      // （dsh-client-ui-renderer 里 `const inject = entry.inject` 与 `cachedSlotInject(spec.inject)`），
      // 所以 `inject: () => face` 保留；但注入的 face 与这里的闭包是同一批函数，
      // 组件侧只保留一条路径即可（历史上「props 优先、闭包兜底」的双路写法已删除）。
      const act = {
        refresh: refreshStatus,
        save,
        discard,
        edit,
        resetField,
        stopMcp,
        runDoctor,
        installGhidra,
        openBrowser,
        browseInto: (p) => { loadDir(p) },
        browseUp,
        browseName: (v) => { browseStore.update({ newName: v }) },
        chooseFolder,
        closeBrowser,
        createFolder,
      }

      const st = (status && status.status) || null
      const py = (st && st.pyghidra) || null
      const mcp = (st && st.mcp) || null
      const tools = (st && st.tools) || null
      const snap = (form && form.snapshot) || null
      const drafts = (form && form.drafts) || {}
      const invalid = (form && form.invalid) || {}
      const children = []

      children.push(h('div', { style: S.head, key: 'head' },
        h('h3', { style: S.title }, 'Ghidra Bridge'),
        st && st.version ? h('span', { style: S.badge, title: 'Installed Ghidra version' }, 'Ghidra ' + st.version) : null,
        tools ? h('span', { style: S.badge }, tools.total + ' tools') : null,
      ))
      children.push(h('p', { style: S.hint, key: 'desc' }, 'Import binaries into Ghidra and operate on decompiled output; config changes apply immediately, no DSH restart needed.'))

      // ---- 状态 ----
      children.push(h('p', { style: S.sectionTitle, key: 'st-title' }, 'Status'))
      if (status && status.loading && !st) children.push(h('p', { style: S.hint, key: 'st-loading' }, 'Loading…'))
      if (status && status.error) children.push(h('p', { style: S.err, key: 'st-err' }, status.error))
      if (st) {
        children.push(h(Row, { key: 'st-py', k: 'PyGhidra bridge', v: py && py.running
          ? 'running · port ' + py.port + (py.program ? ' · ' + py.program : '') + (py.serverPid ? ' · pid ' + py.serverPid : '')
          : 'not running' }))
        children.push(h(Row, { key: 'st-mcp', k: 'GhidraMCP server', v: mcp && mcp.running
          ? 'running · port ' + mcp.port + (mcp.mode ? ' · ' + mcp.mode : '')
            + (mcp.sharedProgram ? ' · shares ' + mcp.sharedProgram : '')
            + (mcp.health && mcp.health.version ? ' · ' + mcp.health.version : '')
          : 'not running' + (mcp && mcp.mode ? ' · ' + mcp.mode : '') }))
        if (tools) children.push(h(Row, { key: 'st-tools', k: 'Tools', v: tools.total + ' (native ' + tools.native + ' + lifecycle ' + tools.lifecycle + ' + generated ' + tools.generated + ')' }))
        if (st.ghidraHome) children.push(h(Row, { key: 'st-home', k: 'Ghidra home', v: st.ghidraHome }))
      }
      children.push(h('div', { style: S.buttonRow, key: 'st-btns' },
        h('button', { className: 'dshg-btn', style: S.button, onClick: () => { refreshStatus() } }, status && status.loading ? 'Refreshing…' : 'Refresh'),
        mcp && mcp.running
          ? h('button', { className: 'dshg-btn', style: S.button, onClick: () => { stopMcp() }, title: 'Gracefully stop the upstream GhidraMCP server (saves loaded programs before exit)' }, 'Stop MCP server')
          : null,
        h('button', {
          className: 'dshg-btn',
          style: install && install.running ? S.button : S.button,
          onClick: () => { act.installGhidra() },
          disabled: !!(install && install.running),
          title: 'Download the latest Ghidra release from GitHub, extract it next to the current home and switch the home to it (the old home is deleted)',
        }, install && install.running ? 'Downloading…' : 'Download Ghidra'),
      ))
      if (install && (install.running || install.phase || install.error || install.home)) {
        children.push(h('p', { style: install.error ? S.err : S.hint, key: 'st-install', role: install.error ? 'alert' : 'status', 'aria-busy': install.running ? 'true' : undefined },
          install.running
            ? (install.phase || 'working…') + (install.total ? ' · ' + install.pct + '% (' + Math.round(install.bytes / 1048576) + '/' + Math.round(install.total / 1048576) + ' MB)' : '')
            : install.error
              ? 'Install failed: ' + install.error
              : install.home
                ? 'Installed → ' + install.home
                : install.phase,
        ))
      }

      // ---- doctor：健康检查 ----
      children.push(h('div', { style: S.buttonRow, key: 'doc-head' },
        h('p', { style: S.sectionTitle }, 'Health check'),
        h('button', {
          className: 'dshg-btn',
          style: S.button,
          onClick: () => { act.runDoctor() },
          disabled: !!(doctor && doctor.running),
          title: 'Check Ghidra install, launcher scripts, Python and both servers',
        }, doctor && doctor.running ? 'Checking…' : 'Run doctor'),
      ))
      if (doctor && doctor.error) children.push(h('p', { style: S.err, key: 'doc-err', role: 'alert' }, doctor.error))
      if (doctor && doctor.result && doctor.result.checks) {
        const dr = doctor.result
        children.push(h('p', { style: dr.ok ? S.ok : S.err, key: 'doc-sum', role: 'status' },
          dr.ok
            ? 'All essential checks passed (' + dr.essentialOk + '/' + dr.essentialTotal + ')' + (dr.runtimeIdle ? ' · ' + dr.runtimeIdle + ' runtime check(s) idle' : '')
            : 'Essential checks: ' + dr.essentialOk + '/' + dr.essentialTotal + ' passed',
        ))
        const docRows = doctor.result.checks.map((c, i) => {
          const label = c.ok ? 'OK' : (c.optional ? 'IDLE' : 'FAIL')
          const style = c.ok ? S.ok : (c.optional ? S.idle : S.err)
          return h('div', { style: S.row, key: 'doc-' + i, role: 'listitem' },
            h('span', { style: { ...style, minWidth: 38, flexShrink: 0, fontWeight: 600 } }, label),
            h('span', { style: S.key }, c.name),
            h('span', { style: c.optional && !c.ok ? S.hint : S.val }, c.detail),
          )
        })
        children.push(h('div', {
          key: 'doc-list',
          role: 'list',
          'aria-label': 'Health check results',
          style: { display: 'flex', flexDirection: 'column', gap: 2 },
        }, ...docRows))
      }

      // ---- 配置 ----
      children.push(h('p', { style: S.sectionTitle, key: 'cfg-title' }, 'Config'))
      if (!form || !form.ready) {
        children.push(h('p', { style: S.hint, key: 'cfg-loading', role: 'status' }, 'Loading…'))
      } else if (form.unavailable || !snap) {
        children.push(h('p', { style: S.hint, key: 'cfg-na' }, 'Config form unavailable (settings service not mounted in this deployment)'))
      } else if (!snap.writable) {
        children.push(h('p', { style: S.hint, key: 'cfg-ro' }, 'Config is read-only (hot edits not allowed in this deployment)'))
      } else {
        FIELDS.forEach((f, i) => {
          const sp = spec(f)
          const cur = sp.format(snap.value && snap.value[f.field])
          const base = sp.format(snap.base && snap.base[f.field])
          const overridden = cur !== base
          const draft = f.field in drafts ? drafts[f.field] : cur
          const bad = invalid[f.field]
          const fieldId = 'dshg-cfg-' + f.field
          children.push(h('div', { style: S.fieldRow, key: 'cfg-' + f.field },
            h('label', { style: S.fieldLabel, htmlFor: fieldId, title: f.help || '' }, f.label),
            h('input', {
              id: fieldId,
              className: 'dshg-input',
              style: bad ? S.inputInvalid : S.input,
              value: draft,
              title: bad || f.help || '',
              'aria-invalid': bad ? 'true' : undefined,
              'aria-describedby': bad ? fieldId + '-err' : undefined,
              onChange: (e) => { act.edit(f.field, (e && e.target && e.target.value) || '') },
            }),
            overridden ? h('span', { style: S.overrideBadge }, 'overridden') : null,
            f.browse ? h('button', {
              className: 'dshg-btn',
              style: S.button,
              onClick: () => { act.openBrowser(f.field) },
              title: 'Browse folders on this machine',
              'aria-label': 'Browse folders for ' + f.label,
            }, 'Browse…') : null,
            overridden
              ? h('button', {
                className: 'dshg-btn',
                style: S.button,
                onClick: () => { act.resetField(f.field) },
                title: 'Reset to default',
                'aria-label': 'Reset ' + f.label + ' to default',
              }, 'Reset')
              : null,
            bad ? h('p', { id: fieldId + '-err', style: S.fieldError, key: fieldId + '-err' }, bad) : null,
          ))
        })
        children.push(h('div', { style: S.buttonRow, key: 'cfg-btns' },
          h('button', {
            className: form.saving ? 'dshg-btn' : 'dshg-btn dshg-primary',
            style: form.saving ? S.button : S.buttonPrimary,
            disabled: !!form.saving,
            onClick: () => { act.save() },
          }, form.saving ? 'Saving…' : 'Save'),
          h('button', { className: 'dshg-btn', style: S.button, onClick: () => { act.discard() } }, 'Discard'),
          form.message ? h('span', { style: S.ok, role: 'status' }, form.message) : null,
          form.failed ? h('span', { style: S.err, role: 'alert' }, form.error || 'Save failed') : null,
        ))
      }

      // ---- 文件夹浏览器：独立组件 + 细粒度订阅（见 BrowseDialog 定义）----
      children.push(browseOpen ? h(BrowseDialog, { key: 'browse', act }) : null)

      return h('div', { style: S.card }, ...children)
    }

    // 目录选择对话框：原生 <dialog> + showModal()
    // —— top-layer 堆叠、Tab 焦点陷阱、Esc 关闭、关闭后焦点归还触发元素，全部由浏览器实现，
    //    插件不再手写 keydown 陷阱与焦点存取（早先那 30 行自绘逻辑已删除）。
    const BrowseDialog = (props) => {
      const act = props.act
      const browse = useSnap(browseStore)
      const [folderFilter, setFolderFilter] = React.useState('')
      const dialogRef = React.useRef(null)
      React.useEffect(() => {
        const el = dialogRef.current
        try { if (el && el.showModal) el.showModal() } catch { /* ignore */ }
        return () => { try { if (el && el.open && el.close) el.close() } catch { /* ignore */ } }
      }, [])
      {
        const all = browse.path
          ? (browse.dirs || [])
          : (browse.drives || []).map((d) => ({ name: d, path: d, dot: false }))
        const q = String(folderFilter || '').trim().toLowerCase()
        const filtered = q ? all.filter((d) => String(d.name).toLowerCase().includes(q)) : all
        const CAP = 150
        const entries = filtered.slice(0, CAP)
        const rows = []
        if (browse.path) {
          rows.push(h('button', {
            key: 'up', className: 'dshg-row', style: S.listRow,
            onClick: () => act.browseUp(),
            'aria-label': 'Go up to ' + (browse.parent || 'the drive list'),
          }, h(IconUp), h('span', null, '..  ' + (browse.parent || 'Drives'))))
        }
        for (const d of entries) {
          rows.push(h(FolderRow, {
            key: d.path,
            path: d.path,
            name: d.name,
            dot: d.dot,
            onOpen: act.browseInto,
          }))
        }
        if (!entries.length) {
          rows.push(h('p', { key: 'empty', style: S.hint }, q ? 'No folder matches "' + folderFilter + '"' : 'No subfolders here'))
        }
        return h('dialog', {
          className: 'dshg-dialog',
          style: S.dialog,
          ref: dialogRef,
          'aria-labelledby': 'dshg-browse-title',
          onCancel: () => act.closeBrowser(),
          onClick: (e) => { if (e && e.target === e.currentTarget) act.closeBrowser() },
        },
          h('div', { style: { display: 'flex', flexDirection: 'column', gap: 10, padding: '14px 16px' } },
          h('div', { style: S.head },
            h('h3', { id: 'dshg-browse-title', style: S.title }, 'Choose a folder'),
            h('span', { style: S.crumb }, browse.path || 'Drives'),
          ),
          browse.error ? h('p', { style: S.err, role: 'alert' }, browse.error) : null,
          browse.message ? h('p', { style: S.ok, role: 'status' }, browse.message) : null,
          all.length > 12 ? h('input', {
            className: 'dshg-input',
            style: S.input,
            placeholder: 'Filter folders…',
            value: folderFilter,
            'aria-label': 'Filter folders by name',
            onChange: (e) => setFolderFilter((e && e.target && e.target.value) || ''),
          }) : null,
          h('div', { style: S.list, role: 'group', 'aria-label': 'Folders' }, ...rows),
          filtered.length > CAP
            ? h('p', { style: S.caption }, 'Showing first ' + CAP + ' of ' + filtered.length + ' folders — use the filter to narrow down')
            : null,
          h('div', { style: S.buttonRow },
            h('input', {
              className: 'dshg-input',
              style: S.input,
              placeholder: 'new folder name',
              value: browse.newName || '',
              'aria-label': 'New folder name',
              onChange: (e) => act.browseName((e && e.target && e.target.value) || ''),
            }),
            h('button', {
              className: 'dshg-btn',
              style: S.button,
              disabled: !browse.path || !String(browse.newName || '').trim(),
              onClick: () => act.createFolder(),
            }, 'Create folder'),
          ),
          h('div', { style: S.buttonRow },
            h('button', {
              className: 'dshg-btn dshg-primary',
              style: S.buttonPrimary,
              disabled: !browse.path || !!browse.dotSegment,
              title: browse.dotSegment ? 'Dot-prefixed path — Ghidra will reject it' : 'Use the folder shown above',
              onClick: () => act.chooseFolder(),
            }, 'Use this folder'),
            h('button', { className: 'dshg-btn', style: S.button, onClick: () => act.closeBrowser() }, 'Cancel'),
            browse.busy ? h('span', { style: S.hint, role: 'status' }, 'Loading…') : null,
          ),
          ),
        )
      }
    }

    // ---- face：hooks + 普通操作（组件经 props 拿到）----
    const face = {
      hooks: { ghidraStatus: statusStore, ghidraForm: formStore },
      refresh: refreshStatus,
      save, discard, edit, resetField, stopMcp,
    }

    return {
      inject: ['slots', 'connection', 'remote', 'configForms'],
      apply(ctx) {
        // 每次配置写入都会重跑 apply（volatile entry reload）—— provider 每次重建
        // Settings 顶级分区（侧边栏 设置 → Ghidra），与 dsh-mobilecode 等插件同位：
        // slots.inject('settings.section') → register({ name, id, order, label }, 组件)
        // 配置表单 transport 必须先绑定（否则 formStore.ready 永远 false → 配置区卡在 Loading…）
        installFormTransport(ctx)
        // 注入 :hover / :focus-visible / reduced-motion 样式表（inline style 表达不了伪类）
        ensureStyle()
        ctx.effect(() => ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: 'ghidra',
          order: 210,
          label: 'Ghidra',
          inject: () => face,
        }, GhidraCard)), 'name')
        refreshStatus()
      },
    }
  },
})
