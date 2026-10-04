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

    // ---- 样式（只用 --dsw-alias-* 主题 token）----
    const S = {
      card: { border: '1px solid var(--dsw-alias-border-l2)', background: 'var(--dsw-alias-bg-layer-2)', borderRadius: 10, padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 12 },
      head: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' },
      title: { fontSize: 14, fontWeight: 600, color: 'var(--dsw-alias-label-primary)', margin: 0 },
      badge: { fontSize: 11, padding: '1px 7px', borderRadius: 999, border: '1px solid var(--dsw-alias-border-l2)', color: 'var(--dsw-alias-label-secondary)', background: 'var(--dsw-alias-bg-layer-3)' },
      sectionTitle: { fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', color: 'var(--dsw-alias-label-dimmed)', margin: '2px 0 0' },
      row: { display: 'flex', gap: 8, fontSize: 12, color: 'var(--dsw-alias-label-secondary)', lineHeight: 1.6 },
      key: { color: 'var(--dsw-alias-label-tertiary)', minWidth: 110, flexShrink: 0 },
      val: { color: 'var(--dsw-alias-label-primary)', wordBreak: 'break-all' },
      ok: { color: 'var(--dsw-alias-state-business-primary)', fontSize: 12 },
      err: { color: 'var(--dsw-alias-state-error-primary)', fontSize: 12, wordBreak: 'break-all' },
      hint: { fontSize: 11, color: 'var(--dsw-alias-label-dimmed)', margin: 0, lineHeight: 1.5 },
      buttonRow: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' },
      button: { fontSize: 12, padding: '4px 12px', borderRadius: 6, border: '1px solid var(--dsw-alias-border-l2)', background: 'var(--dsw-alias-bg-layer-3)', color: 'var(--dsw-alias-label-primary)', cursor: 'pointer' },
      buttonPrimary: { fontSize: 12, padding: '4px 12px', borderRadius: 6, border: '1px solid var(--dsw-alias-state-business-primary)', background: 'var(--dsw-alias-state-business-primary)', color: '#ffffff', cursor: 'pointer' },
      input: { fontSize: 12, padding: '4px 8px', borderRadius: 6, border: '1px solid var(--dsw-alias-border-l2)', background: 'var(--dsw-alias-bg-layer-3)', color: 'var(--dsw-alias-label-primary)', flex: 1, minWidth: 140 },
      inputInvalid: { fontSize: 12, padding: '4px 8px', borderRadius: 6, border: '1px solid var(--dsw-alias-state-error-primary)', background: 'var(--dsw-alias-bg-layer-3)', color: 'var(--dsw-alias-label-primary)', flex: 1, minWidth: 140 },
      fieldRow: { display: 'flex', gap: 8, alignItems: 'center' },
      fieldLabel: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)', minWidth: 150, flexShrink: 0 },
      overrideBadge: { fontSize: 10, padding: '0 6px', borderRadius: 999, border: '1px solid var(--dsw-alias-brand-primary)', color: 'var(--dsw-alias-brand-primary)', flexShrink: 0 },
      overlay: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.45)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 },
      modal: { width: 620, maxWidth: '92vw', maxHeight: '80vh', display: 'flex', flexDirection: 'column', gap: 10, padding: '14px 16px', borderRadius: 10, border: '1px solid var(--dsw-alias-border-l2)', background: 'var(--dsw-alias-bg-layer-2)', color: 'var(--dsw-alias-label-primary)', boxShadow: '0 12px 40px rgba(0,0,0,0.45)' },
      crumb: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)', wordBreak: 'break-all', flex: 1, minWidth: 120 },
      list: { display: 'flex', flexDirection: 'column', gap: 2, overflowY: 'auto', maxHeight: '46vh', border: '1px solid var(--dsw-alias-border-l2)', borderRadius: 8, padding: 6, background: 'var(--dsw-alias-bg-layer-3)' },
      listRow: { display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', borderRadius: 6, cursor: 'pointer', fontSize: 12, color: 'var(--dsw-alias-label-primary)', background: 'transparent', border: 'none', textAlign: 'left' },
      listRowDot: { display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', borderRadius: 6, cursor: 'pointer', fontSize: 12, color: 'var(--dsw-alias-label-dimmed)', background: 'transparent', border: 'none', textAlign: 'left' },
    }

    const Row = (props) => h('div', { style: S.row },
      h('span', { style: S.key }, props.k),
      h('span', { style: S.val }, props.v),
    )

    // React 原生响应式兜底：订阅 snapshot store（无 hooks 仓 props 时分区仍实时刷新）
    const useSnap = (store) => {
      const [snap, setSnap] = React.useState(() => store.getSnapshot())
      React.useEffect(() => {
        const off = store.subscribe(() => setSnap(store.getSnapshot()))
        return () => { try { off() } catch {} }
      }, [])
      return snap
    }

    const GhidraCard = (props) => {
      // hooks compartment 成员 → use<Key> hook；否则 React 原生订阅兜底（无条件调用，hooks 规则合规）
      const sel = (s) => s
      const fallbackStatus = useSnap(statusStore)
      const fallbackForm = useSnap(formStore)
      const fallbackDoctor = useSnap(doctorStore)
      const fallbackInstall = useSnap(installStore)
      const fallbackBrowse = useSnap(browseStore)
      const status = props.useGhidraStatus ? props.useGhidraStatus(sel) : fallbackStatus
      const form = props.useGhidraForm ? props.useGhidraForm(sel) : fallbackForm
      const doctor = fallbackDoctor
      const install = fallbackInstall
      const browse = fallbackBrowse
      // 操作兜底：无 face 注入时直接用闭包动作（settings.section 分发不保证注入 inject face）
      const act = {
        refresh: props.refresh || refreshStatus,
        save: props.save || save,
        discard: props.discard || discard,
        edit: props.edit || edit,
        resetField: props.resetField || resetField,
        stopMcp: props.stopMcp || stopMcp,
        runDoctor: props.runDoctor || runDoctor,
        installGhidra: props.installGhidra || installGhidra,
        openBrowser: props.openBrowser || openBrowser,
        browseInto: props.browseInto || ((p) => { loadDir(p) }),
        browseUp: props.browseUp || browseUp,
        browseName: props.browseName || ((v) => { browseStore.update({ newName: v }) }),
        chooseFolder: props.chooseFolder || chooseFolder,
        closeBrowser: props.closeBrowser || closeBrowser,
        createFolder: props.createFolder || createFolder,
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
        h('button', { style: S.button, onClick: () => { refreshStatus() } }, status && status.loading ? 'Refreshing…' : 'Refresh'),
        mcp && mcp.running
          ? h('button', { style: S.button, onClick: () => { stopMcp() }, title: 'Gracefully stop the upstream GhidraMCP server (saves loaded programs before exit)' }, 'Stop MCP server')
          : null,
        h('button', {
          style: install && install.running ? S.button : S.button,
          onClick: () => { act.installGhidra() },
          disabled: !!(install && install.running),
          title: 'Download the latest Ghidra release from GitHub, extract it next to the current home and switch the home to it (the old home is deleted)',
        }, install && install.running ? 'Downloading…' : 'Download Ghidra'),
      ))
      if (install && (install.running || install.phase || install.error || install.home)) {
        children.push(h('p', { style: install.error ? S.err : S.hint, key: 'st-install' },
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
          style: S.button,
          onClick: () => { act.runDoctor() },
          disabled: !!(doctor && doctor.running),
          title: 'Check Ghidra install, launcher scripts, Python and both servers',
        }, doctor && doctor.running ? 'Checking…' : 'Run doctor'),
      ))
      if (doctor && doctor.error) children.push(h('p', { style: S.err, key: 'doc-err' }, doctor.error))
      if (doctor && doctor.result && doctor.result.checks) {
        const dr = doctor.result
        children.push(h('p', { style: dr.ok ? S.ok : S.err, key: 'doc-sum' },
          dr.ok
            ? 'All essential checks passed (' + dr.essentialOk + '/' + dr.essentialTotal + ')' + (dr.runtimeIdle ? ' · ' + dr.runtimeIdle + ' runtime check(s) idle' : '')
            : 'Essential checks: ' + dr.essentialOk + '/' + dr.essentialTotal + ' passed',
        ))
        doctor.result.checks.forEach((c, i) => {
          const label = c.ok ? 'OK' : (c.optional ? 'IDLE' : 'FAIL')
          const style = c.ok ? S.ok : (c.optional ? S.hint : S.err)
          children.push(h('div', { style: S.row, key: 'doc-' + i },
            h('span', { style: { ...style, minWidth: 38, flexShrink: 0, fontWeight: 600 } }, label),
            h('span', { style: S.key }, c.name),
            h('span', { style: c.optional && !c.ok ? S.hint : S.val }, c.detail),
          ))
        })
      }

      // ---- 配置 ----
      children.push(h('p', { style: S.sectionTitle, key: 'cfg-title' }, 'Config'))
      if (!form || !form.ready) {
        children.push(h('p', { style: S.hint, key: 'cfg-loading' }, 'Loading…'))
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
          children.push(h('div', { style: S.fieldRow, key: 'cfg-' + f.field },
            h('span', { style: S.fieldLabel, title: f.help || '' }, f.label),
            h('input', {
              style: bad ? S.inputInvalid : S.input,
              value: draft,
              title: bad || f.help || '',
              onChange: (e) => { act.edit(f.field, (e && e.target && e.target.value) || '') },
            }),
            overridden ? h('span', { style: S.overrideBadge }, 'overridden') : null,
            f.browse ? h('button', {
              style: S.button,
              onClick: () => { act.openBrowser(f.field) },
              title: 'Browse folders on this machine',
            }, 'Browse…') : null,
            overridden
              ? h('button', { style: S.button, onClick: () => { act.resetField(f.field) }, title: 'Reset to default' }, 'Reset')
              : null,
          ))
        })
        children.push(h('div', { style: S.buttonRow, key: 'cfg-btns' },
          h('button', {
            style: form.saving ? S.button : S.buttonPrimary,
            disabled: !!form.saving,
            onClick: () => { act.save() },
          }, form.saving ? 'Saving…' : 'Save'),
          h('button', { style: S.button, onClick: () => { act.discard() } }, 'Discard'),
          form.message ? h('span', { style: S.ok }, form.message) : null,
          form.failed ? h('span', { style: S.err }, form.error || 'Save failed') : null,
        ))
      }

      // ---- 文件夹浏览器（模态；宿主只列目录，选择器由本 UI 渲染）----
      if (browse && browse.open) {
        const rows = []
        if (browse.path) {
          rows.push(h('button', { key: 'up', style: S.listRow, onClick: () => act.browseUp() },
            '⬆  ..  ' + (browse.parent || 'Drives')))
        }
        const entries = browse.path
          ? (browse.dirs || [])
          : (browse.drives || []).map((d) => ({ name: d, path: d, dot: false }))
        for (const d of entries) {
          rows.push(h('button', {
            key: d.path,
            style: d.dot ? S.listRowDot : S.listRow,
            title: d.dot ? d.path + '  — dot-prefixed; Ghidra rejects these as project paths' : d.path,
            onClick: () => act.browseInto(d.path),
          }, '📁  ' + d.name))
        }
        if (!entries.length) rows.push(h('p', { key: 'empty', style: S.hint }, 'No subfolders here'))
        children.push(h('div', { style: S.overlay, key: 'browse' },
          h('div', { style: S.modal },
            h('div', { style: S.head },
              h('h3', { style: S.title }, 'Choose a folder'),
              h('span', { style: S.crumb }, browse.path || 'Drives'),
            ),
            browse.error ? h('p', { style: S.err }, browse.error) : null,
            browse.message ? h('p', { style: S.ok }, browse.message) : null,
            h('div', { style: S.list }, ...rows),
            h('div', { style: S.buttonRow },
              h('input', {
                style: S.input,
                placeholder: 'new folder name',
                value: browse.newName || '',
                onChange: (e) => act.browseName((e && e.target && e.target.value) || ''),
              }),
              h('button', {
                style: S.button,
                disabled: !browse.path || !String(browse.newName || '').trim(),
                onClick: () => act.createFolder(),
              }, 'Create folder'),
            ),
            h('div', { style: S.buttonRow },
              h('button', {
                style: S.buttonPrimary,
                disabled: !browse.path || !!browse.dotSegment,
                title: browse.dotSegment ? 'Dot-prefixed path — Ghidra will reject it' : 'Use the folder shown above',
                onClick: () => act.chooseFolder(),
              }, 'Use this folder'),
              h('button', { style: S.button, onClick: () => act.closeBrowser() }, 'Cancel'),
              browse.busy ? h('span', { style: S.hint }, 'Loading…') : null,
            ),
          ),
        ))
      }

      return h('div', { style: S.card }, ...children)
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
