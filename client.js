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
      { field: 'githubToken', label: 'GitHub token (optional)', kind: 'text', help: 'Only used by "Download Ghidra" to look up the latest release. Leave empty to fall back to GH_TOKEN / GITHUB_TOKEN / gh auth token. Anonymous GitHub API calls are capped at 60/hour per IP; a token raises that to 5000/hour' },
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
    const installStore = createSnap({ running: false, phase: '', pct: 0, bytes: 0, total: 0, error: '', home: null })
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
          // bytes / total 必须一起搬过来：下面进度条的分支以 install.total 为条件，
          // 少搬这两个字段，几百 MB 的下载就只剩一个 phase 词，百分比永远不出现。
          if (ins) installStore.update({ running: !!ins.running, phase: ins.phase || '', pct: ins.pct || 0, bytes: ins.bytes || 0, total: ins.total || 0, error: ins.error || '', home: ins.home || null })
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
          // 触屏/粗指针：把控件抬到 44px 命中区（鼠标环境保持宿主的 28px 紧凑密度）。
          // !important 在这里是必需的，不是偷懒：三类元素全都带行内 min-height，而行内声明在层叠里
          // 高过任何非 !important 的作者样式（媒体查询不改变优先级）。少了它这条规则就是死的
          // ——它曾经死了一整个版本，而探针只检查字符串存在，于是一路 PASS。
          '@media (pointer: coarse){.dshg-btn,.dshg-input,.dshg-row{min-height:44px!important}}',
        ].join('')
        document.head.appendChild(el)
      } catch { /* 无 DOM 时忽略（测试环境） */ }
    }

    const S = {
      card: { border: '1px solid var(--dsw-alias-border-l2)', background: 'var(--dsw-alias-bg-layer-2)', borderRadius: 'var(--dsw-radius-md)', padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 12 },
      head: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' },
      title: { fontSize: 'var(--dsw-font-s-14-font-size)', fontWeight: 600, color: 'var(--dsw-alias-label-primary)', margin: 0 },
      badge: { fontSize: 'var(--dsw-font-xxxs-11-font-size)', padding: '1px 7px', borderRadius: 999, border: '1px solid var(--dsw-alias-border-l2)', color: 'var(--dsw-alias-label-secondary)', background: 'var(--dsw-alias-bg-layer-3)' },
      sectionTitle: { fontSize: 'var(--dsw-font-xxxs-11-font-size)', fontWeight: 600, letterSpacing: '0.06em', color: 'var(--dsw-alias-label-secondary)', margin: '2px 0 0' },
      row: { display: 'flex', gap: 8, fontSize: 'var(--dsw-font-xxs-12-font-size)', color: 'var(--dsw-alias-label-secondary)', lineHeight: 'var(--dsw-font-xxs-12-line-height)' },
      key: { color: 'var(--dsw-alias-label-secondary)', minWidth: 110, flexShrink: 0 },
      val: { color: 'var(--dsw-alias-label-primary)', wordBreak: 'break-all' },
      ok: { color: 'color-mix(in srgb, var(--dsw-alias-state-success-primary) 55%, var(--dsw-alias-label-primary))', fontSize: 'var(--dsw-font-xxs-12-font-size)' },
      err: { color: 'color-mix(in srgb, var(--dsw-alias-state-error-primary) 75%, var(--dsw-alias-label-primary))', fontSize: 'var(--dsw-font-xxs-12-font-size)', wordBreak: 'break-all' },
      idle: { color: 'color-mix(in srgb, var(--dsw-alias-state-idle-primary) 40%, var(--dsw-alias-label-primary))', fontSize: 'var(--dsw-font-xxs-12-font-size)' },
      hint: { fontSize: 'var(--dsw-font-xxs-12-font-size)', color: 'var(--dsw-alias-label-secondary)', margin: 0, lineHeight: 'var(--dsw-font-xxs-12-line-height)' },
      caption: { fontSize: 'var(--dsw-font-xxxs-11-font-size)', color: 'var(--dsw-alias-label-secondary)', margin: 0, lineHeight: 'var(--dsw-font-xxxs-11-line-height)' },
      buttonRow: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' },
      button: { fontSize: 'var(--dsw-font-xxs-12-font-size)', minHeight: 28, padding: '0 12px', borderRadius: 'var(--dsw-radius-sm)', border: '0.5px solid var(--dsw-alias-border-l4)', background: 'transparent', color: 'var(--dsw-alias-label-primary)', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 4 },
      buttonPrimary: { fontSize: 'var(--dsw-font-xxs-12-font-size)', minHeight: 28, padding: '0 12px', borderRadius: 'var(--dsw-radius-sm)', border: 'none', background: 'var(--dsw-alias-button-primary-fill)', color: 'var(--dsw-alias-label-primary-foreground)', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 4 },
      input: { fontSize: 'var(--dsw-font-xxs-12-font-size)', minHeight: 28, padding: '0 8px', borderRadius: 'var(--dsw-radius-sm)', border: '0.5px solid var(--dsw-alias-border-l4)', background: 'var(--dsw-alias-bg-layer-3)', color: 'var(--dsw-alias-label-primary)', flex: 1, minWidth: 140 },
      inputInvalid: { fontSize: 'var(--dsw-font-xxs-12-font-size)', minHeight: 28, padding: '0 8px', borderRadius: 'var(--dsw-radius-sm)', border: '0.5px solid var(--dsw-alias-state-error-primary)', background: 'var(--dsw-alias-bg-layer-3)', color: 'var(--dsw-alias-label-primary)', flex: 1, minWidth: 140 },
      fieldRow: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' },
      fieldLabel: { fontSize: 'var(--dsw-font-xxs-12-font-size)', color: 'var(--dsw-alias-label-secondary)', minWidth: 150, flexShrink: 0 },
      fieldError: { fontSize: 'var(--dsw-font-xxxs-11-font-size)', color: 'color-mix(in srgb, var(--dsw-alias-state-error-primary) 75%, var(--dsw-alias-label-primary))', flexBasis: '100%', margin: 0 },
      fieldHelp: { fontSize: 'var(--dsw-font-xxxs-11-font-size)', color: 'var(--dsw-alias-label-secondary)', lineHeight: 'var(--dsw-font-xxxs-11-line-height)', flexBasis: '100%', margin: 0 },
      overrideBadge: { fontSize: 'var(--dsw-font-xxxs-11-font-size)', padding: '0 6px', borderRadius: 999, border: '1px solid var(--dsw-alias-brand-primary)', color: 'var(--dsw-alias-brand-primary)', flexShrink: 0 },
      // 原生 <dialog> + showModal()：top-layer 堆叠、焦点陷阱、Esc 关闭、焦点归还全由浏览器负责
      // overflow:hidden 是必需的：max-height 只约束盒子，不约束内容——不剪裁的话，矮视口
      //（横屏手机、被压扁的窗口）里内容会溢出圆角边框之外，且滚动条落在对话框外面。
      // 真正的滚动交给内层 wrapper（见 BrowseDialog），这样标题和按钮行保持常驻。
      dialog: { width: 620, maxWidth: '92vw', maxHeight: '80vh', margin: 'auto', padding: 0, borderRadius: 'var(--dsw-radius-md)', border: '1px solid var(--dsw-alias-border-l2)', background: 'var(--dsw-alias-bg-layer-2)', color: 'var(--dsw-alias-label-primary)', display: 'flex', flexDirection: 'column', overflow: 'hidden' },
      crumb: { fontSize: 'var(--dsw-font-xxs-12-font-size)', color: 'var(--dsw-alias-label-secondary)', wordBreak: 'break-all', flex: 1, minWidth: 120 },
      // 不自带滚动：滚动容器只留一个（对话框内层 wrapper）。两层滚动条在矮视口下会互相嵌套。
      list: { display: 'flex', flexDirection: 'column', gap: 2, border: '1px solid var(--dsw-alias-border-l2)', borderRadius: 'var(--dsw-radius-sm)', padding: 6, background: 'var(--dsw-alias-bg-layer-3)' },
      listRow: { display: 'flex', alignItems: 'center', gap: 8, minHeight: 32, padding: '0 8px', borderRadius: 'var(--dsw-radius-sm)', cursor: 'pointer', fontSize: 'var(--dsw-font-xxs-12-font-size)', color: 'var(--dsw-alias-label-primary)', background: 'transparent', border: 'none', textAlign: 'left', width: '100%' },
      dotBadge: { fontSize: 'var(--dsw-font-xxxs-11-font-size)', padding: '0 5px', borderRadius: 999, border: '1px solid color-mix(in srgb, var(--dsw-alias-state-warn-primary) 70%, var(--dsw-alias-label-primary))', color: 'color-mix(in srgb, var(--dsw-alias-state-warn-label) 70%, var(--dsw-alias-label-primary))', flexShrink: 0 },
      icon: { flexShrink: 0, color: 'var(--dsw-alias-menu-icon)' },
    }

    // 内联 SVG 图标（不用 emoji：跨平台渲染不一致，且无法继承 currentColor）
    const IconFolder = () => h('svg', { width: 14, height: 14, viewBox: '0 0 16 16', 'aria-hidden': 'true', focusable: 'false', style: S.icon },
      h('path', { d: 'M1.5 4.2c0-.6.5-1.1 1.1-1.1h3.1l1.2 1.4h6.5c.6 0 1.1.5 1.1 1.1v6.2c0 .6-.5 1.1-1.1 1.1H2.6c-.6 0-1.1-.5-1.1-1.1V4.2z', fill: 'none', stroke: 'currentColor', strokeWidth: 1.2, strokeLinejoin: 'round' }))
    const IconUp = () => h('svg', { width: 14, height: 14, viewBox: '0 0 16 16', 'aria-hidden': 'true', focusable: 'false', style: S.icon },
      h('path', { d: 'M8 12.5V3.5M4 7.5 8 3.5l4 4', fill: 'none', stroke: 'currentColor', strokeWidth: 1.2, strokeLinecap: 'round', strokeLinejoin: 'round' }))

    // 目录行：memo + 自定义比较器（只比数据，不比回调身份）——
    // 过滤框每敲一个字都重渲染整张列表时，只有真正变化的行会重画。
    const memoize = React.memo
    const FolderRow = memoize(function FolderRow(props) {
      return h('button', { type: 'button',
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
    //
    // useSyncExternalStore 是 React 为「订阅外部 store」提供的标准 API。手写的
    // subscribe-in-useEffect 版本有一个丢更新的窗口：订阅建立之前发生的 store 写入不会被看到
    // （首帧到 effect 之间），要等下一次写入才补上。useSyncExternalStore 在订阅后会立刻核对一次。
    // 测试 stub 没有这个 hook，所以保留一条回退路径（hook 序列在任一环境内是稳定的）。
    const useSnap = (store, selector) => {
      const sel = selector || ((s) => s)
      // useCallback/useState/useEffect 从 React 16.8 起就有，直接用；
      // useSyncExternalStore 是 React 18 才引入的，而这个插件用的是宿主的 React、自身不锁定版本，
      // 所以只有它保留一条回退路径（hook 序列在任一环境内都是稳定的）。
      const subscribe = React.useCallback((onChange) => store.subscribe(onChange), [store])
      const getSnapshot = React.useCallback(() => sel(store.getSnapshot()), [store, sel])
      if (React.useSyncExternalStore) return React.useSyncExternalStore(subscribe, getSnapshot)
      const [snap, setSnap] = React.useState(getSnapshot)
      React.useEffect(() => {
        setSnap(getSnapshot())
        const off = store.subscribe(() => setSnap(getSnapshot()))
        return () => { try { off() } catch {} }
      }, [store])
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

      // 操作：只用闭包动作（组件不读 props）。
      // 已核实的宿主契约：settings.section 的调用点是
      //   renderSlot("settings.section", { close: onClose }, { only: active })
      // —— 显式 props 只有 { close }。渲染器会解析注册项的 inject，但它的 runInject 首行就是
      // `if (!inject) return EMPTY_INJECTED_PROPS`：没有 inject 是受支持的分支。既然组件只用
      // 这里的闭包动作，注册项那边就不再挂一个没人读的 inject（见 apply() 末尾）。
      // 历史上「props 优先、闭包兜底」的双路写法已删除。
      // 卡片自己用的动作。目录对话框拿的是另一张更窄的表（browseAct）——原来这里是一个 15 成员的
      // 袋子整体透传下去，其中 refresh / stopMcp 从来没有人通过它调用过（卡片直接调的是闭包）。
      const act = {
        save,
        discard,
        edit,
        resetField,
        runDoctor,
        installGhidra,
        openBrowser,
      }
      const browseAct = {
        browseInto: loadDir,
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
      // 分区标题必须是标题元素，不是加粗的 <p>：屏幕阅读器靠标题大纲跳转分区，
      // 视觉上完全一样、语义上完全缺失，是最典型的“做了样式没做结构”。
      children.push(h('h4', { style: S.sectionTitle, key: 'st-title' }, 'Status'))
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
        h('button', { type: 'button', className: 'dshg-btn', style: S.button, onClick: refreshStatus }, status && status.loading ? 'Refreshing…' : 'Refresh'),
        mcp && mcp.running
          ? h('button', { type: 'button', className: 'dshg-btn', style: S.button, onClick: stopMcp, title: 'Gracefully stop the upstream GhidraMCP server (saves loaded programs before exit)' }, 'Stop MCP server')
          : null,
        h('button', { type: 'button',
          className: 'dshg-btn',
          style: S.button,
          onClick: act.installGhidra,
          disabled: !!(install && install.running),
          title: 'Download the latest Ghidra release from GitHub, extract it next to the current home and switch the home to it (the old home is deleted)',
        }, install && install.running ? 'Downloading…' : 'Download Ghidra'),
      ))
      // 常驻 live region：读屏只在「已存在的区域内容变了」时才可靠播报，把 role 和文本同时插进
      // DOM 往往一声不吭（WCAG 4.1.3）。所以区域无条件渲染，只换里面的文字；空文本高度为 0。
      children.push(h('p', { style: S.hint, key: 'st-install', role: 'status', 'aria-busy': install && install.running ? 'true' : undefined },
        install && install.running
          ? (install.phase || 'working…') + (install.total ? ' · ' + install.pct + '% (' + Math.round(install.bytes / 1048576) + '/' + Math.round(install.total / 1048576) + ' MB)' : '')
          : install && !install.error && install.home
            ? 'Installed → ' + install.home
            : (install && !install.error && install.phase) || '',
      ))
      children.push(h('p', { style: S.err, key: 'st-install-err', role: 'alert' },
        install && install.error ? 'Install failed: ' + install.error : '',
      ))

      // ---- doctor：健康检查 ----
      children.push(h('div', { style: S.buttonRow, key: 'doc-head' },
        h('h4', { style: S.sectionTitle }, 'Health check'),
        h('button', { type: 'button',
          className: 'dshg-btn',
          style: S.button,
          onClick: act.runDoctor,
          disabled: !!(doctor && doctor.running),
          title: 'Check Ghidra install, launcher scripts, Python and both servers',
        }, doctor && doctor.running ? 'Checking…' : 'Run doctor'),
      ))
      children.push(h('p', { style: S.err, key: 'doc-err', role: 'alert' }, (doctor && doctor.error) || ''))
      const dr = (doctor && doctor.result && doctor.result.checks) ? doctor.result : null
      children.push(h('p', { style: dr && !dr.ok ? S.err : S.ok, key: 'doc-sum', role: 'status' },
        dr
          ? (dr.ok
            ? 'All essential checks passed (' + dr.essentialOk + '/' + dr.essentialTotal + ')' + (dr.runtimeIdle ? ' · ' + dr.runtimeIdle + ' runtime check(s) idle' : '')
            : 'Essential checks: ' + dr.essentialOk + '/' + dr.essentialTotal + ' passed')
          : '',
      ))
      if (dr) {
        const docRows = doctor.result.checks.map((c, i) => {
          const label = c.ok ? 'OK' : (c.optional ? 'IDLE' : 'FAIL')
          const style = c.ok ? S.ok : (c.optional ? S.idle : S.err)
          // 失败项把 remediation 一并显示出来：自检的价值在于「怎么修」，只挂在 tooltip 里等于没有。
          const detail = c.detail + (!c.ok && c.hint ? ' — ' + c.hint : '')
          return h('div', { style: S.row, key: 'doc-' + i, role: 'listitem', title: c.hint || '' },
            h('span', { style: { ...style, minWidth: 38, flexShrink: 0, fontWeight: 600 } }, label),
            h('span', { style: S.key }, c.name),
            h('span', { style: c.optional && !c.ok ? S.hint : S.val }, detail),
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
      children.push(h('h4', { style: S.sectionTitle, key: 'cfg-title' }, 'Config'))
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
              // 帮助文本不能只挂在 title 上：title 只有鼠标悬停看得到，键盘与读屏都拿不到，
              // 而这几条帮助恰恰是在说「这么填会失败」。改成 aria-describedby 指向正文里的段落。
              'aria-describedby': [bad ? fieldId + '-err' : null, f.help ? fieldId + '-help' : null].filter(Boolean).join(' ') || undefined,
              onChange: (e) => { act.edit(f.field, (e && e.target && e.target.value) || '') },
            }),
            overridden ? h('span', { style: S.overrideBadge }, 'overridden') : null,
            f.browse ? h('button', { type: 'button',
              className: 'dshg-btn',
              style: S.button,
              onClick: () => { act.openBrowser(f.field) },
              title: 'Browse folders on this machine',
              'aria-label': 'Browse folders for ' + f.label,
            }, 'Browse…') : null,
            overridden
              ? h('button', { type: 'button',
                className: 'dshg-btn',
                style: S.button,
                onClick: () => { act.resetField(f.field) },
                title: 'Reset to default',
                'aria-label': 'Reset ' + f.label + ' to default',
              }, 'Reset')
              : null,
            f.help ? h('p', { id: fieldId + '-help', style: S.fieldHelp, key: fieldId + '-help' }, f.help) : null,
            bad ? h('p', { id: fieldId + '-err', style: S.fieldError, key: fieldId + '-err' }, bad) : null,
          ))
        })
        children.push(h('div', { style: S.buttonRow, key: 'cfg-btns' },
          h('button', { type: 'button',
            className: form.saving ? 'dshg-btn' : 'dshg-btn dshg-primary',
            style: form.saving ? S.button : S.buttonPrimary,
            disabled: !!form.saving,
            onClick: act.save,
          }, form.saving ? 'Saving…' : 'Save'),
          h('button', { type: 'button', className: 'dshg-btn', style: S.button, onClick: act.discard }, 'Discard'),
          // 常驻 live region（同上）：文本来了才插入的 region 读屏经常不播报。
          h('span', { style: S.ok, role: 'status' }, form.message || ''),
          h('span', { style: S.err, role: 'alert' }, form.failed ? (form.error || 'Save failed') : ''),
        ))
      }

      // ---- 文件夹浏览器：独立组件 + 细粒度订阅（见 BrowseDialog 定义）----
      children.push(browseOpen ? h(BrowseDialog, { key: 'browse', act: browseAct }) : null)

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
      const all = browse.path
        ? (browse.dirs || [])
        : (browse.drives || []).map((d) => ({ name: d, path: d, dot: false }))
      const q = String(folderFilter || '').trim().toLowerCase()
      const filtered = q ? all.filter((d) => String(d.name).toLowerCase().includes(q)) : all
      const CAP = 150
      const entries = filtered.slice(0, CAP)
      const rows = []
      if (browse.path) {
        rows.push(h('button', { type: 'button',
          key: 'up', className: 'dshg-row', style: S.listRow,
          onClick: act.browseUp,
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
        onCancel: act.closeBrowser,
        onClick: (e) => { if (e && e.target === e.currentTarget) act.closeBrowser() },
      },
        // minHeight:0 让这个 flex 子项能真正收缩到内容高度以下（否则 min-height:auto 把它顶开），
        // overflowY:auto 才是那个滚动容器 —— 矮视口下依然能滚到「Use this folder」。
        h('div', { style: { display: 'flex', flexDirection: 'column', gap: 10, padding: '14px 16px', minHeight: 0, overflowY: 'auto' } },
        h('div', { style: S.head },
          h('h3', { id: 'dshg-browse-title', style: S.title }, 'Choose a folder'),
          h('span', { style: S.crumb }, browse.path || 'Drives'),
        ),
        // 常驻 live region（同上）。
        h('p', { style: S.err, role: 'alert' }, browse.error || ''),
        h('p', { style: S.ok, role: 'status' }, browse.message || ''),
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
          h('button', { type: 'button',
            className: 'dshg-btn',
            style: S.button,
            disabled: !browse.path || !String(browse.newName || '').trim(),
            onClick: act.createFolder,
          }, 'Create folder'),
        ),
        h('div', { style: S.buttonRow },
          h('button', { type: 'button',
            className: 'dshg-btn dshg-primary',
            style: S.buttonPrimary,
            disabled: !browse.path || !!browse.dotSegment,
            title: browse.dotSegment ? 'Dot-prefixed path — Ghidra will reject it' : 'Use the folder shown above',
            onClick: act.chooseFolder,
          }, 'Use this folder'),
          h('button', { type: 'button', className: 'dshg-btn', style: S.button, onClick: act.closeBrowser }, 'Cancel'),
          browse.busy ? h('span', { style: S.hint, role: 'status' }, 'Loading…') : null,
        ),
        ),
      )
    }

    // 这里曾有一个 `face` 对象（hooks + refresh/save/discard/edit/resetField/stopMcp），
    // 经 `inject: () => face` 注入成 props。但组件侧早已改为只用闭包动作（见 GhidraCard 顶部注释），
    // 于是那份 face 每次渲染都被构造、被 bindInjectSources 绑定、再被原样丢弃 —— 一个没人读的层。
    // 删除它是安全的：宿主渲染器的 runInject 首行就是 `if (!inject) return EMPTY_INJECTED_PROPS`，
    // 「没有 inject」是框架明确支持的分支，不是异常路径。

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
        }, GhidraCard)), 'name')
        refreshStatus()
      },
    }
  },
})
