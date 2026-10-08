// 回归探针：「Download Ghidra」的 GitHub 403。
// 根因不是权限而是配额 —— 匿名 GitHub API 只有 60 次/小时，而且【按 IP 计】，
// 共享出口后面别人用完了，我们这边也一样 403。旧代码把响应的 body 和配额头全丢了，
// 只抛 'GitHub API 403' 给面板，用户看不到「什么时候能重试」和「怎么修」。
//
// 本探针断言的是【效果】，不是声明字符串是否存在（同一个洞在本仓库出现过两次）：
//   1. 有 token 时，请求真的带上了 Authorization 头（不是"代码里写了这个分支"）
//   2. 没 token 时，错误文本真的包含恢复时间与补救办法
//   3. POSIX 平台真的不再调用 powershell（Linux 上根本没有这个命令）
//   4. 资产下载真的绕开 undici 的 fetch（本机实测 fetch ~6 MB/s、node:https 31 MB/s，
//      差 5~6 倍；判据是"把 fetch 换成会抛错的桩，下载照样完成"）
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { readFileSync, rmSync } from 'node:fs'
import { fileUrl, installedDir, REPO_ROOT } from './lib/dev-env.mjs'

const results = []
const check = (name, ok, detail) => { results.push({ name, ok, detail }); console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  :: ' + detail : '')) }
const info = (name, detail) => console.log('INFO  ' + name + (detail ? '  :: ' + detail : ''))

// ---- 环境孤立：先摘掉 PATH，让 `gh` 不可解析，否则本机的 gh 登录会让「匿名」用例失去意义
const saved = { PATH: process.env.PATH, GH_TOKEN: process.env.GH_TOKEN, GITHUB_TOKEN: process.env.GITHUB_TOKEN }
const restoreEnv = () => {
  process.env.PATH = saved.PATH
  if (saved.GH_TOKEN === undefined) delete process.env.GH_TOKEN; else process.env.GH_TOKEN = saved.GH_TOKEN
  if (saved.GITHUB_TOKEN === undefined) delete process.env.GITHUB_TOKEN; else process.env.GITHUB_TOKEN = saved.GITHUB_TOKEN
}

// ---- mock 宿主（与 probe-v4-routes.mjs 同一套形状）----
const routes = []
const mockCtx = {
  tools: { register(d) { routes.push({ tool: d }); return () => {} } },
  jobs: { background() { return 'job-x' } },
  inject(names, cb) {
    return cb({ webServer: { exact: new Map(), prefixes: new Map(), register(r) { routes.push(r); return () => {} } } })
  },
  effect(fn) { return fn() },
  on() { return () => {} },
}

let TOKEN = ''
const cfg = {}
for (const k of ['ghidraHome', 'ghidraProjectDir', 'projectName', 'pythonVer', 'analysisTimeoutSec', 'serverStartupTimeoutMs', 'maxOutputChars', 'stream', 'mcpPort', 'mcpStartupTimeoutSec', 'mcpTimeoutSec', 'githubToken']) {
  cfg[k] = { get: () => undefined }
}
cfg.pythonVer = { get: () => '3.13' }
cfg.githubToken = { get: () => TOKEN }
// 重新 apply 才会重算 currentConfig 快照（githubToken() 读的是快照里解析后的普通值）
const setToken = (v) => { TOKEN = v; mod.apply(mockCtx, cfg) }

const mod = await import(fileUrl(join(installedDir('web'), 'index.js')) + '?probe=' + Date.now())
setToken('')

const byPath = Object.fromEntries(routes.filter((r) => r.path && r.path.startsWith('/api/dsh-ghidra')).map((r) => [r.path, r]))

const mkReq = (method, body) => {
  const handlers = {}
  const req = { socket: { remoteAddress: '127.0.0.1' }, method, on(ev, fn) { handlers[ev] = fn; return req } }
  setTimeout(() => { if (body !== undefined && handlers.data) handlers.data(body); if (handlers.end) handlers.end() }, 5)
  return req
}
const mkRes = () => {
  const res = { statusCode: 0, body: null }
  res.writeHead = (s) => { res.statusCode = s; return res }
  res.end = (b) => { res.body = b; return res }
  return res
}
const callRoute = async (path, method, body) => {
  const res = mkRes()
  await byPath[path].handler(mkReq(method, body), res)
  let parsed = null
  try { parsed = JSON.parse(res.body) } catch {}
  return { status: res.statusCode, body: parsed }
}

// ---- fetch 桩：只拦 GitHub，其余（插件内部的 mcpHealth 等本机探活）原样放行 ----
// 不能整锅替换 globalThis.fetch：/status 会顺带探活 GhidraMCP 端口，那些请求会把
// 桩的响应队列抽干，于是下载那次 fetch 拿到空队列、报出一个与真实根因无关的错误。
const realFetch = globalThis.fetch
const GH_URL = /^https:\/\/(api\.github\.com\/|github\.com\/NationalSecurityAgency\/)/
let calls = []
const stubFetch = (responses) => {
  calls = []
  globalThis.fetch = async (url, opts) => {
    const u = String(url)
    if (!GH_URL.test(u)) return realFetch(url, opts)
    calls.push({ url: u, headers: (opts && opts.headers) || {} })
    const r = responses.shift()
    if (!r) throw new Error('unexpected fetch: ' + u)
    return r
  }
}

const RESET = Math.floor(Date.now() / 1000) + 2700   // 约 45 分钟后
const rateLimited = () => new Response(
  JSON.stringify({ message: 'API rate limit exceeded for 105.98.99.57. (But here\'s the good news: Authenticated requests get a higher rate limit.)' }),
  { status: 403, statusText: 'rate limit exceeded', headers: {
    'content-type': 'application/json', 'x-ratelimit-limit': '60', 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(RESET),
  } })

// 真实抓下来的 release 形状（2026-10-08 实测）
const releaseJson = (dlUrl) => new Response(JSON.stringify({
  tag_name: 'Ghidra_12.1.4_build',
  assets: [
    // 诱饵：真实的 Ghidra release 里就有这种 .zip.sha256 资产，名字里同样含 _PUBLIC_
    { name: 'ghidra_12.1.4_PUBLIC_20260921.zip.sha256', size: 128, browser_download_url: dlUrl + '?decoy=1' },
    { name: 'ghidra_12.1.4_PUBLIC_20260921.zip', size: 569732197, browser_download_url: dlUrl },
  ],
}), { status: 200, headers: { 'content-type': 'application/json' } })

const settle = async () => {
  for (let i = 0; i < 400; i++) {
    const s = await callRoute('/api/dsh-ghidra/status', 'GET')
    if (s.body && s.body.install && !s.body.install.running) return s.body.install
    await new Promise((r) => setTimeout(r, 25))
  }
  throw new Error('install 状态一直没有停下')
}
const startInstall = () => callRoute('/api/dsh-ghidra/install-ghidra', 'POST', JSON.stringify({ force: true }))

// ---- 本机资产服务器 ----
// 下载改成 node:https 之后，fetch 桩就再也拦不到它了（这正是修复的本体），所以下载层
// 只能用真的 HTTP 服务来验。顺带拿到了真实请求头：以前「下载不带 Authorization」是从
// 桩里推断的，现在是服务器实际观察到的。
const PAYLOAD = Buffer.alloc(8 * 1024 * 1024)
for (let i = 0; i < PAYLOAD.length; i++) PAYLOAD[i] = i % 251
const PAYLOAD_SHA = createHash('sha256').update(PAYLOAD).digest('hex')
const seen = []
let port = 0
const assetSrv = createServer((req, res) => {
  seen.push({ url: req.url, headers: req.headers })
  if (req.url === '/download-404') { res.writeHead(404); res.end('nope'); return }
  if (req.url === '/loop') { res.writeHead(302, { location: 'http://127.0.0.1:' + port + '/loop' }); res.end(); return }
  if (req.url === '/download') { res.writeHead(302, { location: '/file' }); res.end(); return }
  if (req.url === '/file') {
    res.writeHead(200, { 'content-type': 'application/zip', 'content-length': String(PAYLOAD.length) })
    res.end(PAYLOAD)
    return
  }
  res.writeHead(404); res.end('nope')
})
await new Promise((r) => assetSrv.listen(0, '127.0.0.1', r))
port = assetSrv.address().port
const assetUrl = (p) => 'http://127.0.0.1:' + port + p

// ============ 1. 解压计划按平台挑（Linux 移植点）============
const win = mod.extractPlan('win32', 'C:\\z.zip', 'C:\\out')
const lin = mod.extractPlan('linux', '/tmp/z.zip', '/opt/ghidra')
const mac = mod.extractPlan('darwin', '/tmp/z.zip', '/opt/ghidra')
check('win32 仍用 PowerShell Expand-Archive（Windows 非回归）',
  win.length === 1 && win[0].file === 'powershell' && /Expand-Archive/.test(win[0].args.join(' ')),
  win.map((c) => c.file).join(','))
check('linux 用 unzip，不再调 powershell（Linux 上没有 powershell 命令）',
  lin.length === 1 && lin[0].file === 'unzip' && !/powershell/i.test(lin.map((c) => c.file).join(',')),
  lin.map((c) => c.file + ' ' + c.args.join(' ')).join(' | '))
check('darwin 用 unzip（macOS 自带）', mac.length === 1 && mac[0].file === 'unzip', mac.map((c) => c.file).join(','))
check('unzip 参数真的带上了 zip 路径与解压目标',
  lin[0].args.includes('/tmp/z.zip') && lin[0].args.includes('/opt/ghidra'), lin[0].args.join(' '))

// ============ 2. token 解析优先级（PATH 仍然摘掉，隔离出真正的「无来源」）============
process.env.PATH = ''
delete process.env.GH_TOKEN
delete process.env.GITHUB_TOKEN
check('三种来源都缺时返回空 token（走匿名，这正是本次报障的情形）',
  mod.githubToken({}).token === '', JSON.stringify(mod.githubToken({})))
process.env.GH_TOKEN = 'ENV_TOKEN'
check('回退 GH_TOKEN', mod.githubToken({}).source === 'GH_TOKEN' && mod.githubToken({}).token === 'ENV_TOKEN', mod.githubToken({}).source)
delete process.env.GH_TOKEN
process.env.GITHUB_TOKEN = 'ENV2_TOKEN'
check('再回退 GITHUB_TOKEN', mod.githubToken({}).source === 'GITHUB_TOKEN', mod.githubToken({}).source)
delete process.env.GITHUB_TOKEN
check('配置里的 token 优先级最高（盖过环境变量）',
  mod.githubToken({ githubToken: 'CFG_TOKEN' }).token === 'CFG_TOKEN' && mod.githubToken({ githubToken: 'CFG_TOKEN' }).source === 'config',
  mod.githubToken({ githubToken: 'CFG_TOKEN' }).source)

// ============ 3. 403 配额：错误必须可行动 ============
if (!byPath['/api/dsh-ghidra/install-ghidra']) { check('install-ghidra 路由存在', false, 'missing') } else {
  // 3a. 匿名 + 配额用尽（PATH 仍为空 → 真的一个 token 都拿不到）
  stubFetch([rateLimited()])
  await startInstall()
  const ins = await settle()
  check('匿名请求没有带 Authorization（真的在复现用户那次匿名调用）',
    calls.length === 1 && !calls[0].headers.authorization, 'calls=' + calls.length + ' auth=' + String(calls[0] && calls[0].headers.authorization))
  check('403 的错误文本告诉用户是【配额】而不是权限', /配额用尽/.test(ins.error), ins.error.slice(0, 90))
  check('错误文本给出恢复时间（用户知道等多久）',
    /恢复/.test(ins.error) && /约 \d+ 分钟后/.test(ins.error), ins.error.slice(0, 130))
  check('错误文本给出补救办法（token 的三种来源 + 配额数字）',
    /GH_TOKEN/.test(ins.error) && /githubToken/.test(ins.error) && /5000/.test(ins.error), ins.error.slice(-150))
  check('不再是对用户毫无信息量的 "GitHub API 403"（旧形态必须消失）',
    !/^GitHub API 403/.test(ins.error), ins.error.slice(0, 60))
  check('服务器原话被保留（含 IP，能判断是不是共享出口被别人用完）',
    /105\.98\.99\.57/.test(ins.error), '')

  restoreEnv()
  const ghTok = mod.githubToken({})
  info('gh auth token 兜底', ghTok.token ? '找到（source=' + ghTok.source + '，长度 ' + ghTok.token.length + '）' : '本机没有可用 gh 登录，该分支未覆盖')

  // 3b. 配了 token → 请求必须真的带上 Authorization（本 bug 的修复本体）
  setToken('CFG_TOKEN')
  stubFetch([rateLimited()])
  await startInstall()
  await settle()
  check('配置了 githubToken 后，请求真的带上 Authorization: Bearer',
    calls.length === 1 && calls[0].headers.authorization === 'Bearer CFG_TOKEN',
    'auth=' + String(calls[0] && calls[0].headers.authorization))

  // 3c. release 解析成功 → 真的选中 *_PUBLIC_*.zip，下载走本机资产服务器
  stubFetch([releaseJson(assetUrl('/download-404'))])
  await startInstall()
  const ins3 = await settle()
  check('release JSON 解析后选中了真正的 *_PUBLIC_*.zip 资产（跳过 .zip.sha256 诱饵）',
    String(ins3.log) === assetUrl('/download-404'), 'log=' + String(ins3.log).slice(0, 90))
  check('资源下载失败时错误是下载层的（说明 API 这一层已经过了）',
    /download failed: HTTP 404/.test(ins3.error), ins3.error.slice(0, 90))
  check('API 查询走 fetch、下载不走 fetch（下载层不出现在 undici 的调用记录里）',
    calls.length === 1, 'fetch 调用次数=' + calls.length)
  setToken('')
}

// ============ 4. 下载层：绕开 fetch、跟随重定向、字节一致、错误可辨 ============
const dlDest = join(tmpdir(), 'dsh-ghidra-probe-dl.zip')
rmSync(dlDest, { force: true })

let ticks = 0
let tickBytes = 0
await mod.downloadToFile(assetUrl('/download'), dlDest, (n) => { ticks++; tickBytes += n })
const onDisk = readFileSync(dlDest)
check('downloadToFile 跟随 302 并写出与源逐字节一致的文件',
  onDisk.length === PAYLOAD.length && createHash('sha256').update(onDisk).digest('hex') === PAYLOAD_SHA,
  onDisk.length + ' bytes，sha256 一致')
check('onBytes 是流式回调（进度条靠它，不是传完才一次性调用）',
  ticks > 1 && tickBytes === PAYLOAD.length, ticks + ' 次回调，合计 ' + tickBytes + ' bytes')

const dlSeen = seen.filter((s) => s.url === '/download' || s.url === '/file')
check('下载的两个请求都不带 Authorization（公开资源；跨主机重定向会把它丢掉）',
  dlSeen.length === 2 && dlSeen.every((s) => !s.headers.authorization), '服务器实际看到 ' + dlSeen.length + ' 个请求')

let e404 = ''
try { await mod.downloadToFile(assetUrl('/download-404'), dlDest, () => {}) } catch (e) { e404 = String(e.message) }
check('404 报下载层错误，而不是静默留下一个空文件', e404 === 'download failed: HTTP 404', e404)

let eLoop = ''
try { await mod.downloadToFile(assetUrl('/loop'), dlDest, () => {}) } catch (e) { eLoop = String(e.message) }
check('重定向环不会无限跟随（上限 5 跳）', /too many redirects/.test(eLoop), eLoop)

// 本条是本次修复的本体：把 globalThis.fetch 换成会抛错的桩，下载仍必须照常完成。
const fetchBefore = globalThis.fetch
let fetchHits = 0
globalThis.fetch = async () => { fetchHits++; throw new Error('downloadToFile 不该碰 fetch') }
let dlOk = true
try { await mod.downloadToFile(assetUrl('/file'), dlDest, () => {}) } catch { dlOk = false }
globalThis.fetch = fetchBefore
check('下载完全不经过 globalThis.fetch（undici 本机 ~6 MB/s、node:https 31 MB/s）',
  fetchHits === 0 && dlOk, 'fetch 调用次数=' + fetchHits)
rmSync(dlDest, { force: true })

// ============ 5. 面板必须真的能填这个 token ============
// client.js 的 FIELDS 是手写清单（和 sync-installed.mjs 的 FILES 同一个坑）：
// 配置字段加了却没进 FIELDS，面板上永远填不了，而服务端一切正常。
const fieldRefs = (readFileSync(join(REPO_ROOT, 'client.js'), 'utf8').match(/field:\s*'/g) || []).length
check('面板 FIELDS 里有 githubToken（否则用户没地方填，只能靠环境变量）',
  /field:\s*'githubToken'/.test(readFileSync(join(REPO_ROOT, 'client.js'), 'utf8')), '')
check('面板字段数与 Config 字段数一致（两处手写清单不许漂移）', fieldRefs === 13, 'FIELDS=' + fieldRefs + ' Config=13')

globalThis.fetch = realFetch
assetSrv.close()

console.log('')
const fails = results.filter((r) => !r.ok).length
console.log('=== ' + (fails ? 'PROBE FAILED: ' + fails + ' fail(s)' : 'PROBE PASSED: ' + results.length + '/' + results.length) + ' ===')
process.exit(fails ? 1 : 0)
