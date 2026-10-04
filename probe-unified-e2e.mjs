// 统一模式端到端：直接对桥的 TCP JSON-RPC 端口验证 mcpServe / mcpState / mcpStop，
// 并确认上游 REST 服务器跑在**桥的同一个 JVM** 内、作用于**同一个程序**。
import net from 'node:net'

const port = Number(process.argv[2])
const mcpPort = Number(process.argv[3] || 8123)
if (!port) { console.error('usage: node probe-unified-e2e.mjs <bridgePort> [mcpPort]'); process.exit(2) }

const results = []
const check = (name, ok, detail) => { results.push(ok); console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  :: ' + detail : '')) }

const call = (op, extra = {}, timeoutMs = 90000) => new Promise((resolve, reject) => {
  const sock = net.connect({ host: '127.0.0.1', port }, () => {
    sock.write(JSON.stringify({ op, ...extra }) + '\n')
  })
  let buf = ''
  const timer = setTimeout(() => { sock.destroy(); reject(new Error('timeout after ' + timeoutMs + 'ms for op=' + op)) }, timeoutMs)
  sock.on('data', (d) => {
    buf += d.toString('utf8')
    const nl = buf.indexOf('\n')
    if (nl >= 0) {
      clearTimeout(timer); sock.end()
      const line = buf.slice(0, nl)
      try { resolve(JSON.parse(line)) } catch (e) { reject(new Error('bad json: ' + line.slice(0, 200))) }
    }
  })
  sock.on('error', (e) => { clearTimeout(timer); reject(e) })
})

const rest = async (path) => {
  const r = await fetch('http://127.0.0.1:' + mcpPort + path, { signal: AbortSignal.timeout(20000) })
  const t = await r.text()
  try { return { status: r.status, body: JSON.parse(t) } } catch { return { status: r.status, body: t } }
}

// 1) 初始状态
try {
  const st = await call('mcpState')
  check('mcpState 初始可用（新脚本已加载）', st.ok === true, JSON.stringify(st.result || st))
  check('初始未运行', !!(st.result && st.result.running === false), JSON.stringify(st.result))
} catch (e) { check('mcpState 初始可用（新脚本已加载）', false, String(e.message)) }

// 2) 启动 unified
let serve = null
try {
  serve = await call('mcpServe', { port: mcpPort, bind: '127.0.0.1' }, 120000)
  check('mcpServe 返回 ok', serve.ok === true, JSON.stringify(serve.result || serve).slice(0, 300))
  check('mcpServe 报告 unified + 端口 + 程序', !!(serve.result && serve.result.mode === 'unified' && serve.result.port === mcpPort && serve.result.program),
    JSON.stringify(serve.result))
} catch (e) { check('mcpServe 返回 ok', false, String(e.message)) }

// 3) REST 是否服务同一程序
try {
  const h = await rest('/health')
  check('REST /health 健康', h.status === 200 && h.body && h.body.status === 'healthy', JSON.stringify(h.body).slice(0, 200))
  const fc = await rest('/get_function_count')
  check('REST 读到桥的同一程序（函数数一致）',
    !!(fc.body && fc.body.program && fc.body.function_count > 0),
    'program=' + (fc.body && fc.body.program) + ' functions=' + (fc.body && fc.body.function_count))
} catch (e) { check('REST /health 健康', false, String(e.message)) }

// 4) 状态再确认（在跑）
try {
  const st = await call('mcpState')
  check('mcpState 报告在跑', !!(st.result && st.result.running === true && st.result.port === mcpPort), JSON.stringify(st.result))
} catch (e) { check('mcpState 报告在跑', false, String(e.message)) }

// 5) 停止
try {
  const stop = await call('mcpStop')
  check('mcpStop 返回 ok', stop.ok === true, JSON.stringify(stop.result || stop))
  await new Promise((r) => setTimeout(r, 1500))
  const st = await call('mcpState')
  check('停止后 mcpState 报告未运行', !!(st.result && st.result.running === false), JSON.stringify(st.result))
} catch (e) { check('mcpStop 返回 ok', false, String(e.message)) }

console.log('')
const fails = results.filter((x) => !x).length
console.log('=== ' + (fails ? 'UNIFIED E2E FAILED: ' + fails + ' fail(s)' : 'UNIFIED E2E PASSED: ' + results.length + '/' + results.length) + ' ===')
process.exit(fails ? 1 : 0)
