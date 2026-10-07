// probe-union-args.mjs — 验收「categories/types 的 oneOf 双形状」
// 层 1：把已装副本里声明的 parameters 用 dsh-tools 的编译器编译（等价注册时校验）。
// 层 2：validateArgs 用 string 与 array 两种形状各调一次（等价调用时校验）。
// 层 3：编译出的 raw JSON Schema 应含 oneOf（模型侧会看到两种形状）。
import { pathToFileURL } from 'node:url'
import { dshToolsEntry, fileUrl, installedDir } from './lib/dev-env.mjs'

const DSH_TOOLS = fileUrl(dshToolsEntry())
const { validateJsonSchemaValue } = await import(DSH_TOOLS)

const dir = process.argv[2]
  || installedDir('web')
const mod = await import(pathToFileURL(dir.endsWith('/index.js') ? dir : dir + '/index.js').href)

const registered = []
const ctx = {
  effect(fn) { return fn() },
  tools: { register(t) { registered.push(t) } },
  jobs: { start() { return { id: 'stub' } } },
  logger: console,
}
await mod.apply(ctx, mod.Config({}))

const targets = ['ghidra_detect_malware_behaviors', 'ghidra_extract_iocs_with_context']
let failed = 0

for (const name of targets) {
  const tool = registered.find(t => t.name === name)
  if (!tool) { console.log(`FAIL 找不到工具 ${name}`); failed++; continue }
  const spec = tool.parameters
  /* tool.parameters 已是 defineTool 编译后的 raw JSON Schema（schema.js:295/301），直接校验即可 */
  const key = name === 'ghidra_detect_malware_behaviors' ? 'categories' : 'types'
  const hasOneOf = spec?.properties?.[key]?.oneOf != null
  console.log(`${hasOneOf ? 'PASS' : 'FAIL'} ${name} raw schema 含 oneOf`)
  if (!hasOneOf) failed++

  const cases = [
    ['string', { [key]: 'process-injection,c2-network' }],
    ['array', { [key]: ['process-injection', 'c2-network'] }],
    ['empty-array', { [key]: [] }],
    ['number(负对照)', { [key]: 42 }],
  ]
  for (const [shape, args] of cases) {
    const violations = validateJsonSchemaValue(spec, args, '')
    const expectReject = shape.includes('负对照')
    if (expectReject ? violations.length > 0 : violations.length === 0) {
      console.log(`PASS ${name} validate(${shape})${expectReject ? ' 拒绝' : ''}`)
    } else {
      console.log(`FAIL ${name} validate(${shape}): ${violations.join('; ')}`)
      failed++
    }
  }
}

console.log(failed === 0 ? '=== UNION ARGS PROBE PASSED ===' : `=== ${failed} FAILURES ===`)
process.exit(failed === 0 ? 0 : 1)
