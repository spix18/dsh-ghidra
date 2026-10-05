#!/usr/bin/env node
/**
 * probe-skill-registry.mjs — 用真实的 @deepseek-ai/dsh-skill 注册表验证随包技能。
 *
 * verify-load.mjs 用的是自建桩，只能证明"我们按自己理解的契约注册了"。
 * 本探针把 skills/dsh-ghidra/SKILL.md 真的注册进 DSH 官方的 SkillRegistry，
 * 再走一遍官方路径：register → list → get → renderSkillContent → dispose。
 * 契约以官方实现为准，不是以我们的桩为准。
 *
 * 找不到 @deepseek-ai/dsh-skill（例如在别人的机器上跑）时 SKIP 退出 0，
 * 不把"环境缺失"误报成"插件坏了"。可用 DSH_SKILL_PKG=<lib/index.js 绝对路径> 指定。
 */
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { loadSkillDefinition, SKILL_DIR, SKILL_FILE } from './lib/skill.js'

const SKILL_NAME = 'dsh-ghidra'

/** 候选的全局 node_modules 根（按平台给常见位置，不猜单一布局）。 */
function candidateRoots() {
	const roots = []
	if (process.env.DSH_SKILL_PKG) roots.push(process.env.DSH_SKILL_PKG)
	if (process.env.APPDATA) roots.push(join(process.env.APPDATA, 'npm', 'node_modules'))
	if (process.env.ProgramFiles) roots.push(join(process.env.ProgramFiles, 'nodejs', 'node_modules'))
	roots.push('/usr/local/lib/node_modules', '/usr/lib/node_modules')
	return roots
}

/** 定位 @deepseek-ai/dsh-skill 的入口文件；两种布局都试。 */
function findSkillPackage() {
	for (const root of candidateRoots()) {
		if (root.endsWith('.js') && existsSync(root)) return root
		const nested = join(root, '@deepseek-ai', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-skill', 'lib', 'index.js')
		if (existsSync(nested)) return nested
		const flat = join(root, '@deepseek-ai', 'dsh-skill', 'lib', 'index.js')
		if (existsSync(flat)) return flat
	}
	return null
}

const pkgPath = findSkillPackage()
if (pkgPath === null) {
	console.log('SKIP: @deepseek-ai/dsh-skill not found on this machine — real-registry probe not applicable.')
	console.log('      (set DSH_SKILL_PKG=<absolute path to dsh-skill/lib/index.js> to force it)')
	process.exit(0)
}

const mod = await import(pathToFileURL(pkgPath).href)
const SkillRegistry = mod.default
const renderSkillContent = mod.renderSkillContent
if (typeof SkillRegistry !== 'function' || typeof renderSkillContent !== 'function') {
	console.error('FAIL: dsh-skill does not export the expected SkillRegistry / renderSkillContent')
	process.exit(1)
}

/* ------------------------------------------------------------------ *
 * 最小但忠实的 ctx：官方 ScopedLayers.effect 走 ctx.effect(generator)，
 * 生成器 yield 一个 undo 函数。scopeOf(ctx) 读 ctx[kScope]，普通对象没有
 * 该 symbol ⇒ undefined ⇒ 落到 global 层，正是宿主插件所在的层。
 * ------------------------------------------------------------------ */
const warnings = []
/** 记录注册表发出去的目录变更事件（notifyChange → ctx.events.dispatch("emit", ["skills/change"])）。 */
const emitted = []
const ctx = {
	logger: { warn: (message) => warnings.push(String(message)) },
	/* SkillRegistry extends cordis' Service, whose constructor publishes
	 * itself through ctx.reflect.provide(name, self, check). */
	reflect: { provide() {} },
	/* notifyChange() 走 ctx.events.dispatch("emit", [...]) 并遍历返回的监听器。 */
	events: {
		dispatch(kind, args) {
			emitted.push([kind, args])
			return []
		}
	},
	effect(generator) {
		const iterator = generator()
		const first = iterator.next()
		const undo = first.value
		if (typeof undo !== 'function') throw new TypeError('effect generator did not yield a disposer')
		iterator.next()
		return undo
	}
}

let passed = 0
let failed = 0
async function check(label, run) {
	try {
		const detail = await run()
		passed += 1
		console.log(`  PASS  ${label}${detail === undefined ? '' : ' — ' + detail}`)
	} catch (error) {
		failed += 1
		console.log(`  FAIL  ${label} — ${error && error.message ? error.message : error}`)
		if (process.env.PROBE_STACK === '1' && error && error.stack) console.log(error.stack)
	}
}
function assert(condition, message) {
	if (!condition) throw new Error(message)
}

console.log(`probing the real registry at ${pkgPath}`)
console.log(`skill file: ${SKILL_FILE}\n`)

const registry = new SkillRegistry(ctx)
const definition = loadSkillDefinition()

await check('SKILL.md loads with a complete definition', () => {
	assert(definition !== null, 'loadSkillDefinition() returned null')
	assert(definition.name === SKILL_NAME, `name is ${definition.name}`)
	assert(typeof definition.description === 'string' && definition.description.length > 0, 'empty description')
	assert(typeof definition.content === 'string' && definition.content.length > 2000, 'body looks truncated')
	return `${definition.content.length} chars of body`
})

let dispose = null
await check('registry.register() accepts the definition', () => {
	dispose = registry.register(definition)
	assert(typeof dispose === 'function', 'register() did not return a disposer')
	return 'disposer returned'
})

await check('registering announces skills/change so caches invalidate', () => {
	assert(emitted.length >= 1, 'no skills/change was dispatched')
	const last = emitted[emitted.length - 1]
	assert(last[0] === 'emit', `dispatch kind is ${last[0]}`)
	assert(Array.isArray(last[1]) && last[1][0] === 'skills/change', `unexpected event args: ${JSON.stringify(last[1])}`)
	return `${emitted.length} dispatch`
})

await check('the skill is listed from the runtime provider', async () => {
	const list = await registry.list({})
	const found = list.find((entry) => entry.name === SKILL_NAME)
	assert(found !== undefined, 'not present in registry.list()')
	assert(found.source === 'runtime', `source is ${found.source}`)
	assert(found.provider === 'runtime', `provider is ${found.provider}`)
	return `source=${found.source} provider=${found.provider}`
})

await check('the summary carries description and whenToUse', async () => {
	const list = await registry.list({})
	const found = list.find((entry) => entry.name === SKILL_NAME)
	assert(found.description === definition.description, 'description did not survive')
	assert(found.whenToUse === definition.whenToUse, 'whenToUse did not survive')
	return `${found.description.length} char description, ${found.whenToUse.length} char whenToUse`
})

await check('registry.get() returns the body', async () => {
	const loaded = await registry.get(SKILL_NAME, {})
	assert(loaded !== undefined, 'get() returned undefined')
	assert(loaded.content === definition.content, 'body differs from the file')
	assert(loaded.invocation.modelInvocable === true, 'modelInvocable was not defaulted to true')
	assert(loaded.invocation.userInvocable === true, 'userInvocable was not defaulted to true')
	return `${loaded.content.length} chars, invocation defaulted`
})

await check('renderSkillContent() wraps the body for the model', async () => {
	const loaded = await registry.get(SKILL_NAME, {})
	const rendered = renderSkillContent(loaded)
	assert(rendered.includes(`<skill_content name="${SKILL_NAME}">`), 'missing the skill_content wrapper')
	assert(rendered.includes('<skill_instructions>'), 'missing the instructions block')
	assert(rendered.includes(definition.content), 'body is not embedded verbatim')
	assert(rendered.includes('</skill_content>'), 'wrapper is not closed')
	assert(rendered.includes('Base directory for this skill: ' + SKILL_DIR), 'resource base hint is missing or wrong')
	return `${rendered.length} chars rendered`
})

await check('a duplicate registration is first-wins and warns', () => {
	const before = warnings.length
	const second = registry.register(definition)
	assert(typeof second === 'function', 'duplicate did not return a disposer')
	assert(warnings.length === before + 1, 'no warning was logged for the duplicate')
	assert(/already registered/.test(warnings[warnings.length - 1]), `unexpected warning: ${warnings[warnings.length - 1]}`)
	second()
	return 'no-op disposer + warning'
})

await check('the disposer removes the skill again', async () => {
	dispose()
	const list = await registry.list({})
	assert(!list.some((entry) => entry.name === SKILL_NAME), 'still listed after dispose()')
	return 'removed'
})

await check('the happy path logged no other warnings', () => {
	assert(warnings.length === 1, `expected only the duplicate warning, saw ${warnings.length}: ${warnings.join(' | ')}`)
	return '1 expected warning'
})

console.log('')
if (failed > 0) {
	console.error(`=== SKILL REGISTRY PROBE FAILED: ${passed}/${passed + failed} ===`)
	process.exit(1)
}
console.log(`=== SKILL REGISTRY PROBE PASSED: ${passed}/${passed + failed} ===`)
