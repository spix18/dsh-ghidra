// gen-mcp-tools.mjs — 从 UPSTREAM-SCHEMA-LIVE.json 生成 lib/mcp-tools.js（上游 GhidraMCP REST 桥的工具层）。
// 架构：上游发布物自带独立 headless 服务器（226 个 REST 端点，live schema 抓自运行中的服务器），
// 本生成器把其中**与原生 47 工具不重复**的端点生成为 ghidra_mcp_* 桥工具（lib/mcp.js 的 mcpCall 发 HTTP）。
// 生成物是静态文件：可 diff、可版本化；上游 schema 更新后重跑本脚本即可（node gen-mcp-tools.mjs）。
// SKIP 表 = 与原生重复的端点 —— 原生已三层验收且语义更全（PyGhidra in-process），保留会造成近重复工具混淆模型。
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const live = JSON.parse(readFileSync(join(HERE, 'UPSTREAM-SCHEMA-LIVE.json'), 'utf8'))

// path → 原生等价工具（SKIP 原因）
const SKIP = new Map([
  // 基础设施/本地 —— ghidra_status 覆盖
  ['/get_version', 'ghidra_status'],
  ['/check_connection', 'ghidra_status'],
  ['/health', 'ghidra_status'],
  ['/mcp/schema', '本地 schema（UPSTREAM-SCHEMA-LIVE.json / probe-union-args.mjs）'],
  ['/list_methods', 'AnnotationScanner javadoc 误命中（非真实端点）'],
  // 与原生 47 重复
  ['/get_current_program_info', 'ghidra_info'],
  ['/get_metadata', 'ghidra_info'],
  ['/decompile_function', 'ghidra_decompile'],
  ['/disassemble_function', 'ghidra_disassemble'],
  ['/list_functions', 'ghidra_functions'],
  ['/list_strings', 'ghidra_strings'],
  ['/list_segments', 'ghidra_segments'],
  ['/list_exports', 'ghidra_exports'],
  ['/list_imports', 'ghidra_imports'],
  ['/list_analyzers', 'ghidra_list_analyzers'],
  ['/configure_analyzer', 'ghidra_configure_analyzer'],
  ['/reanalyze', 'ghidra_reanalyze'],
  ['/run_analysis', 'ghidra_run_analysis'],
  ['/read_memory', 'ghidra_read_memory'],
  ['/search_functions', 'ghidra_search_functions'],
  ['/search_strings', 'ghidra_search_strings'],
  ['/search_instructions', 'ghidra_search_instructions'],
  ['/search_byte_patterns', 'ghidra_search_byte_patterns'],
  ['/get_xrefs_to', 'ghidra_xrefs'],
  ['/get_xrefs_from', 'ghidra_xrefs'],
  ['/get_function_callers', 'ghidra_calls'],
  ['/get_function_callees', 'ghidra_calls'],
  ['/diff_functions', 'ghidra_compare_functions'],
  ['/get_function_pcode', 'ghidra_pcode'],
  ['/create_function', 'ghidra_create_function'],
  ['/delete_function', 'ghidra_delete_function'],
  ['/rename_function', 'ghidra_rename'],
  ['/rename_symbol', 'ghidra_rename'],
  ['/rename_variables', 'ghidra_set_variables'],
  ['/get_function_variables', 'ghidra_variables'],
  ['/set_variables', 'ghidra_set_variables'],
  ['/set_variable_type', 'ghidra_set_variables'],
  ['/set_function_prototype', 'ghidra_set_prototype'],
  ['/set_function_no_return', 'ghidra_set_prototype(noReturn)'],
  ['/get_comment', 'ghidra_get_comments'],
  ['/batch_get_comments', 'ghidra_get_comments(addresses[])'],
  ['/set_comment', 'ghidra_set_comment'],
  ['/batch_set_comments', 'ghidra_set_comment(comments{})'],
  ['/create_function_tag', 'ghidra_tags'],
  ['/delete_function_tag', 'ghidra_tags(delete)'],
  ['/add_function_tag', 'ghidra_tags(attach)'],
  ['/remove_function_tag', 'ghidra_tags(detach)'],
  ['/get_function_tags', 'ghidra_tags(get)'],
  ['/list_function_tags', 'ghidra_tags(list)'],
  ['/search_functions_by_tag', 'ghidra_tags(search)'],
  // 脚本执行 —— 原生走 PyGhidra in-process（完整 API、默认启用），上游要 GHIDRA_MCP_ALLOW_SCRIPTS=1
  ['/run_script_inline', 'ghidra_run_script_inline'],
  ['/run_ghidra_script', 'ghidra_run_script_file'],
  // 恶意代码四件套 + 代码空洞 —— 原生已三层验收（批次 1/4）
  ['/detect_crypto_constants', 'ghidra_detect_crypto_constants'],
  ['/detect_malware_behaviors', 'ghidra_detect_malware_behaviors'],
  ['/extract_iocs_with_context', 'ghidra_extract_iocs_with_context'],
  ['/find_anti_analysis_techniques', 'ghidra_find_anti_analysis_techniques'],
  ['/find_code_gaps', 'ghidra_find_code_gaps'],
  ['/find_dead_code', 'ghidra_find_dead_code'],
])

// 上游 param type → dsh-tools JSON-Schema 子集（已核实 schema.js 词汇：string/number/integer/
// boolean/null/json/object/array/oneOf；json = annotation-only，验证任何值 —— 正好承接 any）。
function mapType(t) {
  switch (t) {
    case 'string': return { type: 'string' }
    case 'integer': return { type: 'integer' }
    case 'number': return { type: 'number' }
    case 'boolean': return { type: 'boolean' }
    case 'json': return { type: 'json' }
    case 'object': return { type: 'object', additionalProperties: true } // object 分支强制要求显式 additionalProperties
    case 'array': return { type: 'array' } // 上游 array 都是批量对象数组（形状各异，description 里说了），不加 items 约束
    case 'any': return { type: 'json' } // 上游 any = 数组或逗号分隔串都收 → annotation-only
    default: return { type: 'string' }
  }
}

function slug(p) { return 'ghidra_mcp_' + p.slice(1).replace(/[/\-]/g, '_') }

function propSpec(p) {
  const spec = mapType(p.type)
  if (p.required === true) spec.required = true // 子集只收字面 true；false 必须省略
  if (p.description) spec.description = p.description
  return spec
}

const tools = []
const skipped = []
for (const ep of live.tools) {
  if (SKIP.has(ep.path)) { skipped.push({ path: ep.path, why: SKIP.get(ep.path) }); continue }
  const properties = {}
  for (const p of ep.params || []) properties[p.name] = propSpec(p)
  tools.push({
    name: slug(ep.path),
    path: ep.path,
    method: ep.method || 'GET',
    category: ep.category,
    description: (ep.description || ep.path) + '（上游 MCP headless 服务器）',
    // defineTool 的 parameters 是【扁平属性表】（compilePropertyMap 自己加 object 根）——
    // 不能写成 {type:'object', properties}（type/properties 会被当成参数名 → compile 报错）。
    parameters: properties,
    // 原始端点参数表（name/type/source/required/default）——lib/mcp.js 的 buildRequest 靠它
    // 把调用方参数编进 GET query / POST body；缺了它 body 恒为 {}（上游报 "X is required"）。
    params: (ep.params || []).map((p) => ({ name: p.name, type: p.type, source: p.source, required: p.required === true })),
  })
}

const names = tools.map(t => t.name)
const dup = names.filter((n, i) => names.indexOf(n) !== i)
if (dup.length) { console.error('NAME COLLISIONS: ' + dup.join(', ')); process.exit(1) }

const banner = '// GENERATED by gen-mcp-tools.mjs from UPSTREAM-SCHEMA-LIVE.json — 不要手改；上游 schema 更新后重跑生成器。\n' +
  '// ' + tools.length + ' 个桥工具（上游 226 端点 − SKIP ' + skipped.length + ' 个与原生 47 工具重复）+ index.js 里 3 个 lifecycle 工具。\n' +
  '// 每个 execute 调 lib/mcp.js 的 mcpCall：GET→query、POST→JSON body；连接拒绝会提示先 ghidra_mcp_start。\n' +
  'export const MCP_TOOLS = ' + JSON.stringify(tools, null, 2) + '\n'
writeFileSync(join(HERE, 'lib', 'mcp-tools.js'), banner)
console.log('generated ' + tools.length + ' tools, skipped ' + skipped.length + ' duplicates')
console.log('categories: ' + [...new Set(tools.map(t => t.category))].join(', '))
