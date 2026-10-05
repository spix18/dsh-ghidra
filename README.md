# dsh-ghidra

[![npm version](https://img.shields.io/npm/v/dsh-ghidra?color=cb3837&label=npm)](https://www.npmjs.com/package/dsh-ghidra)
[![npm downloads](https://img.shields.io/npm/dm/dsh-ghidra?color=cb3837)](https://www.npmjs.com/package/dsh-ghidra)
[![license](https://img.shields.io/npm/l/dsh-ghidra?color=blue)](https://github.com/spix18/dsh-ghidra/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/spix18/dsh-ghidra?color=yellow)](https://github.com/spix18/dsh-ghidra)

**Ghidra bridge plugin for DeepSeek Harness (DSH)** — gives DSH (and any agent running in it) a full
reverse-engineering workbench: import a binary, analyze it, decompile functions, list
functions/strings/segments/imports/exports, walk xrefs and call graphs, disassemble, read memory,
**edit and persist** (rename, comments, prototypes, locals, create/delete functions, tags), run
**composite analysis** (call graph, instruction search, hashing, data flow) and **malware triage**
(crypto-constant tables, behavioural APIs, IOCs, anti-analysis clues) — all as DSH tools, usable from
any project.

## Install

**Requirements:** Windows · Ghidra 12.x · Python 3.13 with `pyghidra` (`py -3.13 -m pip install pyghidra`) · Node ≥ 20 · DSH ≥ 0.2

```bash
# 1. install the plugin into your DSH profile
dsh plugin --profile web add dsh-ghidra

# 2. restart DSH  (browser-half changes need a restart)
# 3. open  Settings → Ghidra  in the sidebar, then press  "Download Ghidra"
#    → fetches the latest Ghidra release into the plugin's own data dir and configures it for you
```

That's it — after step 3 the plugin is fully set up. Ask the agent for `ghidra_open <path-to-binary>`
and start working. Everything the plugin owns lives under
`<DSH_HOME>\profiles\web\node_modules\dsh-ghidra-home\` (Ghidra install, projects cache, logs).

<details>
<summary>Other ways to install / verify</summary>

```bash
# from a local checkout (editable, copy-style install)
git clone https://github.com/spix18/dsh-ghidra
dsh plugin --profile web add "file:$PWD/dsh-ghidra"

# already have Ghidra? point the plugin at it instead of downloading
#   Settings → Ghidra → "Ghidra install directory (optional)" → Browse…

# health check without the GUI
node <profile>/node_modules/dsh-ghidra/verify-load.mjs <profile>/node_modules/dsh-ghidra
```

After editing a local checkout, re-sync the installed copy:
`node sync-installed.mjs` (web + headless, SHA256-checked).
</details>

## Features

- **218 tools** = 47 native (PyGhidra bridge) + 3 lifecycle + 168 generated from the upstream
  [GhidraMCP](https://github.com/bethington/ghidra-mcp) REST surface (226 endpoints).
- **Single JVM (default `mcpMode=unified`)** — the upstream REST server runs *inside* the PyGhidra
  bridge process and is bound to the same open program, so native and REST tools never diverge.
- **Self-contained data root** — the Ghidra install, logs and runtime files live in
  `<DSH_HOME>\profiles\<profile>\node_modules\dsh-ghidra-home\`; `Download Ghidra` fetches the latest
  release from GitHub and installs it there.
- **Settings section** — a `Settings → Ghidra` page (status, health check/doctor, download, folder
  picker, 12 hot-reloadable config fields; no DSH restart needed for config changes).
- **Bundled agent skill** — `skills/dsh-ghidra/SKILL.md` is registered into DSH's skill registry at
  load time, so the agent knows *when* this plugin is the right tool (and when it is not) before it
  starts calling anything.
- **Only reachable tools are advertised** — with no bridge and no REST server running the plugin
  exposes 5 entry points instead of 218, and reports the hidden groups, the reason and the fix.
  `ghidra_open` / `ghidra_mcp_start` bring the rest back in the same session.
- **Verification harnesses ship with the package** (`verify-load.mjs`, `probe-availability.mjs`,
  `probe-*.mjs`) so you can check the install on your own machine.

## Support

If you find this useful, you can support development at [ko-fi.com/spix18](https://ko-fi.com/spix18).

Deep detail (architecture, patches, data layout, pitfalls) follows in Chinese below.

---

让 DeepSeek Harness（DSH）直接操作 **Ghidra** 反编译：导入二进制、完整分析、反编译函数、
列函数/字符串/段/导入导出、查交叉引用、反汇编、读内存、**改名/写注释/改原型/改局部变量/
增删函数/打标签并落盘**、**复合分析（调用图/指令搜索/哈希对比/数据流）与恶意代码分析
（加密常量表/行为 API/IOC/反分析线索）** —— 全部作为 DSH 工具使用，与工作区无关（任何项目里都能用）。

## 工作原理

Ghidra 12 的 headless **Java 脚本**加载有上游 bug（NSA/ghidra#9551，未修复），
因此本插件走 **PyGhidra** 官方 Python 接口：

    插件 ──spawn──> pyghidra_launcher.py ──> Ghidra headless + Python 3.13
       │                                          │
       └──────── TCP 127.0.0.1 JSON-RPC ◄─────────┘   （常驻服务器，毫秒级操作）

`ghidra_open` 首次导入并完整分析二进制（数分钟，后台任务流式显示进度），
之后所有操作走常驻服务器，毫秒级返回。

> **写侧落盘的两条铁律（本插件已按此实现，改代码时别破坏）**
> 1. headless **只在脚本正常结束后**才把改动写回项目。因此任何停止服务器的路径都必须
>    **优雅**停（发 `{op:'shutdown'}` 让桥接脚本的 `main()` return），硬杀 = 整轮分析白做。
>    `ghidra_save` 是 flush 语义（优雅停止 → 落盘 → 重开）；插件卸载钩子与
>    `process.on('exit')` 同步兜底也都走优雅停止。
> 2. 桥接脚本里的写事务是 PyGhidra 外层事务的**子事务**，`endTransaction` 只能提交（`True`），
>    **绝不能 abort** —— abort 子事务会让 Ghidra 丢弃整个外层事务（内存里读得到、日志说
>    `Save succeeded`，磁盘却是旧值）。

## 工具（47 原生 + 171 REST 桥 = 218 个）

| 分组 | 工具 |
| --- | --- |
| 会话 / 总览 | `ghidra_status`、`ghidra_open`（导入+分析+起服务器，默认流式后台任务）、`ghidra_info`、`ghidra_save`（把改动 flush 落盘）、`ghidra_close` |
| 读侧 · 基础 | `ghidra_decompile`、`ghidra_functions`、`ghidra_strings`、`ghidra_xrefs`、`ghidra_disassemble`、`ghidra_variables`、`ghidra_segments`、`ghidra_read_memory` |
| 读侧 · 进阶 | `ghidra_imports`、`ghidra_exports`、`ghidra_search_strings`（正则）、`ghidra_search_functions`（正则）、`ghidra_calls`、`ghidra_call_graph`（BFS）、`ghidra_pcode`（listing/high 两档） |
| 写侧 | `ghidra_get_comments`、`ghidra_set_comment`、`ghidra_rename`、`ghidra_label`、`ghidra_set_prototype`、`ghidra_set_variables`、`ghidra_create_function`、`ghidra_delete_function`、`ghidra_tags` |
| 分析自动化 | `ghidra_run_script_inline`、`ghidra_run_script_file`、`ghidra_list_analyzers`、`ghidra_configure_analyzer`、`ghidra_run_analysis`、`ghidra_reanalyze`、`ghidra_search_byte_patterns`、`ghidra_find_code_gaps`、`ghidra_find_dead_code` |
| 复合分析 | `ghidra_function_context`（一个函数一次给全：参数/调用关系/字符串引用/指令统计/复杂度/伪代码）、`ghidra_search_instructions`（助记符/操作数/正则）、`ghidra_hash`（函数级 bytes·code·mnemonic 三种哈希，程序级逐块 + `imageHash`）、`ghidra_compare_functions`（相似度 + 差集 + 逐条差异）、`ghidra_data_flow`（变量定义/使用链 BFS） |
| 恶意代码分析 | `ghidra_detect_crypto_constants`（28 条常量签名：AES S-box、CRC32/CRC32C、MD5/SHA-1/256/512 的 init 与 K 表、Keccak 轮常量、Base64 双字母表、Blowfish P-array、曲线模数）、`ghidra_detect_malware_behaviors`（10 类行为 × API 名表，证据分 import/function/string）、`ghidra_extract_iocs_with_context`（17 类 IOC，可选 `includeRawMemory` 扫未定义数据）、`ghidra_find_anti_analysis_techniques`（反调试/反 VM/调试器线索 + RDTSC/CPUID/INT3 字节计数） |
| MCP REST 桥 · 生命周期 | `ghidra_mcp_start`（拉起上游 GhidraMCP headless 服务器，可带 file 自动导入分析；已在运行时采纳）、`ghidra_mcp_stop`（先保存程序再优雅退出）、`ghidra_mcp_status`（/health 快照） |
| MCP REST 桥 · 生成工具（168 个） | `ghidra_mcp_*`（`lib/mcp-tools.js` 由生成器从上游 live schema 产出：xref/datatype/program/malware/analysis/documentation/headless/function/symbol/comment/listing/project/emulation/getter/server 共 15 类；与原生 47 工具重复的 45 个端点不生成） |
| 诊断（仅 socket） | `probe`（`{tx:true}` / `{save:true}` / `{handles:true}` / `{analysis:true}` / `{class:'...'}` / `{locals:'0x...'}`，不注册为模型工具） |

**`ghidra_run_script_inline` 是这一组里的万能钥匙**：它在桥接脚本的上下文里直接 `exec` 一段 Python
（运行环境是 **CPython 3.13 + JPype**，不是 Jython），命名空间里预置 `currentProgram` / `program` /
`monitor` / `println` / `print` / `getScriptArgs()`；把结果赋给 `result` 就会原样回传，Python 与 Java
两路 stdout 都会被捕获，脚本报错只返回 `error` + `traceback`、不会打断服务器。写操作记得 `write=true`
（整段包进一个事务），之后照旧用 `ghidra_save` 落盘。

写侧改动**不会**自动落盘：会话结束（`ghidra_close` / 插件卸载 / DSH 退出）时会自动保存，
中途想立刻确认请调 `ghidra_save`，之后的判据永远是**重开一次读回来**。

## 随包技能与工具可用性（v0.10.0）

**随包技能。** `skills/dsh-ghidra/SKILL.md` 在插件加载时注册进 DSH 的运行时技能注册表
（`ctx.skills.register()`，`source: 'runtime'`）。为什么不能只把文件放进包里：DSH 的技能文件系统
provider 只扫 project / user / bundled 三类根，**不会去翻 node_modules 里的插件目录** ——
光有文件永远不会被发现，技能必须跟着插件注册才活。技能内容的核心是**路由**，即「什么时候该用它、
什么时候不该用」：原生可执行/库/驱动/固件 → 用它；JavaScript/Electron/ASAR/源码、压缩包、
.NET 托管程序集 → **明确说不用它**（Ghidra 会把托管程序集当不透明原生 blob 导入，据此得出的
结论全是错的）。另有「先看概览再动手」「区分观察 / 推断 / 未知」「写侧改动要 `ghidra_save` 才落盘」
「收尾 `ghidra_close`」等纪律。

注册走的是**全局层**（宿主插件所在层），而注册表解析顺序是 `[global, ...scopeChain]` 且**近层覆盖远层**
（`dsh-skill` 的 `collectFresh()`），所以每个 agent 视图都能看到它，除非同名技能出现在更近的一层。
`resourceBase` 指向 `skills/dsh-ghidra/`，模型看到的是 "Base directory for this skill: …" 而不是
provider 托管的占位提示。`probe-skill-registry.mjs` 用**真实的** `@deepseek-ai/dsh-skill` 注册表
跑一遍 `register → list → get → renderSkillContent → dispose`（10/10），契约以官方实现为准。

⚠️ **在「设置 → 技能」里看不到它，这是预期的**：`dsh-skill-hub` 的目录是**文件系统扫描**
（bundled / project-* / user-* 五类根），不枚举运行时注册表。技能对 agent 有效，只是不出现在那个列表里。

**只广告现在跑得起来的工具。** 218 个工具里只有 5 个不需要任何服务器
（`ghidra_status`、`ghidra_open`、`ghidra_mcp_start/stop/status`）。桥或 REST 服务器没跑时，
其余 213 个**不再注册进工具表** —— 模型看不到，也就不会去调一个必然失败的工具。
`ghidra_status` 与 `GET /api/dsh-ghidra/status` 都返回 `toolAvailability`：

```
{ "total": 218, "advertised": 5,
  "hidden": [
    { "group": "bridge", "label": "PyGhidra bridge", "count": 45,
      "reason": "not_running", "remediation": "call ghidra_open on a binary" },
    { "group": "mcp", "label": "upstream GhidraMCP REST server", "count": 168,
      "reason": "not_running", "remediation": "call ghidra_mcp_start (unified mode needs ghidra_open first)" } ],
  "groups": { "bridge": { "available": false, "tools": 45 }, "mcp": { "available": false, "tools": 168 } } }
```

`ghidra_open` 成功 → 桥的 45 个立刻回来；`ghidra_mcp_start` 成功 → REST 的 168 个回来；
服务器停掉则同步撤掉（`ghidra_mcp_stop`、面板上的停止按钮、任何一次 `ghidra_status` 都会同步）。
**没有工具会在门控里丢失**：`advertised + Σhidden = 218`，有断言守着。代价是注册表变化会让那一次
prompt 前缀缓存失效（每次 start/stop 一次），换来的是「模型看到的工具集 = 现在真能跑的工具集」。

## 环境要求（本机已配好）

| 组件 | 本机位置 / 版本 |
| --- | --- |
| Ghidra | `D:\tools\ghidra_12.1.4_PUBLIC`（12.1.4 PUBLIC，纯 ASCII 路径） |
| JDK | Temurin 21.0.12.1 LTS（Ghidra 12 要求） |
| Python | `py -3.13`（3.13.14） |
| pyghidra | 3.1.0 + JPype1 1.5.2（装进 3.13 的 site-packages） |

- Ghidra 非 ASCII 路径会导致 log4j 配置加载失败；插件会自动注入
  `GHIDRA_HEADLESS_JAVA_OPTIONS` / `PYGHIDRA_JAVA_OPTIONS` 兜底，但**推荐放纯 ASCII 路径**。
- `pythonVer` 固定 `'3.13'` 且用 `py` 启动器探测（uv 装的 3.13 探测不到）。
- 以上齐全时**无需任何配置**：`ghidraHome` 留空即自动探测（优先插件数据根里的安装，见下）。

## 插件数据根（v0.6.0：关于这个插件的一切都在插件树里）

    <DSH_HOME>\profiles\web\node_modules\dsh-ghidra-home\
      ├── ghidra\ghidra_<ver>_PUBLIC\    Ghidra 安装（Download Ghidra 落在这里；也可手工拷入）
      ├── logs\                          MCP / 运行日志
      └── run\                           端口文件 / pid 文件 / 桥日志 / 脚本副本

- 解析顺序（`lib/paths.js`）：自身 profile 的 `node_modules\dsh-ghidra-home` → 已存在的
  `profiles\web\node_modules\dsh-ghidra-home`（跨 profile 共享同一份）→ 缺省在 web profile 下创建。
- `detectGhidraHome` 优先级：显式 `ghidraHome` → **数据根里的安装**（`source: plugin-data`）→
  历史/外部安装（`GHIDRA_HOME`、`D:\tools\...` 等，`source: external`）。状态路由与 doctor 会回报来源。
- **为什么是兄弟目录而不是包内**：`dsh plugin add` / npm install 会替换 `node_modules\dsh-ghidra`
  整个包目录，包内的 Ghidra 安装会被下次插件更新抹掉；同级的 `dsh-ghidra-home` 不归 npm 管。
- **项目目录例外（硬约束）**：Ghidra 的项目路径校验禁止任何以 `.` 开头的路径元素
  （`NamingUtilities.checkName` → "Path element starting with '.' is not permitted"），
  而 `DSH_HOME` 本身叫 `.dsh` —— 所以**项目目录不能放在插件树里**，缺省仍是
  `%TEMP%\dsh-ghidra-projects`（可用 `ghidraProjectDir` 覆盖为任意不含点元素的路径）。
  安装目录不受此限（Ghidra 只校验项目 locator）。

## 安装 / 更新

**从 npm 安装（推荐）：**

    dsh plugin --profile web add dsh-ghidra
    # 然后重启 DSH → 侧边栏 设置 → Ghidra → 按 "Download Ghidra" 一键装好 Ghidra

**从本地源码安装（开发用）：**

    dsh plugin --profile web add "file:C:/Users/Administrator/.dsh/plugins/ghidra-bridge"

`file:` 是**拷贝式**安装：改完本目录的源码后必须同步已装副本，否则跑的还是旧代码——

    node sync-installed.mjs     # 同步 web + headless 两个副本，逐文件校验 SHA256，清 __pycache__

改完**必须重启 DSH**：`web` profile 没有 `patchReload`，运行中的 server 不会热加载新 bundle
（重启后新工具才会出现在会话里）。

## 配置（可选 · 可热改）

11 个字段全部 **volatile**：在 DSH 的 **插件管理页**（侧边栏「插件」→ Ghidra 桥）的卡片表单里
直接改，**保存后立即生效，无需重启 DSH**（写侧 reload Loader entry 重跑 apply）。也可以走 cordis patch：

    - id: ghidra-bridge
      name: dsh-ghidra
      config:
        ghidraHome: ''          # 留空即用插件数据根里的安装（node_modules\dsh-ghidra-home\ghidra），外部安装仅作回退
        ghidraProjectDir: ''    # 项目缓存目录（缺省 %TEMP%\dsh-ghidra-projects；**不能**放 .dsh 下——Ghidra 拒绝点元素路径）
        projectName: dsh
        pythonVer: '3.13'
        analysisTimeoutSec: 600
        serverStartupTimeoutMs: 180000
        maxOutputChars: 100000
        stream: true            # ghidra_open 默认后台流式
        mcpPort: 8123           # 上游 GhidraMCP headless 服务器端口
        mcpStartupTimeoutSec: 180
        mcpTimeoutSec: 900

## Settings 分区（状态 + 配置 + 健康检查 + 下载）

双面插件：浏览器半（`client.js`，plain JS + React，无打包）注册 `settings.section` slot
（与 dsh-mobilecode 等插件同位），渲染进 **设置 → Ghidra 顶级分区**：

- **状态区**：PyGhidra 桥与 GhidraMCP 服务器的运行态（端口 / 程序 / pid）、工具计数
  （原生 + lifecycle + 生成）、Ghidra 主目录与版本；「刷新」「停止 MCP 服务器」
  （优雅停止，先保存已加载程序再退出）「Download Ghidra」按钮。数据来自节点半注册的
  `GET /api/dsh-ghidra/status`（回环-only，headless profile 无 webServer 时显示"配置表单不可用"）。
- **健康检查（Doctor）**：「Run doctor」按钮 → `GET /api/dsh-ghidra/doctor`，
  逐项检查 Ghidra 主目录 / PyGhidra launcher 脚本 / ghidraMCPHeadless.bat /
  Python（`py -3.13 --version`）/ 双服务器运行态 / Ghidra 版本，每项 OK/FAIL + 详情；
  前置 4 项全过才 overall 通过，运行态为参考项。
- **下载安装**：「Download Ghidra」→ `POST /api/dsh-ghidra/install-ghidra`（后台）：
  GitHub 最新 release（`ghidra_*_PUBLIC_*.zip`）流式下载（进度 % + MB）→ PowerShell
  `Expand-Archive` 解压到当前主目录旁 → 校验 `support/ghidraMCPHeadless.bat` →
  自动把 ghidraHome 切到新目录（走迁移流程删旧目录）。进度在 /status 的 `install` 字段。
- **配置区**：12 字段表单（staged edits → 保存逐条写 + 读回 Host 验收；已覆盖字段带徽标 +
  单字段「重置」恢复默认；实时校验）。走 `ctx.configForms.get('ghidra-bridge')` 的 FormScope。
  **路径字段带「Browse…」按钮**：打开插件自己的文件夹浏览器（模态：驱动器列表 → 逐层进入 →
  「Use this folder」写回 draft，另有「Create folder」就地建目录）。选择器由本 UI 渲染，**不弹原生
  对话框** —— 宿主进程弹的 PowerShell/WinForms 对话框在无交互 window station 的环境里不可见
  （表现为「点了没反应」且请求一直挂着），所以宿主只提供两个确定性接口：
  `POST /api/dsh-ghidra/list-dir`（只读列目录；空路径回驱动器列表；回 dotSegment 供前端预警）与
  `POST /api/dsh-ghidra/mkdir`（建目录；拒绝分隔符与点开头的名字）。
  **ghidraHome 变更保存时自动迁移**：`POST /api/dsh-ghidra/migrate-home`（后台）——
  停双服务器 → 旧 home 复制到新目录 → 校验结构（launcher + bat）→ 删除旧 home；
  校验不过则保留旧 home 不删。目标已存在且是完整 Ghidra home（含 bat）时按版本切换处理
  （不复制，只删旧）；目标是非空且非 Ghidra 目录时拒绝。

需要 DSH **重启一次**让浏览器半加载（`client.js` 由 `/plugins/dsh-ghidra/client.js` serve）；
此后节点半的配置改动即时生效，浏览器半刷新即可看到。

## 目录结构

    ghidra-bridge/
    ├── package.json            # dsh.bundle manifest + dsh.client（浏览器半）
    ├── cordis.patch.yml        # 插件行插入层
    ├── index.js                # 218 个工具的注册（47 原生 + 3 MCP lifecycle + 168 生成）+ 服务器状态/优雅停止管理 + /api/dsh-ghidra/status|mcp-stop|doctor|install-ghidra|migrate-home 路由
    ├── client.js               # 浏览器半：插件管理页的 Ghidra 桥卡片（状态 + 可热改配置表单）
    ├── icon.svg                # 插件管理页图标
    ├── locale/                 # en.json / zh.json（插件列表卡片的标题/描述）
    ├── lib/
    │   ├── ghidra.js           # 环境探测/导入/服务器生命周期（headless 日志落 %TEMP%\dsh-ghidra\headless.log）
    │   ├── socket.js           # TCP 行式 JSON 客户端
    │   ├── mcp.js              # 上游 GhidraMCP headless 服务器（REST 226 端点）的 HTTP 桥（mcp-headless.log）
    │   ├── mcp-tools.js        # 168 个 ghidra_mcp_* 生成工具（GENERATED — 重跑 gen-mcp-tools.mjs 再生成）
    │   └── run.js              # 进程工具（进程树清理/cmd 引号/pidAlive）
    ├── scripts/
    │   └── DecompileBridge.py  # PyGhidra 桥接脚本（常驻 TCP JSON-RPC，~3450 行）
    ├── PATCHES.md              # 相对上游的补丁与踩坑记录（**改代码前先读**）
    ├── gen-mcp-tools.mjs       # REST 桥工具生成器（读 UPSTREAM-SCHEMA-LIVE.json，SKIP 表 58 条）
    ├── UPSTREAM-SCHEMA-LIVE.json / upstream-src/  # 上游 live schema dump 与 55 个 Java 源（移植依据）
    ├── sync-installed.mjs      # 同步已装副本（20 文件 × 2 profile）
    ├── verify-load.mjs / verify.mjs / verify-tools.mjs / verify-batch3.mjs / verify-batch4.mjs / verify-mcp-e2e.mjs / fail-test.mjs / exit-test.mjs
    ├── kat-consts.py           # 批次 4 常量表的 KAT（62 条已知答案，脱离 Ghidra 单跑）
    └── *.mjs                   # 诊断脚本（probe/probe3*/persist/timing/volume/readwrite/bisect/tx-probe/ioc-probe/union-args）

## 验收

    node sync-installed.mjs               # 先把源码同步进两个已装副本（否则验的是旧代码）
    node verify-load.mjs [已装副本目录]   # 加载路径 + 218 个工具定义 + 门控只广告 5 个 +
                                          #   随包技能注册 + 桥工具 params 回归   → 21/21
    node probe-availability.mjs [副本]    # 工具可用性门控：冷启动 5 → 服务器上线 173 →
                                          #   下线回 5，撤门干净且幂等              → 14/14
    node probe-skill-registry.mjs         # 用真实的 @deepseek-ai/dsh-skill 注册表跑一遍
                                          #   register→list→get→render→dispose     → 10/10
                                          #   （找不到该包时 SKIP 退出 0）
    node verify.mjs                       # lib 层：探测→导入→起服务器→op 往返 → 15/15
    node verify-tools.mjs                 # 工具层：批次 1/2 全部实调 + 失败用例 → 85/85
    node verify-batch3.mjs                # 批次 3 的 14 个新工具（含落盘回归）   → 77/77
    node verify-batch4.mjs                # 批次 4 的 4 个新工具（winver 负对照 / kernel32 真阳性 /
                                          #   cmd.exe 行为与反分析 / certutil+reg.exe 的 IOC /
                                          #   oneOf 双形状）                      → 58/58
    node verify-mcp-e2e.mjs               # REST 桥 E2E（8123 上已运行的服务器）：采纳 → 读 → 写标签 →
                                          #   读回 → 删除                          → MCP_E2E_OK
    py -3.13 kat-consts.py                # 批次 4 常量表 KAT：62 checks / 28 signatures
    node fail-test.mjs                    # 8 个失败路径逐个隔离（事务污染回归） → 8/8 PERSISTED
    node exit-test.mjs write|read         # 卸载/硬退出时写改动是否落盘            → PERSISTED=true

## 已知限制

- 同一时刻只服务一个已打开程序；切换目标直接 `ghidra_open` 即可（会自动优雅停旧的），无需先 close。
- 分析结果缓存在 Ghidra 项目（默认 `%TEMP%\dsh-ghidra-projects`），二进制未变则复用。
- 项目目录是**单服务器**设计：两个实例同时用同一 `ghidraProjectDir` 会互抢项目锁。
- 上游 GUI-only 端点（`debugger/*` 等 27 个）不移植；批次 1–4 已全部完成（8 → 47 个工具），
  剩下的候选是依赖 BSim/FID 的相似函数类工具（成本高，见 `PATCHES.md`）。
- **统一模式（v0.5.0，缺省 `mcpMode=unified`）**：上游 168 个生成工具**不再需要第二个 Ghidra 进程**——
  `ghidra_mcp_start` 会把上游 REST 服务器启动在 PyGhidra 桥的**同一个 JVM** 内
  （`DecompileBridge.py` 的 `mcpServe` op：`com.xebyte.headless.GhidraMCPHeadlessServer.launch()` 跑在
  daemon 线程 + `HeadlessProgramProvider.setCurrentProgram()` 绑定桥当前程序），
  于是 47 个原生工具与 168 个 REST 工具作用于**同一个程序、同一个进程**（状态不再分叉，省一份 JVM）。
  桥停止/REST 服务器随之消失，重新 `ghidra_open` + `ghidra_mcp_start` 即可。
  `mcpMode=standalone` 回退旧行为（独立 `ghidraMCPHeadless.bat`，第二个实例，可用 `file` 参数启动时导入）。
  前置：上游扩展 jar 在用户扩展目录
  `%APPDATA%\ghidra\ghidra_<ver>_PUBLIC\Extensions\GhidraMCP\lib\GhidraMCP-*.jar`。
- 发布注记的 "253 MCP TOOLS" 与实测 226 端点的差异是上游计数口径（REST 桥以 live schema dump 为准）。

## 支持

如果这个插件对你有用，可以在 [ko-fi.com/spix18](https://ko-fi.com/spix18) 支持开发。
