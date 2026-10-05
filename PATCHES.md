# ghidra-bridge — 本机安装记录与本地补丁

## 来源
- 上游仓库：https://github.com/zp2921060653/dsh-plugins （子目录 `ghidra-bridge`）
- 本地 master（可编辑副本）：`C:\Users\Administrator\.dsh\plugins\ghidra-bridge`
- 克隆快照 commit：`aae715db7af181a0d118bc47258dc4150ae901bb`（2026-09-11，"Add dsh-wxapkg plugin; fix reminder-bridge tick race crash"）
- 安装形态：pnpm `file:` 依赖 → 实装在 `C:\Users\Administrator\.dsh\profiles\<profile>\node_modules\dsh-ghidra`（**真实目录**，非符号链接）
- 注册：`profiles/<profile>/package.json` 的 `dependencies.dsh-ghidra` + `dsh.profile.bundles`
- 已装 profile：`web`（当前 GUI 用）、`headless`（用于无 GUI 的真实运行时验证）

## 本地补丁（必须全部保留）

### 1. `index.js:3` — 裸包名 `schemastery` 不存在
```diff
-import Schema from 'schemastery'
+import Schema from '@deepseek-ai/schemastery'
```
原因：本机（及 DSH 0.2.0-rc.2）只提供 `@deepseek-ai/schemastery`（v3.18.4，cordis 自身使用的
同一份实现），npm 上的独立 `schemastery` 从未被安装，插件 `package.json` 也未声明任何依赖。
未打补丁时 Node ESM 解析直接抛
`ERR_MODULE_NOT_FOUND :: Cannot find package 'schemastery' imported from .../dsh-ghidra/index.js`，
插件在 DSH 里静默加载失败。

### 2. 安装协议必须是 `file:`，不能用 `link:`
`dsh plugin --profile web add <绝对路径>` 会写成 `link:../../plugins/ghidra-bridge`，在
`node_modules` 里产生 **符号链接**。Node ESM 按 **realpath** 解析裸包名，于是从
`C:\Users\Administrator\.dsh\plugins\ghidra-bridge` 向上找到 `C:\node_modules` 也找不到
`@deepseek-ai/dsh-tools`，同样报 `ERR_MODULE_NOT_FOUND`。
改用 `file:` 协议后 pnpm 安装为真实目录，向上走到 `profiles\node_modules\@deepseek-ai\*` 正常解析。

正确的安装命令：
```powershell
dsh plugin --profile web add "file:C:/Users/Administrator/.dsh/plugins/ghidra-bridge"
```

### 3. `lib/ghidra.js` — `pyghidra_launcher.py` 提前退出被误判为「服务器启动失败」
这是最严重的一个，**不修则 `ghidra_open` 在真实 DSH 里随机（实测经常）失败**。

`pyghidra_launcher.py` 只是启动器：它拉起真正的 Ghidra（`py -3.13 -m pyghidra.ghidra_launch
--install-dir <home> ...`）后**自己 exit 0**，真正的 JVM 继续活着并稍后写出端口文件。
上游原代码在轮询里把 wrapper 的退出当成致命错误：

```js
while (Date.now() < deadline) {
  if (child.exitCode !== null) { killPid(child.pid); throw new Error('Ghidra 服务器进程提前退出 ...') }
  /* 之后才读 portFile */
}
```

于是「wrapper 先退」还是「端口文件先出现」纯看时序 —— 实测在 DSH 运行时 wrapper 约 **0.7s** 就退出了，
而 JVM 要到约 **6s** 才写端口文件，所以几乎必然抛错，尽管服务器其实正常。
（旧版 `verify.mjs` 之所以「通过」，只是恰好赢了这次竞态，掩盖了 bug。）

修复：**wrapper 的退出永远不算失败**，唯一成功判据是「端口文件出现 + ping 通」；退出码只作为
超时错误里的诊断信息。见 `lib/ghidra.js` 的 `startServer` 轮询段。

### 4. `lib/ghidra.js` — 残留 JVM 占着 Ghidra 项目锁，导致后续 `ghidra_open` 全部失败
Ghidra 用的是 **Java Channel Lock**。上一个 JVM 若因崩溃 / DSH 被杀 / 测试脚本未清理而残留，
它会一直持有 `dsh.lock`（lock 文件内容里 `Hostname` / `Username` / `Timestamp`）。
**删掉 `.lock` 文件并不能释放锁**，而 `cleanLocks()` 只做删除，于是新的 launcher 拿不到项目、
立刻 exit 0 且永不写端口文件 —— 表面症状与补丁 3 完全一样，极易误诊。

修复：新增 `killStaleServers(projectDir, pidFile)`，在 `startServer` 里于 spawn 之前执行：
1. 读 `%TEMP%\dsh-ghidra\server.pid`（成功启动后写入），有则 `killPid`；
2. 用 PowerShell CIM 找出命令行包含该 `projectDir` 的 `java.exe` / `python.exe` 并杀掉；
3. 删除 pid 文件。

局限：本项目目录是**单服务器**设计（插件自己也只服务一个程序），因此同时跑两个实例
（例如 GUI 里开着 + 另跑 headless 测试）会互相杀掉对方的服务器。这是上游设计使然，非本次引入。

### 5. `scripts/DecompileBridge.py` + `index.js` — 上报并清理真正的 JVM pid
wrapper 会提前退出，所以 `srv.child.pid` 是那个短命启动器，`taskkill` 它 **杀不到真正的 JVM**，
每次 `ghidra_close` 都会留下孤儿 JVM —— 正是补丁 4 里那个锁的来源。

- `DecompileBridge.py`：新增 `server_pid()`（优先 `ManagementFactory.getRuntimeMXBean()`，退回
  `os.getpid()`），端口文件从 `<port>` 改为写 **`<port> <pid>`**。
- `lib/ghidra.js`：解析两个字段，成功后在 `server.pid` 落盘，返回值增加 `pid`。
- `index.js`：`state.serverPid`；`killServer()` 先杀 `serverPid` 再兜底杀 `child.pid`；
  `ghidra_open` 返回体里的 `pid` 改为真实 JVM pid（`OUT` schema 本来就预留了 `pid` 字段）。

## 本地扩展：批次 1「读侧补齐」（11 个新工具，不是上游补丁）
对照 `bethington/ghidra-mcp` v7.0.0（253 端点 / headless 可用 226）的端点语义，
在**本插件里用 Python 重写**为单程序版——不采用其 Java 扩展，因为那需要多一套 Ghidra 进程、
把版本绑死到 12.1.3，且 226 个工具 schema 注进系统提示的上下文成本不可接受
（其 `tests/conformance/snapshots/mcp_schema.snap` 就有 316KB）。
上游每个端点都带 `program` 参数（多程序服务器），本插件单程序，**一律丢弃该参数**。

落点：`scripts/DecompileBridge.py` 的 `op_*` + `OPS` 注册；`index.js` 的 `defineTool`。工具总数 **8 → 19**。

| 新工具 | 桥接 op | 对照上游端点 |
| --- | --- | --- |
| `ghidra_segments` | `segments` | `list_segments` |
| `ghidra_imports` | `imports` | `list_imports` |
| `ghidra_exports` | `exports` | `list_exports` |
| `ghidra_search_strings` | `searchStrings` | `search_strings`（正则 + offset/limit 翻页） |
| `ghidra_search_functions` | `searchFunctions` | `search_functions`（正则 + 翻页） |
| `ghidra_calls` | `calls` | `get_function_callers` + `get_function_callees` |
| `ghidra_call_graph` | `callGraph` | `get_function_call_graph`（BFS，带 depth/maxNodes 上限） |
| `ghidra_read_memory` | `readMemory` | `read_memory` + `inspect_memory_content` |
| `ghidra_disassemble` | `disassemble` | `disassemble_function`（只读反汇编，不新建指令） |
| `ghidra_variables` | `variables` | `get_function_variables` |
| `ghidra_pcode` | `pcode` | `get_function_pcode`（listing / high 两档） |

移植时踩到的两个 Ghidra 12 API 事实（已写死在 `_take()` 里，**别按直觉写**）：
1. `Function.getCalledFunctions/getCallingFunctions` 返回 **`java.util.Set`**，不是 `FunctionIterator`；
   而 `ReferenceManager.getReferencesTo` 返回迭代器。按迭代器用会得到
   `'java.util.HashSet' object has no attribute 'hasNext'`。`_take(coll, maxn)` 两种都吃。
2. `Function.getSignature()` 对返回类型未解析的函数会渲染成 `undefined __fastcall entry(void)` ——
   那个 `undefined` 是 **Ghidra 自己的措辞**，不是字段丢失，别去「修」它。

已由批次 2 接走：写侧（rename/comment/prototype/save/函数增删/标签）。工具总数 **8 → 19 → 29**。

仍留在上游未移植（后续批次 3/4）：分析自动化（`run_script_inline` / `run_ghidra_script`，
**全仓库最高杠杆的单项**）、malware/BSim、`debugger/*`（20 个，且 GUI-only）、`server/*`、
project/headless 生命周期、documentation 迁移类。

## 本地扩展：批次 2「写侧补齐」（10 个新工具 + 一个致命补丁 6）
对照 `bethington/ghidra-mcp` v7.0.0 的写侧端点，在 Python 侧重写为单程序版（同上，不走 Java 扩展）。
落点：`scripts/DecompileBridge.py` 的 `op_*` + `OPS`；`index.js` 的 `defineTool`。工具总数 **19 → 29**。

| 新工具 | 桥接 op | 关键语义（实测，勿凭直觉） |
| --- | --- | --- |
| `ghidra_get_comments` | `getComments` | 单地址 → `{list:[...], total}`；批量 `addresses[]` → **扁平数组**；另有 `onlyWithComments` |
| `ghidra_set_comment` | `setComment` | 参数是 `address` 或 `addresses[]` + `comment`+`type`，或 `comments{}` 一次多类型；`type` = plate/pre/eol/post/repeatable（**没有 `target`/`text`**） |
| `ghidra_rename` | `rename` | 函数/符号改名 |
| `ghidra_label` | `label` | create / list / delete；list 用三参 `getSymbols(AddressSetView, SymbolType, boolean)`（两参版在 Ghidra 12 不存在） |
| `ghidra_set_prototype` | `setPrototype` | 三级解析链：`ghidra.app.util.cparser.C.CParserUtils.parseSignature` → `FunctionSignatureParser.parse(f.getSignature(), text)` → 手写 `_manual_signature`；另有 `noReturn` |
| `ghidra_set_variables` | `setVariables` | 先 DB（`_find_db_var` 遍历 `getParameters()`+`getLocalVariables()`，因为 `getParameter(String)` 不存在），失败再走反编译器 |
| `ghidra_create_function` | `createFunction` | |
| `ghidra_delete_function` | `deleteFunction` | `DeleteFunctionCmd.applyTo(Program)` —— **不接受 monitor 参数** |
| `ghidra_tags` | `tags` | get/attach/detach/create/delete/search/list；挂摘标签在 **`Function`** 上（`addTag`/`getTags`/`removeTag`），删标签对象用 `FunctionTag.delete()` |
| `ghidra_save` | `save` | flush 语义：进程内 `df.save()` 必然失败（见下），改为「优雅停止服务器 → headless 收尾落盘 → 重开」，返回 `flushed:true` |

### ★ 6. `scripts/DecompileBridge.py` — `_Tx.__exit__` 用 abort 关子事务，静默丢掉整轮写改动
本批次最隐蔽的缺陷，**现象与根因相距极远，值得完整记录**。

**症状**：写操作在会话内全部读得回来，`currentProgram.isChanged()` 与
`getDomainFile().isChanged()` 都是 `true`，headless 每次都打印
`INFO REPORT: Save succeeded for processed file: /winver.exe`，**但重开服务器读到的还是改动前的旧值**。
即「保存成功」与「改动消失」同时发生。

**根因**：`_Tx.__exit__` 原本写的是
```python
currentProgram.endTransaction(self.tid, et is None)   # 异常时 = False = abort
```
headless / PyGhidra **在脚本外层持有一个事务**（`PyGhidraScriptProvider$PyGhidraHeadlessScript`），
我们的每个写事务都是它的**子事务**。对子事务调用 abort 会让 Ghidra **丢弃整个外层事务**——
内存里改过的东西还在（所以读得到、`isChanged()` 仍为 true），但收尾提交时全部作废。
更糟的是 `except Exception: pass` 把这个失败也吞了，所以 `bridge.log` / `application.log` 里**一条错误都没有**。

**触发条件**：任何在 `_Tx` 内部抛异常的操作。用 8 个失败用例做隔离（`fail-test.mjs`，每例
`open → 探事务 → 跑失败 op → 写唯一 plate → ghidra_save → 读回`）后，**恰好两个**中招：

| 失败 op | 结果 |
| --- | --- |
| `create_function`（不可创建地址 `0x14000f000`） | **丢弃** |
| `set_prototype`（签名 `int ???bad(` 无法解析） | **丢弃** |
| `set_variables` 坏变量名 / 坏类型 | 落盘正常 |
| `search_strings` 坏正则 | 落盘正常 |
| `get_comments` 坏地址 | 落盘正常 |
| `tags attach` 不存在的标签 | 落盘正常（且 attach 会按需创建标签） |
| `rename` 不存在的函数 | 落盘正常 |

后五个之所以没事，是因为它们在**进入 / 交换事务之前**就失败了，压根没走到 `__exit__` 的 abort 分支。

**修复**：`__exit__` **永远提交**，绝不 abort——
```python
currentProgram.endTransaction(self.tid, True)   # abort 子事务会让整个外层事务被丢弃
```
并在 `endTransaction` 自己失败时写 `log()`（原来的 `pass` 让这个问题隐身了很久）。
修复后 `fail-test.mjs` 8/8 全部 `PERSISTED=true`，harness 从 83/84 变 **84/84**。

**这个 bug 为什么难定位**：单写 / 18 个写逐个 save / 全部读 op + 1 个写 / 19 个写（含删除+重建函数）
等我自己构造的**只用成功操作**的复现，**全都落盘正常**；只有 harness 顺带跑了那两个**失败**用例才命中。
教训：验收用例里「失败路径」不是陪衬，它们会污染共享状态；而「保存成功」这句日志**不能**当作
「改动写进了磁盘」的证据，必须重开一次读回来才算数。

### ★ 7. `index.js` — 插件卸载时硬杀 JVM，整个会话的写改动全丢
**症状**：会话里 `ghidra_set_comment` 等写操作全部成功、会话内读得回来；但 DSH 一旦重启 / 关窗
（插件被卸载）而 agent **没有**显式调用 `ghidra_save` / `ghidra_close`，重开后改动全部消失。
只读批次（1）永远暴露不出这一条，它是写侧能力上线后才成立的缺陷。

**根因**：卸载钩子 `ctx.effect(() => () => killServer())` 走的是**硬杀**
（`process.kill` + `taskkill /pid <jvm> /T /F`）。此时 `DecompileBridge.py` 的 `main()` 还在
`server.accept()` 循环里，脚本永远不会 return；而 headless **只在脚本正常结束后**才把改动写回项目 ——
一刀下去等于把整轮分析白做（实测：dispose 4ms 返回、JVM 随即消失、重开读到旧值）。

**修复（两层）**：
1. 卸载钩子改为**优雅停止**：`ctx.effect(() => () => stopServer(20000))` —— 先发 `{op:'shutdown'}`
   让 `main()` return，轮询等 JVM 自行退出（宽限期内没退才强杀），graceful 时再多留 1.5s 给 headless 收尾。
2. 进程被硬退出（`process.exit` / 关窗，dispose 可能来不及 await）的**同步兜底**：`process.on('exit')`
   里用 `spawnSync(process.execPath, ['-e', SYNC_STOP, port, pid], { timeout: 20000, stdio: 'ignore' })`
   起一个同步子进程发 shutdown 并等 JVM 消失。`'exit'` 回调里不能 await，所以只能这么做。

**验证**：新增 `exit-test.mjs`（两阶段、两个独立进程：`write` 写唯一 plate 后模拟卸载，`read` 重开读回）

| 场景 | 修复前 | 修复后 |
| --- | --- | --- |
| 调 dispose 钩子（等价插件卸载） | `PERSISTED=false`（dispose 4ms 返回，JVM 已被杀） | `PERSISTED=true`（dispose 2272ms，JVM 自行退出） |
| 直接 `process.exit(0)`（不给 dispose 机会） | `PERSISTED=false` | `PERSISTED=true`（同步兜底生效） |

两种场景结束后都无 java/python 残留。

## 本地扩展：批次 3「分析自动化」（共 14 个新工具）
对照 `bethington/ghidra-mcp` v7.0.0 的分析自动化端点，在 Python 侧重写为单程序版（同上，不走 Java 扩展）。
落点：`scripts/DecompileBridge.py` 的 `op_*` + `OPS`；`index.js` 的 `defineTool`。工具总数 **29 → 38 → 43**。

本批次的价值不在于「多 14 个工具」，而在于第一件：**`ghidra_run_script_inline` 等于把完整的 Ghidra API 交给 agent**，
其余移植从此只是便利性，不再是能力上限；后续批次（malware/BSim、debugger、project 生命周期）都可以由它兜底。

### 3a. 运行与分析控制（9 个）

| 新工具 | 桥接 op | 关键语义（实测，勿凭直觉） |
| --- | --- | --- |
| `ghidra_run_script_inline` | `runScriptInline` | 在桥接脚本的上下文里 `exec` 一段 Python。命名空间预置 `currentProgram/program/monitor/println/print/getScriptArgs()`；赋值给 `result` 会原样回传；**Python 与 Java 双路 stdout** 都被捕获；脚本抛异常不打断桥（返回 `error` + `traceback`）；`write=true` 时整段包在一个事务里 |
| `ghidra_run_script_file` | `runScript` | 与 inline 同一上下文，源码来自磁盘（`.py/.pyw/.txt`），参数经 `getScriptArgs()` 传入；Java/Groovy 脚本**明确拒绝**（本桥是进程内执行，不走 headless 的 script provider） |
| `ghidra_list_analyzers` | `analyzers` | 分析器与开关就存在程序的「分析选项」里：`Program.ANALYSIS_PROPERTIES` = **`"Analyzers"`**（12.1.4 实测 125 个叶子选项 / **32 个分析器**）。顶层名 = 分析器，`分析器.子项` = 子选项 |
| `ghidra_configure_analyzer` | `analyzerConfig` | 按选项**真实类型**写：`getType` → `BOOLEAN/INT/LONG/DOUBLE/STRING/ENUM`。⚠️ `getBoolean` 对非布尔选项抛 `IllegalStateException: Expected option type: BOOLEAN_TYPE`；⚠️ 枚举**只能** `setEnum(String, java.lang.Enum)`（传字符串报 `No matching overloads found ... setEnum(str,str)`），实现用 `getEnum(name, None)` 取当前常量、再 `getClass().getEnumConstants()` 找同名常量，并把可选值列在 `choices` 里 |
| `ghidra_run_analysis` | `runAnalysis` | `AutoAnalysisManager.startAnalysis(TaskMonitor, boolean force)`。**不自己开事务**：分析线程自己管事务，而 headless 在脚本外层本来就持有一个大事务 |
| `ghidra_reanalyze` | `reanalyze` | 范围 = 函数体 / 单地址 / `all=true` 的全部已初始化内存 → `reAnalyzeAll(AddressSetView)` + `startAnalysis` |
| `ghidra_search_byte_patterns` | `searchBytes` | 反复调 `Memory.findBytes(start, end, byte[], mask[], forward, monitor)`。支持整字节 `??` 与**半字节** `4?`（掩码实现）、`\|` 分隔多模式；`executable=true` 只扫可执行块 |
| `ghidra_find_code_gaps` | `codeGaps` | `Listing.getUndefinedRanges(AddressSetView, doFollowData, monitor)`。⚠️ **必须传 AddressSetView，不能传 MemoryBlock** —— 见补丁 8 |
| `ghidra_find_dead_code` | `deadCode` | 无调用者 ∧ 非 external ∧ 非 thunk ∧ 不在入口点集合里。间接调用（函数指针表 / 虚表）在这套判据下看不见，所以是**候选**而非定论 |

### 3b. 复合分析 / 指令搜索 / 哈希比较 / 数据流（5 个）

| 新工具 | 桥接 op | 关键语义（实测，勿凭直觉） |
| --- | --- | --- |
| `ghidra_function_context` | `functionContext` | 一个函数一次拿全：签名/参数/局部变量、callers/callees、指向入口的 xref、函数体内指向字符串的引用、指令数与 `codeMd5`/`mnemonicMd5`、反编译器的基本块·pcodeOp·分支·边·**圈复杂度**、伪代码（`includeCode=false` 可省）。比逐个调 decompile/variables/calls 省往返 |
| `ghidra_search_instructions` | `searchInstructions` | 三种条件 AND：`mnemonic` 助记符子串、`operand` 整条指令文本子串、`pattern` 整条指令文本正则；`target` 可限定函数体（`scope` 回显 `function <名>`）；返回 `{list,total,scope,truncated}`，每行带所在 `function` |
| `ghidra_hash` | `hash` | 函数级：`bytesHash`（原始字节）+ `codeHash`（整条指令文本）+ `mnemonicHash`（只取助记符 —— 改立即数不变，适合认「同一段代码的变体」）。程序级：逐块哈希 + `imageHash`，并回传 Ghidra 记的 `executableMD5`/`executableSHA256`/`executableFormat`/`executablePath` |
| `ghidra_compare_functions` | `compareFunctions` | 同程序两函数的参数/被调用函数差集、`textSimilarity` 与 `mnemonicSimilarity`（`difflib.SequenceMatcher`）、`sameMnemonicSequence`、逐条对齐的前 N 处差异。**一次只开一个程序**，跨程序比较请各自 `ghidra_hash` |
| `ghidra_data_flow` | `dataFlow` | 用反编译器高层 p-code：`Varnode.getDef()` 往回、`Varnode.getDescendants()` 往前做 BFS（`direction`=forward/backward/both，`depth`≤12、`max`≤2000）。`list=true` 且不给 `variable` 时列出该函数全部高层符号（`LocalSymbolMap.getSymbols()`） |

### ★ 10. `op_function_context` — 用不存在的 `getOutEdges()` 算圈复杂度，字段静默缺失
`HBasicBlock` 的实现类是 `ghidra.program.model.pcode.PcodeBlockBasic`，它**没有** `getOutgoingEdges()`/`getOutEdges()`
（实测报 `'PcodeBlockBasic' object has no attribute 'getOutgoingEdges'`）。我原来把取边包在 `try/except` 里、
失败就整块跳过，于是 `edges`/`cyclomaticComplexity` **既不报错也不出现** —— 又是一个「假绿」形状。
正确的取法是 `getOutSize()` / `getInSize()`（还有 `getIn(i)` / `getOut(i)` / `getTrueOut()` / `getFalseOut()`），
圈复杂度按 `M = E - N + 2P`（P=1）计算。教训同补丁 8：**用 try/except 兜住的字段，验收必须显式断言它存在**。

### ★ 8. `op_code_gaps` — 把 MemoryBlock 当成 AddressSetView 传，且错误只在结果字段里
第一轮 `verify-batch3.mjs` 里 `find_code_gaps` 返回 `total:0` 而断言全过，看起来「没找到空洞」；
实际每个块都失败了：`getUndefinedRanges(MemoryBlockDB, bool, TaskMonitor)` 报
`No matching overloads found`，而我把这个错误塞进结果的 `errors` 字段、断言却没检查那个字段。
给每个块先构造 `AddressSet(block.getStart(), block.getEnd())` 再传，`.text` 立刻报出真实空洞
（例如 `140001001–14000100f`，15 字节）。验收脚本同时加了一条「errors 必须为空」的断言。
教训：**「工具返回了结果」不等于「工具工作了」**；把错误降格成结果字段时，验收必须断言那个字段。

### ★ 9. `op_analyzer_configure` — 枚举选项与字符串布尔的静默陷阱
(a) `Options.getBoolean` 对 ENUM/STRING 选项抛 `IllegalStateException`，必须先 `getType(name)` 分派；
(b) Node 工具把 `value` 声明成 `string` 传下来，而 `bool('false') == True` —— 会把「关掉分析器」写成「打开」，
所以显式走 `_coerce_bool` / `_coerce_num`。

## 本地扩展：批次 4「恶意代码分析」（4 个新工具 + 补丁 11/12）
工具数 43 → **47**。四个 op 都插在 `scripts/DecompileBridge.py` 的 `_HANDLES = {` 之前；常量生成器夹在
`# ==== BATCH4-CONSTS-BEGIN ====` / `# ==== BATCH4-CONSTS-END ====` 之间，**纯 Python、不 import java/jpype**，
所以能脱离 Ghidra 单测（这也是 KAT 能做起来的前提）。

| 工具 | 参数 | 干什么 |
|---|---|---|
| `ghidra_detect_crypto_constants` | `filter` / `blockFilter` / `limit` | 28 条常量签名逐块精确匹配：AES S-box 正/逆表、CRC32/CRC32C、MD5 与 SHA-1/256/512 的 init 与 K 表、Keccak 轮常量、ChaCha/Salsa 魔数、Base64 两种字母表、Blowfish P-array、Curve25519/secp256k1/P-256 素域模数 |
| `ghidra_detect_malware_behaviors` | `categories` / `limit` | 10 类行为（process-injection / execution / persistence / credential-access / c2-network / evasion-anti-debug / cryptography / collection-exfiltration / file-registry-ops / privilege-escalation）× 词边界匹配的 API 名表；每条证据标明来源 `import`（外部符号）/ `function`（函数名）/ `string`（字符串） |
| `ghidra_extract_iocs_with_context` | `types` / `minLength` / `max` / `includeRawMemory` / `maxBytes` | 17 类 IOC；默认只扫已定义字符串，`includeRawMemory=true` 再扫未定义数据里的可打印 ASCII 串（补丁 11 的现场） |
| `ghidra_find_anti_analysis_techniques` | `max` | 反调试 API / 反虚拟机沙箱字符串 / 调试器与分析工具字符串 + `RDTSC`(0F 31) / `CPUID`(0F A2) / `INT3`(CC) 字节计数，`risk` 是线索数量压成的排序标签 |

**常量表用 KAT 自证**：`kat-consts.py` 切出 BATCH4-CONSTS 块 `exec` 后跑 62 条已知答案断言
（AES S-box[0]=0x63、逆表与正表互逆、CRC32 表[1]=0x77073096 / [255]=0x2D02EF8D、CRC32C[1]=0xF26B8303、
MD5 T[0]=0xD76AA478 / [63]=0xEB86D391、SHA-512 K、Keccak rc[0]=1 / rc[23]=0x8000000080008008、
Blowfish P-array 首字节 `243F6A8885A308D3`、三条全表长度 256/1024/256 …），
`py -3.13 kat-consts.py` → `KAT OK — 62 checks passed, 28 signatures verified`。
常量是**运行时算出来的**（`_aes_sbox` = GF(2^8) 求逆 + 仿射变换，`_md5_t` = `int(abs(sin(i+1)) * 2^32)`，
`_keccak_rc` = LFSR 且每轮 xor 0x71，模数由 `2^n ± …` 现算），不是抄的十六进制字面量 —— KAT 就是它们的证明。

### ★ 11. `_range_len` 对 MemoryBlock 静默返回 0 —— `includeRawMemory` 一个字节都没扫
`verify-batch4.mjs` 首跑 44/47，其中一条是 `bytesScanned=0`。真因是两个 bug 叠在一起：
1. `_range_len(r)` 老实现只试 `r.getLength()`，失败退回 `r.getMaxAddress().subtract(r.getMinAddress()) + 1`；
   **`MemoryBlock` 这两个方法都没有**（用 `ghidra_run_script_inline` 实测，两者都是 `AttributeError`；
   它只有 `getStart()` / `getEnd()` / `getSize()`）→ 两路全失败 → `return 0`。
2. `_raw_printable_rows` 里 `while off < length` 于是从不执行，函数安安静静返回 `(rows=[], total=0)`，
   op 把它当作「没有 IOC」报出去。
`_range_len` 在 `op_search_bytes` / `op_code_gaps` 里一直没暴露这个洞，因为那两处传进去的是 `AddressSetView`。
修法：四条探测链 `getLength() → getSize() → min/max → start/end`，取第一个 >0 的结果；
`_raw_printable_rows` 改为返回 `(rows, bytes_read, blocks_seen, blocks_read)`，op 在
「请求了 includeRawMemory 却读到 0 字节」时**直接报错**，不再返回一个看起来正常的空结果。
修后实测：certutil.exe 1606736 字节 / 10 块，reg.exe 69632 字节 / 3 块。
顺手把 `maxBytes` 从「软上限」改成**硬上限**：每次读也按剩余额度裁剪
（`min(chunk, length - off, max_bytes - total)`）。改之前 `reg.exe` 请求 65536 却读了 69632
（整块读会超出一个 chunk），改之后正好 65536 —— 参数说多少就多少。
教训（第三次同一形状）：**把失败降格成 0 或空值，验收只有显式断言那个数字才能发现**。

### ★ 12. IOC 的 ipv4 通道被 X.509 OID 表项淹没 —— 新增 `oid` 类型
`certutil.exe` 实测：80 条命中里 **59 条被判成 ipv4**，几乎全是 OID —— `2.5.29.14`、`2.5.29.35`，
甚至从 `1.3.6.1.4.1.311.21.4` 里切出来的碎片 `3.6.1.4`。两个修法：
- 正则前后加 `[\d.]` 边界：`(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])` —— 切出来的碎片消失；
- 新增 17 类里的 **`oid`**：点分十进制在形式上无法与 IPv4 区分，改用 ITU-T 的弧取值规则判定
  （第一弧 ≤2 且第二弧 ≤39 ⇒ OID；段数 >4 一定不是 IPv4）。代价是 1.x/2.x 且第二段 ≤39 的真实地址
  会被归到 `oid`（值仍在结果里，只是类型不同）。
修后实测：`byType={"oid":180,"url":3,"domain":11,"mutex":5,"winpath":1}`，**ipv4 = 0**；
`types=ipv4` 只剩版本串里的 `5.1.0.0`。顺带把 URL 正则加了前置 `%` 排除
（`%ws://%ws/ct/v1/%ws` 是 printf 模板，不是 URL）。

### ★ 13. 验收断言的两种写法：断在回归点上，别断死数字；负对照与真阳性成对
批次 4 的 harness 先跑成 54/55，唯一 FAIL 是我自己写死的
`(byType.ipv4 || 0) === 0`：全量扫描（`max:400`）比开发期的小样本多抓到一条
`5.1.0.0` —— 那是 certutil 里的版本串，第一弧 5 > 2，按 ITU-T 弧规则**本来就不是 OID**，
归 `ipv4` 是正确行为。补丁 12 的回归点是「OID 表项不再灌进 ipv4」，所以断言改成
**`oid >= 20` + `ipv4` 稀少（≤5）+ 没有任何 `^[0-2]\.(\d|[1-3]\d)\.` 形状的值**（`oidShaped === 0`）。
两条纪律记在这里：
1. **不许为了让 harness 变绿而放宽断言** —— 先证明「这个值是合法的」再改；
2. 改成形状断言（有边界的性质）而不是等值断言（写死的数字），否则样本一变大就会假红。
另一个正向经验：**负对照和真阳性必须成对**。`detect_crypto_constants` 在 `winver.exe` 上
`total=0`（负对照，证明不是「见谁都报」），在 `kernel32.dll` 上抓到完整的 1024 字节 CRC32 表
（真阳性，证明真的会扫）—— 只有一边都说明不了问题。

### ★ 14. `index.js` — `categories`/`types` 只收逗号分隔 string，传数组直接 `ToolArgsError`
`ghidra_detect_malware_behaviors` 的 `categories` 与 `ghidra_extract_iocs_with_context` 的 `types`
原本声明为 `type: 'string'`，而模型很容易传数组，会得到
`ToolArgsError: invalid arguments: "types" must be a string`；Python 侧两种形状都收
（`DecompileBridge.py` categories/types：str → `split(',')`，list → 逐个 str）。
**修复**：两个参数改成 `oneOf: [{type:'string'…}, {type:'array', items:{type:'string'}…}]`，
顶层 `description` 说明双形状，payload 构建按 key 循环转发（数组原样传给 Python，无需改）。
`defineTool` 的 parameters 相关事实（读 `@deepseek-ai/dsh-tools/lib/types/schema.js` 核实）：
- **不是 schemastery**，是 JSON Schema 子集；`schema.js:295` 在 `defineTool` 时就把
  `options.parameters` 编译成 raw schema 存到 `tool.parameters` —— 验收时**别再编译一遍**
  （重复编译会把编译根的 `type` 键当成属性名，报 `parameters.type must be a value schema object`）。
- `oneOf`（`schema.js:130-148`）：与 `type` 不能同时出现，须 ≥2 个 value schema；
  分支 `allowRequired:false`，可带 `description`（`ANNOTATION_KEYS = ['description','title','default','examples']`）。
- array 分支（`schema.js:173-186`）允许 `items`（value schema）。
**验收**：`node probe-union-args.mjs [已装副本目录]` —— 校验 `tool.parameters`（已编译）含 oneOf、
`validateJsonSchemaValue` 接受 string/array/空数组、拒绝 number（负对照）；两副本各跑一遍；
`verify-batch4.mjs` 增加三个数组形状调用：certutil 上 `types:['domain','url']` **真阳性**
（排序后的 `typesScanned` 集合语义 + `total>=1` + 每条 type ∈ 输入集合）、reg.exe 上同数组
（无命中 → `total=0` 是正确行为，只断 typesScanned 集合）、cmd.exe 上 `categories:['c2-network']`
（`categoriesScanned===1`，与 string 形状一致）。
**补丁 13 的教训在这里再次应验**：`typesScanned` 按 Python `_IOC_TYPES` **表顺序**回，不按输入顺序 ——
第一版断言写死 `=== '["domain","url"]'` 直接假红（实际回 `["url","domain"]`，工具本身是对的）；
集合语义断言必须排序后比较。

## 本地扩展：上游 GhidraMCP REST 桥（168 个生成工具 + 3 个 lifecycle + 补丁 15/16/17）
上游 `bethington/ghidra-mcp` 7.0.0-rc.1 发布物自带独立 headless 服务器（`com.xebyte.headless.GhidraMCPHeadlessServer`，
226 个 REST 端点；`<ghidraHome>\support\ghidraMCPHeadless.bat`）。**架构决策**：不把 226 个端点逐个移植成
PyGhidra in-process op（那是批次 1–4 的路子，成本太高），而是写一层 **HTTP 桥** —— `lib/mcp.js` 把
`ghidraMCPHeadless.bat` 当子进程拉起（stdout/stderr 重定向到 `%TEMP%\dsh-ghidra\mcp-headless.log`，服务器在
管道断开后会存活但输出丢失），REST 调用 GET→query / POST→JSON body；`lib/mcp-tools.js` 是**生成器
`gen-mcp-tools.mjs`** 从 live schema dump（`UPSTREAM-SCHEMA-LIVE.json`，实测 226 端点）产出的 168 个
`ghidra_mcp_*` 工具（SKIP 表 58：5 个 infra + 45 个与原生 47 工具重复 + 2 个脚本 + 6 个恶意代码原生等价）。
`index.js` 注册 3 个 lifecycle（`ghidra_mcp_start` 带 file/project 参数、`ghidra_mcp_stop` 先
`/save_all_programs` + `/exit_ghidra` 优雅再按端口/PID 强杀、`ghidra_mcp_status` /health 快照）+ 循环注册 168 个。
**语义分界**：`ghidra_mcp_*` 作用于 MCP headless 服务器里加载的程序，与 `ghidra_open` 的 PyGhidra 桥程序
完全无关 —— 两个独立 Ghidra 实例；`mcpStart` 已在运行时直接采纳（已加载程序保留）。
**发布注记的 "253 MCP TOOLS" vs 实测 226 端点**：同一构建的运行服务器只暴露 226 个 REST 端点
（`/list_methods` 列的是程序函数不是端点）；253 是上游自己的计数口径（可能含 MCP stdio 模式的注册），
live schema dump 是 REST 桥的 ground truth。226 = 168 生成 + 45 原生映射 + 5 infra + 2 脚本 + 6 恶意代码。

### ★ 15. `lib/mcp.js` + `gen-mcp-tools.mjs` — 生成条目缺 `params` 数组，参数恒传不出去（上游报 "X is required"）
生成器第一版只把端点参数编译成 `parameters`（schema 属性表），没把**原始端点参数表**（`name/type/source/required`）
带进条目 —— `lib/mcp.js` 的 `buildRequest` 靠 `ep.params` 把调用方参数编进 GET query / POST body，
`ep.params` 为 undefined 时静默跳过所有参数 → body 恒为 `{}` → 上游报
`{"error":"Address is required (or pass labels[] for bulk)"}`（HTTP 仍 200，`ok:true` 掩盖失败）。
**修复**：① 生成器每个条目带 `params: (ep.params||[]).map(p => ({name,type,source,required}))`；
② `mcpCall` 把上游错误也算失败 —— 上游错误有两种形状：`{success:false,error}` 与裸 `{error:"…"}`（HTTP 200），
都返回 `ok:false`；成功包络 `{status:'success',message,warnings[]}` 无 error 键不受影响。
**回归**：`verify-load.mjs` 新增断言「桥工具全部带 params 数组」—— 查 **MCP_TOOLS 条目**而不是注册结果
（defineTool 会丢掉自定义键，`params` 在 `execute` 闭包里经原始条目 `t` 传递）；12 个无参端点
（`exit_ghidra`/`get_current_address` 等）`params: []` 是合法的显式无参，不断言 length>0。

### ★ 16. `index.js` — `ghidra_mcp_status` 成功时返回 `error: undefined`，harness 判 invalid output
status 原本 `error: h.ok ? undefined : h.error` —— 输出 schema 里 `error` 声明为 `string`，成功时该
own property 持 `undefined`，harness 的输出校验报 invalid output（工具层 E2E 不校验输出，抓不到；
真实 headless 会话实测：`ghidra_mcp_list_functions_enhanced` 正常返回 3 个函数，`ghidra_mcp_status` 报错）。
**修复**：error 只在失败时写进结果对象。**验收**：真实 headless 会话重跑 → `MCP_STATUS_OK running=true program=winver.exe`。

### ★ 17. `lib/mcp.js:105` — Node 20.12+ 在 Windows 上直接 spawn `.bat` 一律抛 `spawn EINVAL`
`mcpStart` 原本 `spawn(opts.bat, args, {windowsHide, stdio})`，`opts.bat` 是
`ghidraMCPHeadless.bat` —— Node 20.12.1 起（CVE-2024-27980 修复）Windows 上对 `.bat`/`.cmd`
无 shell 的 spawn **无条件抛 EINVAL**。之前没抓到是因为验收全走**采纳路径**（服务器已运行，
`adopted:true` 不 spawn）；重启后首次真实调用 `ghidra_mcp_start` 才暴露。
**修复**：`spawn([opts.bat, ...args].map(a => /\s/.test(a) ? '"'+a+'"' : a).join(' '), {shell:true, ...})`
—— shell:true + 单串命令，含空格的 token 手工加引号；`child.pid` 是 cmd.exe 的，
停止时 `mcpStop` 用 `findPidByPort` 找真正的 java PID（不受影响）。
**验收**：`probe-mcp-start.mjs`（从已装副本 fresh import `lib/mcp.js` 绕开运行中 DSH 的旧内存代码）
→ `MCP_START ok:true adopted:false health 200`（3055ms 起服）→ `/server/status` ok:true → PROBE OK；
孤儿服务器存活，运行中会话 `ghidra_mcp_status` → running:true。
**顺带事实**：状态端点是两级路径 **`/server/status`**（不是 `/server_status`——后者 404）；
probe 退出后孤儿 JVM 存活且会挂住 pwsh 管道（job_kill 只杀 pwsh 包装进程，node 探针已退出，
java 服务器是有意保留的）。

## 本地扩展：插件化（v0.2.0 — 插件管理页 + 状态卡 + 可热改配置）
把包从「纯 node 半」升级为**双面插件**（浏览器半 + 状态路由 + 可热改配置），对齐 dsh-skill-hub 的成熟形态：

### 节点半（`index.js`）
- **Config 全部 volatile**：11 字段全部 `.default(...).description(...).volatile()`（`@deepseek-ai/schemastery`
  v3.18.4 官方路径）。保存配置 → Host reload Loader entry → `apply()` 重跑 → 立即生效，无需重启 DSH。
  volatile 值在 apply 时是 **ref**，`resolveConfig()`（`typeof v?.get === 'function' ? v.get() : v`）
  在 apply 顶部解析一次成普通值，其余代码照旧读 `config.*` 不感知 volatile。
- **模块级共享状态**：`state`（child/port/program/serverPid/binaryPath/mcpPid）、`currentConfig`、
  `activeDisposers`、`toolCounts` 与 `killServer/stopServer/SYNC_STOP + process.on('exit')` 全部移到模块级 ——
  volatile 写侧会**重跑 apply**，进程级资源与退出钩子必须跨 re-entry 保留；apply re-entry 先逆序拆解
  `activeDisposers` 再重注册（dsh-tools 同层重复名抛 `tool "X" is already registered`）。
- **状态路由**（soft inject `ctx.inject(['webServer'], ...)`，headless 无 webServer 静默跳过）：
  `GET /api/dsh-ghidra/status`（回环-only 校 `req.socket.remoteAddress`，返回 pyghidra/mcp 运行态、
  工具计数 native+lifecycle+generated、Ghidra 主目录与版本）与 `POST /api/dsh-ghidra/mcp-stop`
  （优雅停止上游 GhidraMCPHeadless）。重复注册用 `webServer.exact/prefixes.has(path)` 守卫。

### 浏览器半（`client.js`，无打包、plain JS + React）
- `window.__ModuleLoader__.load({ id: 'dsh-ghidra', factory(require) {...} })` 入口；
  **不 require 任何 `@deepseek-ai/dsh-client-*` 包**（plain-JS 插件无类型检查，抛错会 blank slot entry）；
  React 来自 browser module table；样式只用 `--dsw-alias-*` 主题 token。
- 注册 `plugins.bundle.config` slot（**key = BUNDLE 包名 `dsh-ghidra`**，非 row id），渲染进
  插件管理页的插件卡片：状态区（PyGhidra 桥 / GhidraMCP 服务器 / 工具计数 / 刷新 / 停止 MCP）
  + 配置区（11 字段表单：staged edits → save() 逐条写 + 读回 Host 验收 `userRecord()[field]===value`、
  已覆盖徽标 + 单字段重置、实时校验 number/boolean parse）。
- 配置表单走 `ctx.configForms.get('ghidra-bridge')`（ns = **plugin name/row id**）的
  `FormScope`（`subscribe/getSnapshot/set/unset`），自写 snapshot store（不依赖 dsh-client-store）。
- `inject: ['slots','connection','remote','configForms']`；每次 apply 用 `ctx.effect` 注册 provider，
  配置写入重跑 apply 时重建。

### 清单（`package.json` v0.2.0）
- `"./client"` export → `client.js`；`dsh.client: { inject: ['@deepseek-ai/dsh-client-connection',
  '@deepseek-ai/dsh-client-ui-settings'], platform: 'web' }`（client.inject 只排序激活，不打包）。
- `icon: "./icon.svg"` + `locale/en.json`、`locale/zh.json`（`{"meta":{"title","description"}}` 形状，
  插件管理页列表卡片的标题/描述；缺字段回退 package.json name/description）。

### 验收
- `node verify-load.mjs <已装副本目录>`（web + headless 各一次）→ 218 工具 + 2 条状态路由 +
  Config all-volatile，全部 PASS（桩 ctx 补了 `inject + webServer` 模拟宿主软注入）。
- 真实 headless 会话（`dsh headless --patch <web cordis.patch.yml>`）加载插件化后的 node 半，
  `ghidra_status` 正常应答（默认配置解析 volatile ref → 默认值，工具注册无异常）。
- **生效条件**：重启 DSH 后浏览器半才加载（client.js 由 `/plugins/dsh-ghidra/client.js` serve），
  插件管理页出现 Ghidra 桥卡片；`GET /api/dsh-ghidra/status` 可从宿主机验证。

## v0.10.0 — 随包技能 + 工具可用性门控（对照 REA 的 skill / tool-availability 契约）

来源是一次对 [morluto/rea](https://github.com/morluto/rea) 的深读：它的 Ghidra provider 只声明
**22 个 capability**（而不是把 122 个工具全摊开），`tools/list` **只广告当前 target/provider/policy
下真能调用的操作**，并用稳定的 `availability reason + remediation` 解释被隐藏的部分；另有一份
`skills/reverse-engineer-anything/SKILL.md` 负责「什么时候该用、什么时候不该用」。dsh-ghidra
此前两个都没有：218 个工具无条件注册，模型看不出哪些是死的；也没有任何东西告诉模型
「.NET 托管程序集不要往 Ghidra 里塞」。本次把这两件事补齐 —— **都不碰分析引擎**。

### 18. `ctx.skills.register()` —— 包里的 SKILL.md 必须跟着插件注册才活

新增 `lib/skill.js`（行级 frontmatter 解析，缺字段返回 `null` 而不是抛）与
`skills/dsh-ghidra/SKILL.md`（正文 10102 字符 / 98 行），在 `apply()` 里用
`ctx.inject(['skills'], (sctx) => ...)` 注册成运行时技能（`source: 'runtime'`）。

**为什么不只是把文件放进包里**：`dsh-skill-filesystem` 的默认根只有 project / custom / user /
bundled 四类（`discoverRoot` 认 `<dir>/SKILL.md` 与 `<dir>/<name>.md` 两种形态），
**不会去扫 `node_modules` 里的插件目录** —— 文件放着永远不会被发现。注册路径两条：
`ctx.skills.register(definition)`（内存技能，随插件生命周期）或 `ctx.skills.registerProvider()`
（dsh-skill-hub 走的这条）。这里选前者：简单，且插件卸载时技能自然消失。
校验只要求 `name` 匹配 `/^[a-z0-9]+(?:-[a-z0-9]+)*$/`、`description` 非空、`source` 是字符串，
默认 `invocation = { modelInvocable: true, userInvocable: true }`。

技能正文的核心是**路由**而不是工具手册：原生可执行/库/驱动/固件 → 用它；
JavaScript / Electron / ASAR / 源码、压缩包、.NET 托管程序集 → **明确说不用它**
（Ghidra 会把托管程序集当不透明原生 blob 导入，据此得出的结论全是错的）；
运行时行为问题 → 静态分析答不了，直说缺什么观察手段，不要用推断冒充事实。
另有「先看概览再动手」「区分观察 / 推断 / 未知」「写侧改动要 `ghidra_save` 才落盘」等纪律。

### 19. `ctx.tools.register()` 的 disposer —— 只广告现在跑得起来的工具

`dsh-tools` 的 `register()` 返回 `layers.effect(...)`，即**一个可用的 disposer**；
`ScopedLayers` 的变更回调会 `ctx.emit("tools/change")`。所以动态增删工具是官方支持的路径。

`apply()` 里新增一个 `gate`：`bridge`（45 个，判据 `state.port`）与 `mcp`（168 个，判据
`mcpHealth(mcpPort).ok`）各持 `pending / live`；`setGate(key, ok)` 幂等翻转 ——
true 时把 pending 逐个 `ctx.tools.register` 收进 live，false 时 `while (live.length) live.pop()()`。
常驻集合只有 5 个：`ghidra_status`、`ghidra_open`、`ghidra_mcp_start/stop/status`。
同步点：`apply` 末尾、`openFlow` 成功后、`ghidra_mcp_start/stop` 的两个分支、
`stopServer()` 内、以及 `ghidra_status` / `ghidra_mcp_status` / `GET /status` / `POST /mcp-stop`
每次被调用时（**agent 只调工具、不调路由，所以工具入口必须自己同步**）。
`gateSnapshot()` 产出 `{total, advertised, hidden:[{group,label,count,reason,remediation}], groups}`，
由 `ghidra_status`、`ghidra_mcp_status` 与状态路由三处上报。

**代价与取舍**：注册表变化会让那一次 prompt 前缀缓存失效（每次 start/stop 一次）。
换来的是「模型看到的工具集 = 现在真能跑的工具集」，以及一个可诊断的失败面 ——
以前 agent 要自己发现「ghidra_decompile 报『服务器未运行』」，现在是它压根看不到这个工具，
而 `ghidra_status` 直接告诉它被隐藏的是哪 45 个、为什么、以及怎么补救。

### 验收

- `node verify-load.mjs` → **21/21**（重写：不再断言「注册了 218 个」，改成断言
  【定义总数 218 = 常驻 5 + 桥门 45 + REST 门 168】+【冷启动只注册 5 个】+【`advertised + Σhidden = 218`】
  +【随包技能注册且带 `whenToUse` 与排除指引】）。桩 ctx 改成**按名字分发软注入**
  （`inject(names, cb)` 只给 `webServer` / `skills`），`tools.register` 用 Map 且**同名重复注册抛错**
  —— 撤门没撤干净会被立刻抓到；另用 `net.createServer().listen(0)` 取一个**确定空闲的端口**，
  否则本机真跑着 8123 时验收结果会随环境漂移。
- 新增 `node probe-availability.mjs` → **14/14**：用一个 stub `/health` 服务器冒充上游 REST，
  走完「冷启动 5 → 上线 173（168 个名字与生成器输出完全一致）→ 下线回 5」并横跳 3 轮，
  全程断言**无重复注册**（即 disposer 幂等、撤门干净）。
- `node probe-v4-routes.mjs <副本>` → 16/16；`node probe-client-apply.mjs` → 26/26；
  `node probe-contrast.mjs` → 21/21；`node verify.mjs` → ALL CHECKS PASSED。

### ★ 20. `verify-tools.mjs` / `verify-batch3.mjs` / `verify-batch4.mjs` / `verify-mcp-e2e.mjs` 的 ctx 桩一直是坏的

这四个 harness 从 v0.4.0（加 `ctx.inject(['webServer'], ...)` 状态路由）起就**再也跑不起来** ——
它们的桩没有 `inject`，`apply` 第一行就 `TypeError: ctx.inject is not a function`，
而它们还一直躺在 `package.json` 的 `files` 里发出去。本次一并修好：补 `inject`（按名字分发，
`webServer` 给最小 `{exact, prefixes, register}`）、并让 `tools.register` 返回 disposer
（门控要求）。**教训**：验收脚本自己也要有回归 —— 一个从不被运行的 harness 和被删掉没有区别，
只是更贵（它还在包里占位、还让人以为覆盖到了）。

### 清单（`package.json` v0.10.0）

- `files` 新增 `skills`（目录）与 `probe-availability.mjs`；`lib` 已覆盖 `lib/skill.js`。
- `sync-installed.mjs` 的 `FILES` 从 15 项加到 17 项（`lib/skill.js`、`skills/dsh-ghidra/SKILL.md`）
  → `synced 34 files across 2 profiles, mismatches=0`。
- **`files` 是显式清单不是 glob** —— 新增可发布文件必须手工登记，发布后必须 `tar -tzf` 解包核对
  （0.9.4 就漏过 `probe-contrast.mjs`）。

## 修改 master 之后的重新安装
`file:` 是**拷贝式**安装，改完 `C:\Users\Administrator\.dsh\plugins\ghidra-bridge` 里的源码后，
必须把它同步进 `profiles/<profile>/node_modules/dsh-ghidra`，变更才会生效。

**首选**：`node sync-installed.mjs` —— 把 17 个源文件（`index.js`、`client.js`、`package.json`、`cordis.patch.yml`、
`README.md`、`icon.svg`、`locale/{en,zh}.json`、`lib/{paths,ghidra,run,socket,mcp,mcp-tools,skill}.js`、
`skills/dsh-ghidra/SKILL.md`、`scripts/DecompileBridge.py`）拷进 web + headless 两个已装副本
（共 34 个文件），逐文件比对 SHA256，并清掉 `scripts/__pycache__`。
（也可重跑 `dsh plugin --profile <p> add "file:C:/Users/Administrator/.dsh/plugins/ghidra-bridge"`，
但它只改一个 profile，且不会清字节码缓存。）

⚠️ 验收脚本刻意加载**已装副本**（复现 DSH 的真实解析路径），所以**忘了同步 = 测的还是旧代码**，
会误判「修复无效」（本批次真实踩过）。

## 运行时依赖（已在本机装好）
| 组件 | 位置 / 版本 | 说明 |
| --- | --- | --- |
| Ghidra | `D:\tools\ghidra_12.1.4_PUBLIC`（12.1.4 PUBLIC） | 纯 ASCII 路径；`support\analyzeHeadless.bat` 存在，被 `detectGhidraHome` 扫 `D:\tools` 命中 |
| JDK | Temurin 21.0.12.1 LTS，`JAVA_HOME` 已设 | Ghidra 12 要求 |
| Python | 3.13.14（`py -3.13`） | 插件硬编码 `pythonVer: '3.13'` 且用 `py` 启动器探测，**不能用 uv 安装的 3.13** |
| pyghidra | 3.1.0 + Jpype1 1.5.2（装进 3.13 的 site-packages） | 插件的 `pyghidraInstalled('3.13')` 依赖它 |

以上都齐全时**无需任何配置**：`ghidraHome` 留空即自动探测到 `D:\tools\ghidra_12.1.4_PUBLIC`。

## 验收脚本
七个脚本都用绝对 `file://` URL 指向 **已安装副本**（`verify-batch3.mjs` / `verify-batch4.mjs` 也可显式传副本目录），
因此验的就是 DSH 实际加载的那份代码。**跑之前先 `node sync-installed.mjs`**，否则测的是旧副本。

```powershell
cd C:\Users\Administrator\.dsh\plugins\ghidra-bridge
node sync-installed.mjs    # 先把源码同步进 web + headless 两个已装副本（SHA256 校验）
node verify-load.mjs       # 加载路径 + Config 默认值(11 项) + 218 个工具注册
                           # (47 原生 + 3 lifecycle + 168 桥工具) + 桥工具 params 数组回归 → 10/10
                           # 传副本目录可分别验 web / headless 两份（LOAD TEST PASSED ×2）
node verify.mjs            # lib 层：探测→导入分析→startServer→7 个 op   → 15/15
node verify-tools.mjs <dir># 工具层：open(同步/流式)→批次 1/2 的全部工具实调→save(flush)→close，
                           # 断言写侧真的落盘（重开读回）且无孤儿 JVM；
                           # <dir> 传别的目录可验「换工作区仍可用」        → 85/85
node fail-test.mjs         # 8 个失败用例逐个隔离：失败 op 不再污染落盘    → 8/8 PERSISTED
node verify-batch3.mjs     # 批次 3 的 14 个新工具（inline 读/报错/写事务、脚本文件、
                           # 分析器列出与开关、枚举选项、字节模式通配、代码空洞、死代码、
                           # 重分析、跑分析、function_context 复合分析、指令搜索、
                           # 函数级/程序级哈希、函数比较、数据流 BFS）
                           # ＋ 用 ghidra_save 的 flush 验证 inline 写真的落盘
                           #                                          → 77/77 BATCH3_E2E_OK
node verify-batch4.mjs     # 批次 4 的 4 个新工具，6 个阶段 58 条断言       → 58/58 BATCH4_E2E_OK
                           # A/B: detect_crypto_constants 用 winver.exe 做**负对照**（一条常量表都没有），
                           #      再用 kernel32.dll 的真 CRC32 表做**真阳性**
                           # C/D: detect_malware_behaviors + find_anti_analysis 跑 cmd.exe
                           # E:   extract_iocs_with_context 跑 certutil.exe（域名/URL/OID，含 includeRawMemory
                           #      的补丁 11 回归）与 reg.exe（HKEY_* 注册表真阳性）；cmd.exe 里**没有** HKEY_*
                           #      字符串 —— 别拿它测注册表（这条是目标选错，不是工具错）
                           #      ＋ categories/types 各一个数组形状调用（补丁 14 的 oneOf 双形状回归）
node probe-union-args.mjs  # 补丁 14：tool.parameters（已编译）含 oneOf，validateJsonSchemaValue
                           #      接受 string/array/空数组、拒绝 number（负对照）  → UNION ARGS PROBE PASSED
node verify-mcp-e2e.mjs    # REST 桥 E2E（对 8123 上已运行的 ghidraMCPHeadless，winver.exe）：
                           # mcpStart 采纳 → status(/health) → list_functions_enhanced(读) →
                           # get_entry_points → create_label(写) → get_function_labels(读回) →
                           # delete_label(清理)                        → MCP_E2E_OK
node probe-mcp-start.mjs   # 补丁 17：mcpStart 的 spawn 修复（.bat EINVAL → cmd.exe/shell:true），
                           # 从已装副本 fresh import 绕开运行中 DSH 的旧内存代码 → PROBE OK
py -3.13 kat-consts.py     # 批次 4 常量表的 KAT（脱离 Ghidra，纯 Python）
                           #                     → KAT OK — 62 checks passed, 28 signatures verified
$env:EXIT_TOKEN='EXIT-...'
node exit-test.mjs write   # 模拟插件卸载/进程硬退出（不调 close/save）
node exit-test.mjs read    # 新进程读回 → 必须 PERSISTED=true
```
`verify-tools.mjs` / `verify-batch3.mjs` 直接调用 `defineTool` 产出的 `execute`，不经过 LLM，
所以不受 provider 限流影响 —— 它们补上了此前只有 lib 层覆盖、工具包装层从未被真实调用过的缺口。
`exit-test.mjs` 用两阶段（两个独立进程）复现「DSH 重启而 agent 没调 save/close」，是补丁 7 的回归用例。
`probe*.mjs`（`probe.mjs` / `probe3.mjs` / `probe3b.mjs` / `probe3c.mjs` / `probe3d.mjs` / `probe4.mjs`）是**开发期**诊断：
它们走 Python 侧只注册在 `OPS` 里、不注册成 Node 工具的 `probe` op，用 `java.lang.Class.getMethods()` 反射
真实的 Java API 形状（`{class}` / `{handle}` / `{handles:true}` / `{locals}` / `{tx}` / `{save}` / `{analysis}`），
不参与验收。**注意 `match` 是子串匹配，不是正则**；一轮反射约 40 秒，比「猜 API → 跑一轮 harness（5 分钟）→ 失败」快得多。
批次 3 后半的 `PcodeBlockBasic` 方法面**不是**用 probe 得到的：直接在真实会话里跑一次
`ghidra_run_script_inline`（反射 `getBasicBlocks()[0].getClass().getMethods()` + 试调 `getOutgoingEdges()`）
一次就拿到准确答案 —— 服务器已经在跑时，这是最快的反射通道。

这些脚本都会在结束时杀掉**真正的 JVM pid**（不只是 wrapper），不留残留锁。

## 生效条件
新增 bundle 需要 **重启 DSH** 才会挂载到运行中的 server（`dsh plugin add` 只改 profile 清单与磁盘，
不会让已运行的进程热加载；`web` profile 也没有 `patchReload` 键）。
重启后用 `ghidra_status` 自检，再对任意二进制跑一次 `ghidra_open`。
