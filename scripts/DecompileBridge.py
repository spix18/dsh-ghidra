# DecompileBridge.py — DSH ghidra 插件的常驻桥接服务器（运行环境见下方说明）
# 用法（headless）：
#   analyzeHeadless <projDir> <projName> -process <program> -noanalysis
#     -scriptPath <dir> -postScript DecompileBridge.py <portFile> <logFile>
# 协议：TCP 127.0.0.1 上的一行一个 JSON 请求/响应。
# ops: info | functions | decompile | strings | xrefs | ping | shutdown
#      segments | imports | exports | searchStrings | searchFunctions
#      calls | callGraph | readMemory | disassemble | variables | pcode
#      getComments | setComment | rename | labels | setPrototype | setVariables
#      createFunction | deleteFunction | save | tags
# 前 8 个是 v0.1.0 原有；中间 11 个是「批次 1 读侧补齐」，语义对照
# bethington/ghidra-mcp v7.0.0 的 list_segments / list_imports / list_exports /
# search_strings / search_functions / get_function_callers+callees /
# get_function_call_graph / read_memory+inspect_memory_content /
# disassemble_function+disassemble_bytes / get_function_variables / get_function_pcode。
# 最后 10 个是「批次 2 写侧」，语义对照 set_comment / get_comment+batch_get_comments /
# rename_symbol+rename_function / create_label+delete_label+get_function_labels /
# set_function_prototype+set_function_no_return / set_variables+rename_variables+set_variable_type /
# create_function+delete_function / save_program / 函数标签族。写侧每个 op 自带事务。
# 另加 9 个「批次 3 分析自动化」：runScriptInline / runScript /
# analyzers / analyzerConfig / runAnalysis / reanalyze / searchBytes / codeGaps / deadCode。
# 再 5 个「批次 3 后半」：functionContext（复合函数分析）/ searchInstructions /
# hash（函数级与程序级）/ compareFunctions / dataFlow。
# 上游每个端点都带 program（多程序服务器），本插件是单程序，故一律丢弃该参数。
# 运行环境是 **CPython 3.13 + JPype**（pyghidra 3.x 用 py -3.13 拉起），不是 Jython：
# exec() 是函数而非语句，可以直接 exec(compile(code, name, 'exec'), ns)。
# @category Analysis

import sys
import json
import re
import threading
import time

from java.io import BufferedReader, InputStreamReader, OutputStreamWriter, PrintWriter, FileWriter
from java.net import ServerSocket, InetAddress
from java.lang import String

from ghidra.app.decompiler import DecompInterface


def log(msg, logFile):
    if logFile:
        try:
            f = open(logFile, 'a')
            f.write(msg + '\n')
            f.close()
        except Exception:
            pass


def server_pid():
    # 真正的 JVM 进程号。pyghidra_launcher.py 会在拉起 Ghidra 之后自己退出（exit 0），
    # 所以 Node 侧 spawn 拿到的 pid 是那个短命 wrapper，不是服务器进程；必须由脚本自报。
    try:
        from java.lang.management import ManagementFactory
        return int(str(ManagementFactory.getRuntimeMXBean().getName()).split('@')[0])
    except Exception:
        try:
            import os
            return int(os.getpid())
        except Exception:
            return 0


def resolve_address(target):
    space = currentProgram.getAddressFactory().getDefaultAddressSpace()
    hexs = target[2:] if target.lower().startswith('0x') else target
    try:
        v = int(hexs, 16)
        return space.getAddress(v)
    except Exception:
        pass
    it = currentProgram.getSymbolTable().getSymbols(target)
    if it.hasNext():
        return it.next().getAddress()
    raise Exception('cannot resolve address/symbol: ' + target)


def op_info(obj):
    p = currentProgram
    blocks = []
    for b in p.getMemory().getBlocks():
        blocks.append({'name': str(b.getName()), 'start': str(b.getStart()), 'size': int(b.getSize())})
    eps = []
    it = p.getSymbolTable().getExternalEntryPointIterator()
    while it.hasNext():
        a = it.next()
        sym = p.getSymbolTable().getPrimarySymbol(a)
        eps.append({'name': str(sym.getName()) if sym is not None else '', 'address': str(a)})
    return {'program': str(p.getName()),
            'language': str(p.getLanguage().getLanguageID()),
            'compiler': str(p.getCompilerSpec().getCompilerSpecID()),
            'imageBase': str(p.getImageBase()),
            'minAddress': str(p.getMinAddress()),
            'maxAddress': str(p.getMaxAddress()),
            'functions': int(p.getFunctionManager().getFunctionCount()),
            'symbols': int(p.getSymbolTable().getNumSymbols()),
            'blocks': blocks,
            'entrypoints': eps}


def op_functions(obj):
    flt = obj.get('filter') or ''
    sort = obj.get('sort') or ''
    maxn = int(obj.get('max') or 200)
    rows = []
    it = currentProgram.getFunctionManager().getFunctions(True)
    while it.hasNext() and len(rows) < maxn:
        f = it.next()
        name = str(f.getName())
        if flt and flt not in name:
            continue
        rows.append({'name': name, 'address': str(f.getEntryPoint()),
                     'size': int(f.getBody().getNumAddresses()), 'thunk': bool(f.isThunk())})
    if sort == 'name':
        rows.sort(key=lambda r: r['name'].lower())
    return {'list': rows, 'total': len(rows)}


def op_decompile(obj):
    target = obj.get('target') or ''
    if not target:
        raise Exception('decompile: missing target')
    addr = resolve_address(target)
    fm = currentProgram.getFunctionManager()
    f = fm.getFunctionAt(addr)
    if f is None:
        f = fm.getFunctionContaining(addr)
    if f is None:
        raise Exception('decompile: no function at ' + target)
    di = DecompInterface()
    try:
        di.openProgram(currentProgram)
        res = di.decompileFunction(f, 60, monitor)
        if res is None or res.getDecompiledFunction() is None:
            raise Exception('decompile failed (program may need analysis): ' + str(f.getName()))
        code = res.getDecompiledFunction().getC()
        return {'function': str(f.getName()), 'address': str(f.getEntryPoint()),
                'signature': str(f.getSignature()), 'code': code}
    finally:
        di.dispose()


def op_strings(obj):
    flt = obj.get('filter') or ''
    minlen = int(obj.get('minLength') or 4)
    maxn = int(obj.get('max') or 200)
    rows = []
    it = currentProgram.getListing().getDefinedData(True)
    while it.hasNext() and len(rows) < maxn:
        d = it.next()
        dt = str(d.getDataType().getName()).lower()
        if 'string' not in dt and 'unicode' not in dt:
            continue
        v = d.getValue()
        if v is None:
            continue
        s = v if isinstance(v, str) else str(v)
        if len(s) < minlen:
            continue
        if flt and flt not in s:
            continue
        rows.append({'address': str(d.getAddress()), 'length': int(d.getLength()), 'value': s})
    return {'list': rows, 'total': len(rows)}


def op_xrefs(obj):
    target = obj.get('target') or ''
    direction = obj.get('direction') or 'to'
    maxn = int(obj.get('max') or 100)
    if not target:
        raise Exception('xrefs: missing target')
    addr = resolve_address(target)
    rm = currentProgram.getReferenceManager()
    # 注意：Ghidra 12 中 getReferencesFrom 返回数组，getReferencesTo 返回迭代器
    if direction == 'from':
        it = rm.getReferencesFrom(addr)
    else:
        it = rm.getReferencesTo(addr)
    refs = []
    if hasattr(it, 'hasNext'):
        while it.hasNext() and len(refs) < maxn:
            refs.append(it.next())
    else:
        refs = list(it)[:maxn]
    rows = []
    for r in refs:
        row = {'from': str(r.getFromAddress()), 'to': str(r.getToAddress()),
               'type': str(r.getReferenceType().getName())}
        sym = currentProgram.getSymbolTable().getSymbol(r)
        if sym is not None:
            row['symbol'] = str(sym.getName())
        rows.append(row)
    return {'address': str(addr), 'list': rows, 'total': len(rows)}


# ---- 批次 1：读侧补齐（只读，不改动 Ghidra 数据库）----


def _monitor():
    try:
        if monitor is not None:
            return monitor
    except Exception:
        pass
    try:
        from ghidra.util.task import TaskMonitor
        return TaskMonitor.DUMMY
    except Exception:
        return None


def _function_at(addr):
    fm = currentProgram.getFunctionManager()
    f = fm.getFunctionAt(addr)
    if f is None:
        f = fm.getFunctionContaining(addr)
    return f


def _func_row(f):
    return {'name': str(f.getName()), 'address': str(f.getEntryPoint()),
            'size': int(f.getBody().getNumAddresses())}


def _take(coll, maxn):
    # Ghidra 12 里 Function.getCalledFunctions/getCallingFunctions 返回 java.util.Set，
    # 而 ReferenceManager.getReferencesTo 返回迭代器——统一成列表，两种都吃。
    rows = []
    if coll is None or maxn <= 0:
        return rows
    try:
        it = coll.iterator()
    except Exception:
        it = coll
    try:
        while it.hasNext() and len(rows) < maxn:
            rows.append(it.next())
        return rows
    except Exception:
        pass
    for x in coll:
        if len(rows) >= maxn:
            break
        rows.append(x)
    return rows


def op_segments(obj):
    rows = []
    for b in currentProgram.getMemory().getBlocks():
        try:
            rwx = ('r' if b.isRead() else '-') + ('w' if b.isWrite() else '-') + ('x' if b.isExecute() else '-')
        except Exception:
            rwx = ''
        cmt = b.getComment()
        rows.append({'name': str(b.getName()),
                     'start': str(b.getStart()),
                     'end': str(b.getEnd()),
                     'size': int(b.getSize()),
                     'rwx': rwx,
                     'initialized': bool(b.isInitialized()),
                     'type': str(b.getType()),
                     'volatile': bool(b.isVolatile()),
                     'comment': str(cmt) if cmt else ''})
    return {'list': rows, 'total': len(rows)}


def op_imports(obj):
    flt = (obj.get('filter') or '').lower()
    maxn = int(obj.get('max') or 200)
    st = currentProgram.getSymbolTable()
    it = None
    prefiltered = False
    getter = getattr(st, 'getExternalSymbols', None)
    if getter is not None:
        try:
            it = getter()
            prefiltered = True
        except Exception:
            it = None
    if it is None:
        it = st.getSymbolIterator()
    rows = []
    while it.hasNext() and len(rows) < maxn:
        s = it.next()
        if not prefiltered and not s.isExternal():
            continue
        name = str(s.getName())
        if flt and flt not in name.lower():
            continue
        row = {'name': name, 'address': str(s.getAddress())}
        try:
            row['library'] = str(s.getParentNamespace().getName())
        except Exception:
            pass
        rows.append(row)
    return {'list': rows, 'total': len(rows)}


def op_exports(obj):
    flt = (obj.get('filter') or '').lower()
    maxn = int(obj.get('max') or 200)
    st = currentProgram.getSymbolTable()
    rows = []
    seen = {}
    it = st.getExternalEntryPointIterator()
    while it.hasNext() and len(rows) < maxn:
        a = it.next()
        sym = st.getPrimarySymbol(a)
        name = str(sym.getName()) if sym is not None else ''
        if flt and flt not in name.lower():
            continue
        key = str(a)
        if key in seen:
            continue
        seen[key] = True
        rows.append({'name': name, 'address': key})
    return {'list': rows, 'total': len(rows)}


def _string_data_rows(minlen, cap=200000):
    it = currentProgram.getListing().getDefinedData(True)
    n = 0
    while it.hasNext() and n < cap:
        n += 1
        d = it.next()
        dt = str(d.getDataType().getName()).lower()
        if 'string' not in dt and 'unicode' not in dt:
            continue
        v = d.getValue()
        if v is None:
            continue
        s = v if isinstance(v, str) else str(v)
        if len(s) < minlen:
            continue
        yield d, s


def _compile_pattern(pattern, caseSensitive):
    if not pattern:
        return None
    flags = 0 if caseSensitive else re.IGNORECASE
    try:
        return re.compile(pattern, flags)
    except Exception as e:
        raise Exception('bad regex: ' + str(e))


def op_search_strings(obj):
    rx = _compile_pattern(obj.get('pattern') or '', bool(obj.get('caseSensitive')))
    minlen = int(obj.get('minLength') or 4)
    offset = int(obj.get('offset') or 0)
    limit = int(obj.get('limit') or 100)
    rows = []
    matched = 0
    truncated = False
    for d, s in _string_data_rows(minlen):
        if rx is not None and rx.search(s) is None:
            continue
        matched += 1
        if matched <= offset:
            continue
        if len(rows) >= limit:
            truncated = True
            break
        rows.append({'address': str(d.getAddress()), 'length': int(d.getLength()), 'value': s})
    return {'list': rows, 'total': len(rows), 'matched': matched,
            'offset': offset, 'truncated': truncated}


def op_search_functions(obj):
    rx = _compile_pattern(obj.get('pattern') or '', bool(obj.get('caseSensitive')))
    offset = int(obj.get('offset') or 0)
    limit = int(obj.get('limit') or 100)
    rows = []
    matched = 0
    truncated = False
    it = currentProgram.getFunctionManager().getFunctions(True)
    while it.hasNext():
        f = it.next()
        name = str(f.getName())
        if rx is not None and rx.search(name) is None:
            continue
        matched += 1
        if matched <= offset:
            continue
        if len(rows) >= limit:
            truncated = True
            break
        rows.append(_func_row(f))
    return {'list': rows, 'total': len(rows), 'matched': matched,
            'offset': offset, 'truncated': truncated}


def op_calls(obj):
    target = obj.get('target') or ''
    direction = obj.get('direction') or 'both'
    maxn = int(obj.get('max') or 100)
    if not target:
        raise Exception('calls: missing target')
    addr = resolve_address(target)
    f = _function_at(addr)
    if f is None:
        raise Exception('calls: no function at ' + target)
    out = {'function': str(f.getName()), 'address': str(f.getEntryPoint()),
           'signature': str(f.getSignature())}
    if direction in ('callees', 'both'):
        rows = [_func_row(f2) for f2 in _take(f.getCalledFunctions(_monitor()), maxn)]
        out['callees'] = {'list': rows, 'total': len(rows)}
    if direction in ('callers', 'both'):
        rows = []
        seen = {}
        for f2 in _take(f.getCallingFunctions(_monitor()), maxn):
            r = _func_row(f2)
            seen[r['address']] = True
            rows.append(r)
        if not rows:
            # 回退：有些调用没被 Ghidra 关联成函数关系，直接扫指向入口的 call 引用
            refs = _take(currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint()), 2000)
            for ref in refs:
                if len(rows) >= maxn:
                    break
                try:
                    if not ref.getReferenceType().isCall():
                        continue
                except Exception:
                    pass
                cf = _function_at(ref.getFromAddress())
                if cf is None:
                    continue
                key = str(cf.getEntryPoint())
                if key in seen:
                    continue
                seen[key] = True
                rows.append(_func_row(cf))
        out['callers'] = {'list': rows, 'total': len(rows)}
    return out


def op_call_graph(obj):
    target = obj.get('target') or ''
    direction = obj.get('direction') or 'callees'
    depth = int(obj.get('depth') or 2)
    maxnodes = int(obj.get('maxNodes') or 150)
    if not target:
        raise Exception('callGraph: missing target')
    if depth < 1:
        depth = 1
    addr = resolve_address(target)
    root = _function_at(addr)
    if root is None:
        raise Exception('callGraph: no function at ' + target)
    nodes = []
    edges = []
    seen = {}
    frontier = [(root, 0)]
    seen[str(root.getEntryPoint())] = True
    nodes.append({'name': str(root.getName()), 'address': str(root.getEntryPoint()), 'depth': 0})
    truncated = False
    while frontier:
        f, d = frontier.pop(0)
        if d >= depth:
            continue
        if direction == 'callers':
            nbrs = f.getCallingFunctions(_monitor())
        else:
            nbrs = f.getCalledFunctions(_monitor())
        for nf in _take(nbrs, 2000):
            key = str(nf.getEntryPoint())
            edges.append({'from': str(f.getEntryPoint()), 'to': key})
            if key in seen:
                continue
            if len(nodes) >= maxnodes:
                truncated = True
                continue
            seen[key] = True
            nodes.append({'name': str(nf.getName()), 'address': key, 'depth': d + 1})
            frontier.append((nf, d + 1))
    return {'root': {'name': str(root.getName()), 'address': str(root.getEntryPoint())},
            'direction': direction, 'depth': depth,
            'nodes': nodes, 'edges': edges, 'total': len(nodes), 'truncated': truncated}


def _new_byte_array(n):
    try:
        import jpype
        return jpype.JArray(jpype.JByte)(n)
    except Exception:
        pass
    try:
        from java.lang import Byte
        from java.lang.reflect import Array
        return Array.newInstance(Byte.TYPE, n)
    except Exception:
        return bytearray(n)


def op_read_memory(obj):
    address = obj.get('address') or obj.get('target') or ''
    length = int(obj.get('length') or 64)
    if length < 1:
        length = 1
    if length > 4096:
        length = 4096
    if not address:
        raise Exception('readMemory: missing address')
    addr = resolve_address(address)
    mem = currentProgram.getMemory()
    buf = _new_byte_array(length)
    data = []
    readError = ''
    try:
        n = int(mem.getBytes(addr, buf))
        for i in range(n):
            data.append(int(buf[i]) & 0xff)
    except Exception as e:
        # 未初始化/越界时逐字节回退，能读多少读多少
        readError = str(e)
        for i in range(length):
            try:
                data.append(int(mem.getByte(addr.add(i))) & 0xff)
            except Exception:
                break
    rows = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        rows.append({'address': str(addr.add(off)),
                     'hex': ' '.join('%02x' % b for b in chunk),
                     'ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)})
    out = {'address': str(addr), 'length': len(data), 'rows': rows}
    if readError:
        out['note'] = '部分读取（' + readError + '）'
    return out


def op_disassemble(obj):
    target = obj.get('target') or ''
    count = int(obj.get('count') or 0)
    if count <= 0:
        count = 500
    if count > 2000:
        count = 2000
    if not target:
        raise Exception('disassemble: missing target')
    addr = resolve_address(target)
    listing = currentProgram.getListing()
    f = _function_at(addr)
    if f is not None:
        it = listing.getInstructions(f.getBody(), True)
    else:
        it = listing.getInstructions(addr, True)
    rows = []
    while it.hasNext() and len(rows) < count:
        insn = it.next()
        rows.append({'address': str(insn.getAddress()), 'text': str(insn)})
    out = {'list': rows, 'total': len(rows),
           'scope': (str(f.getName()) + ' 函数体') if f is not None else ('自 ' + str(addr) + ' 起 ' + str(count) + ' 条')}
    if f is not None:
        out['function'] = str(f.getName())
        out['address'] = str(f.getEntryPoint())
        out['signature'] = str(f.getSignature())
    return out


def op_variables(obj):
    target = obj.get('target') or ''
    if not target:
        raise Exception('variables: missing target')
    addr = resolve_address(target)
    f = _function_at(addr)
    if f is None:
        raise Exception('variables: no function at ' + target)

    def row(v):
        d = {'name': str(v.getName())}
        try:
            d['type'] = str(v.getDataType().getName())
        except Exception:
            d['type'] = ''
        try:
            d['storage'] = str(v.getVariableStorage())
        except Exception:
            d['storage'] = ''
        try:
            d['length'] = int(v.getLength())
        except Exception:
            d['length'] = 0
        return d

    params = [row(p) for p in f.getParameters()]
    locals_ = [row(v) for v in f.getLocalVariables()]
    return {'function': str(f.getName()), 'address': str(f.getEntryPoint()),
            'signature': str(f.getSignature()),
            'parameters': params, 'locals': locals_,
            'total': len(params) + len(locals_)}


def op_pcode(obj):
    target = obj.get('target') or ''
    mode = obj.get('mode') or 'listing'
    limit = int(obj.get('limit') or 60)
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500
    if not target:
        raise Exception('pcode: missing target')
    addr = resolve_address(target)
    f = _function_at(addr)
    if f is None:
        raise Exception('pcode: no function at ' + target)
    head = {'function': str(f.getName()), 'address': str(f.getEntryPoint()), 'mode': mode}
    if mode in ('high', 'decompiled'):
        di = DecompInterface()
        try:
            di.openProgram(currentProgram)
            res = di.decompileFunction(f, 60, _monitor())
            hf = res.getHighFunction() if res is not None else None
            if hf is None:
                raise Exception('pcode: decompiler produced no HighFunction')
            rows = []
            it = hf.getPcodeOps()
            while it.hasNext() and len(rows) < limit:
                o = it.next()
                rows.append({'address': str(o.getSeqnum().getTarget()), 'text': str(o)})
            head['list'] = rows
            head['total'] = len(rows)
            return head
        finally:
            di.dispose()
    rows = []
    total = 0
    it = currentProgram.getListing().getInstructions(f.getBody(), True)
    while it.hasNext() and len(rows) < limit:
        insn = it.next()
        ops = []
        try:
            for o in insn.getPcode():
                ops.append(str(o))
        except Exception:
            pass
        total += len(ops)
        if ops:
            rows.append({'address': str(insn.getAddress()), 'instruction': str(insn), 'pcode': ops})
    head['list'] = rows
    head['total'] = total
    return head


# ---- 批次 2：写侧（会改动 Ghidra 数据库）----
# 语义对照 bethington/ghidra-mcp v7.0.0 的 set_comment / get_comment+batch_get_comments /
# rename_symbol+rename_function / create_label+delete_label+get_function_labels /
# set_function_prototype+set_function_no_return / set_variables /
# create_function+delete_function / save_program / 函数标签族。
# 每个写 op 都自带事务（startTransaction/endTransaction），改完需 op_save 才写回项目。

class _Tx(object):
    def __init__(self, label):
        self.label = label
        self.tid = None

    def __enter__(self):
        self.tid = currentProgram.startTransaction(self.label)
        return self

    def __exit__(self, et, ev, tb):
        # 必须**永远提交**（True），绝不 abort。headless/PyGhidra 在脚本外层持有事务，
        # 我们的每个写事务都是它的子事务；对子事务调 endTransaction(tid, False) 会让
        # Ghidra 丢弃整个外层事务——症状是「改动在内存里可见、isChanged()=true、
        # headless 报 Save succeeded，但项目里什么都没写进去」。
        # 实测：create_function 坏地址、set_prototype 不可解析签名这两个抛异常的路径，
        # 曾把一整轮 50+ 处写改动静默清空（原来的 except: pass 还把这个失败吞掉了）。
        try:
            currentProgram.endTransaction(self.tid, True)
        except Exception as e:
            try:
                log('endTransaction(%s, True) failed: %s' % (self.tid, e))
            except Exception:
                pass
        return False


def _tx(label):
    return _Tx(label)


_COMMENT_TYPES = {'plate': 'PLATE', 'pre': 'PRE', 'eol': 'EOL', 'post': 'POST',
                  'repeatable': 'REPEATABLE', 'decompiler': 'PRE', 'disassembly': 'EOL'}


def _comment_type(name):
    from ghidra.program.model.listing import CommentType
    key = str(name or 'plate').strip().lower()
    const = _COMMENT_TYPES.get(key)
    if const is None:
        raise Exception('unknown comment type: ' + str(name) + ' (plate|pre|eol|post|repeatable)')
    try:
        return CommentType.valueOf(const)
    except Exception:
        return getattr(CommentType, const)


def _addr_list(obj):
    got = obj.get('addresses')
    if got is None:
        got = obj.get('address') or obj.get('target')
    if got is None:
        return []
    if isinstance(got, list):
        return [str(x) for x in got]
    return [str(got)]


def op_get_comments(obj):
    types = ['plate', 'pre', 'eol', 'post', 'repeatable']
    only = bool(obj.get('onlyWithComments'))
    rows = []
    for a in _addr_list(obj):
        addr = resolve_address(a)
        row = {'address': str(addr)}
        for t in types:
            try:
                v = currentProgram.getListing().getComment(_comment_type(t), addr)
            except Exception:
                v = None
            if v:
                row[t] = str(v)
        if only and len(row) == 1:
            continue
        rows.append(row)
    return {'list': rows, 'total': len(rows)}


def op_set_comment(obj):
    addrs = _addr_list(obj)
    if not addrs:
        raise Exception('setComment: missing address')
    pairs = []
    bag = obj.get('comments')
    if isinstance(bag, dict):
        for k in bag.keys():
            pairs.append((str(k), bag[k]))
    if obj.get('comment') is not None:
        pairs.append((obj.get('type') or 'plate', obj.get('comment')))
    for k in ('plate', 'pre', 'eol', 'post', 'repeatable'):
        if k in obj:
            pairs.append((k, obj.get(k)))
    if not pairs:
        raise Exception('setComment: nothing to set (give comment+type, comments{}, or plate/pre/eol/post/repeatable)')
    listing = currentProgram.getListing()
    applied = []
    with _tx('dsh setComment'):
        for a in addrs:
            addr = resolve_address(a)
            for tn, text in pairs:
                ct = _comment_type(tn)
                listing.setComment(addr, ct, '' if text is None else str(text))
                applied.append({'address': str(addr), 'type': str(tn), 'empty': not text})
    return {'applied': applied, 'total': len(applied),
            'note': '空字符串会清除该类型注释；改动需 ghidra_save 落盘'}


def op_rename(obj):
    target = obj.get('target') or obj.get('address') or ''
    new_name = obj.get('newName') or obj.get('name') or ''
    kind = str(obj.get('kind') or 'auto').lower()
    if not target:
        raise Exception('rename: missing target')
    if not new_name:
        raise Exception('rename: missing newName')
    from ghidra.program.model.symbol import SourceType
    st = SourceType.USER_DEFINED
    fm = currentProgram.getFunctionManager()
    symtab = currentProgram.getSymbolTable()
    addr = resolve_address(str(target))
    old = ''
    done = kind
    with _tx('dsh rename'):
        f = fm.getFunctionAt(addr)
        if kind in ('auto', 'function') and f is not None:
            old = str(f.getName())
            f.setName(str(new_name), st)
            done = 'function'
        elif kind in ('variable',):
            raise Exception('rename: variable rename needs ghidra_set_variables (newType/batch)')
        elif kind in ('auto', 'label', 'symbol', 'data'):
            syms = [s for s in _take(symtab.getSymbols(addr), 50)]
            s0 = symtab.getPrimarySymbol(addr)
            if s0 is None and syms:
                s0 = syms[0]
            if s0 is not None:
                old = str(s0.getName())
                s0.setName(str(new_name), st)
                done = 'symbol'
            else:
                symtab.createLabel(addr, str(new_name), st)
                done = 'label'
        else:
            raise Exception('rename: no ' + kind + ' target at ' + str(target))
    return {'address': str(addr), 'kind': done, 'oldName': old, 'newName': str(new_name)}


def _sym_row(s):
    row = {'name': str(s.getName()), 'address': str(s.getAddress())}
    try:
        row['type'] = str(s.getSymbolType())
    except Exception:
        row['type'] = ''
    try:
        row['primary'] = bool(s.isPrimary())
    except Exception:
        row['primary'] = False
    try:
        row['source'] = str(s.getSource())
    except Exception:
        row['source'] = ''
    return row


def op_labels(obj):
    action = str(obj.get('action') or 'list').lower()
    from ghidra.program.model.symbol import SourceType
    st = SourceType.USER_DEFINED
    symtab = currentProgram.getSymbolTable()
    if action == 'list':
        target = obj.get('target') or obj.get('address') or ''
        maxn = int(obj.get('max') or 200)
        rows = []
        if target:
            addr = resolve_address(str(target))
            f = _function_at(addr)
            in_func = f is not None and str(f.getEntryPoint()) == str(addr)
            if in_func:
                it = None
                try:
                    # Ghidra 12 只有 getSymbols(AddressSetView, SymbolType, boolean) 这一个重载，
                    # 两参版本不存在；SymbolType 传 None 表示不过滤类型。失败则退回全表过滤。
                    it = symtab.getSymbols(f.getBody(), None, True)
                except Exception:
                    it = None
                if it is None:
                    body = f.getBody()
                    it = []
                    for s in _take(symtab.getAllSymbols(True), 200000):
                        try:
                            if body.contains(s.getAddress()):
                                it.append(s)
                        except Exception:
                            pass
            else:
                it = symtab.getSymbols(addr)
            for s in _take(it, maxn):
                rows.append(_sym_row(s))
        else:
            for s in _take(symtab.getAllSymbols(True), maxn):
                rows.append(_sym_row(s))
        return {'list': rows, 'total': len(rows)}
    if action == 'create':
        address = obj.get('address') or obj.get('target') or ''
        if not address:
            raise Exception('labels/create: address required')
        names = obj.get('names')
        if names is None:
            names = [obj.get('name')] if obj.get('name') else []
        if not isinstance(names, list):
            names = [names]
        names = [str(n) for n in names if n]
        if not names:
            raise Exception('labels/create: name or names[] required')
        addr = resolve_address(str(address))
        made = []
        with _tx('dsh createLabel'):
            for n in names:
                made.append(_sym_row(symtab.createLabel(addr, n, st)))
        return {'address': str(addr), 'list': made, 'total': len(made)}
    if action == 'delete':
        address = obj.get('address') or obj.get('target') or ''
        if not address:
            raise Exception('labels/delete: address required')
        addr = resolve_address(str(address))
        want = obj.get('name')
        removed = []
        with _tx('dsh deleteLabel'):
            for s in _take(symtab.getSymbols(addr), 200):
                if want and str(s.getName()) != str(want):
                    continue
                removed.append(_sym_row(s))
                try:
                    symtab.removeSymbolSpecial(s)
                except Exception:
                    s.delete()
        return {'address': str(addr), 'list': removed, 'total': len(removed)}
    raise Exception('labels: unknown action ' + str(action) + ' (list|create|delete)')


def _resolve_type(dtm, name):
    s = str(name).strip()
    stars = 0
    while s.endswith('*'):
        stars += 1
        s = s[:-1].strip()
    t = None
    for cand in (s, '/' + s):
        try:
            t = dtm.getDataType(cand)
        except Exception:
            t = None
        if t is not None:
            break
    if t is None:
        return None
    for _i in range(stars):
        t = dtm.getPointer(t)
    return t


def _manual_signature(f, text):
    """手写兜底解析器：能吃 "<ret> [__conv] [name](<type> [pname], ...)"。
    官方解析器都失败时用它，保证 setPrototype 在最坏情况下仍可用。"""
    from ghidra.program.model.data import FunctionDefinitionDataType
    from ghidra.program.model.listing import ParameterImpl
    s = str(text).strip()
    lp = s.find('(')
    rp = s.rfind(')')
    if lp < 0 or rp < lp:
        raise Exception('not a C signature (no parentheses): ' + s)
    head = s[:lp].strip()
    argstr = s[lp + 1:rp].strip()
    cc = ''
    keep = []
    for t in head.split():
        if t.startswith('__'):
            cc = t
        else:
            keep.append(t)
    fname = ''
    ret = ''
    if keep:
        fname = keep[-1]
        ret = ' '.join(keep[:-1]).strip()
    if not ret:
        ret = 'void'
    dtm = currentProgram.getDataTypeManager()
    rdt = _resolve_type(dtm, ret)
    if rdt is None:
        raise Exception('unknown return type: ' + ret)
    fd = FunctionDefinitionDataType(fname or str(f.getName()))
    fd.setReturnType(rdt)
    if cc:
        try:
            fd.setCallingConvention(cc)
        except Exception:
            pass
    args = []
    if argstr and argstr != 'void':
        for part in argstr.split(','):
            p = part.strip()
            if not p:
                continue
            toks = p.split()
            pname = ''
            if len(toks) >= 2 and not toks[-1].endswith('*'):
                pname = toks[-1]
                toks = toks[:-1]
            ptype = ' '.join(toks).strip() or 'undefined'
            pdt = _resolve_type(dtm, ptype)
            if pdt is None:
                raise Exception('unknown parameter type: ' + ptype)
            args.append(ParameterImpl(pname or ('p' + str(len(args))), pdt, currentProgram))
    if args:
        fd.setArguments(args)
    return fd


def _parse_signature(f, text):
    """把 C 风格签名解析成 FunctionSignature。返回 (sig, how)；三条路全失败才抛异常。"""
    errs = []
    try:
        # 真实包名是 ghidra.app.util.cparser.C（末尾多一层 C），别写成 ghidra.app.util.cparser
        from ghidra.app.util.cparser.C import CParserUtils
        sig = CParserUtils.parseSignature(None, currentProgram, text, True)
        if sig is not None:
            return sig, 'CParserUtils'
        errs.append('CParserUtils returned None')
    except Exception as e:
        errs.append('CParserUtils: ' + str(e))
    try:
        # 注意：parse() 的第一个参数必须是 FunctionSignature（传 Function 会报 No matching overloads）
        from ghidra.app.util.parser import FunctionSignatureParser
        sig = FunctionSignatureParser(currentProgram.getDataTypeManager(), None).parse(f.getSignature(), text)
        if sig is not None:
            return sig, 'FunctionSignatureParser'
        errs.append('FunctionSignatureParser returned None')
    except Exception as e:
        errs.append('FunctionSignatureParser: ' + str(e))
    try:
        return _manual_signature(f, text), 'manual'
    except Exception as e:
        errs.append('manual: ' + str(e))
    raise Exception('cannot parse prototype "' + str(text) + '" — ' + ' | '.join(errs))


def op_set_prototype(obj):
    target = obj.get('target') or obj.get('function') or obj.get('address') or ''
    if not target:
        raise Exception('setPrototype: missing target')
    proto = obj.get('prototype')
    cc = obj.get('callingConvention')
    no_return = obj.get('noReturn')
    if not proto and not cc and no_return is None:
        raise Exception('setPrototype: give prototype and/or callingConvention and/or noReturn')
    from ghidra.program.model.symbol import SourceType
    addr = resolve_address(str(target))
    f = _function_at(addr)
    if f is None:
        raise Exception('setPrototype: no function at ' + str(target))
    out = {'function': str(f.getName()), 'address': str(f.getEntryPoint())}
    with _tx('dsh setPrototype'):
        if proto:
            sig, how = _parse_signature(f, str(proto))
            out['parsedBy'] = how
            from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
            cmd = ApplyFunctionSignatureCmd(f.getEntryPoint(), sig, SourceType.USER_DEFINED)
            if not cmd.applyTo(currentProgram, _monitor()):
                raise Exception('setPrototype: ApplyFunctionSignatureCmd failed: ' + str(cmd.getStatusMsg()))
        if cc:
            f.setCallingConvention(str(cc))
        if no_return is not None:
            f.setNoReturn(bool(no_return))
        out['signature'] = str(f.getSignature())
        try:
            out['callingConvention'] = str(f.getCallingConventionName())
        except Exception:
            out['callingConvention'] = ''
        try:
            out['noReturn'] = bool(f.hasNoReturn())
        except Exception:
            out['noReturn'] = None
    return out


def _find_db_var(f, name):
    """按名字在 DB 变量里找。注意 Function.getParameter(String) 在 Ghidra 12 不存在，只能遍历。"""
    for v in f.getParameters():
        if str(v.getName()) == name:
            return v
    for v in f.getLocalVariables():
        if str(v.getName()) == name:
            return v
    return None


def _apply_variable(f, name, new_name, dt, st):
    """优先走反编译器（HighFunctionDBUtil 会同步 DB），失败退回直接改 DB 变量。"""
    rename_to = str(new_name) if new_name else None
    errs = []
    try:
        from ghidra.app.decompiler import DecompInterface, HighFunctionDBUtil
        di = DecompInterface()
        try:
            di.openProgram(currentProgram)
            res = di.decompileFunction(f, 60, _monitor())
            hf = res.getHighFunction() if res is not None else None
            if hf is None:
                errs.append('decompiler: no HighFunction')
            else:
                sym = None
                avail = []
                for s in _take(hf.getLocalSymbolMap().getSymbols(), 4000):
                    nm = str(s.getName())
                    avail.append(nm)
                    if nm == name:
                        sym = s
                        break
                if sym is None:
                    errs.append('decompiler: no symbol named ' + name +
                                ' (saw: ' + ', '.join(avail[:25]) + ')')
                else:
                    HighFunctionDBUtil.updateDBVariable(
                        sym, rename_to if rename_to else str(sym.getName()), dt, st)
                    return 'decompiler'
        finally:
            di.dispose()
    except Exception as e:
        errs.append('decompiler: ' + str(e))
    v = _find_db_var(f, name)
    if v is None:
        raise Exception('variable not found: ' + str(name) + ' (' + ' | '.join(errs) + ')')
    try:
        if rename_to:
            v.setName(rename_to, st)
        if dt is not None:
            v.setDataType(dt, st)
    except Exception as e:
        errs.append('database: ' + str(e))
        raise Exception('variable update failed: ' + str(name) + ' (' + ' | '.join(errs) + ')')
    return 'database'


def op_set_variables(obj):
    target = obj.get('target') or obj.get('function') or obj.get('address') or ''
    items = obj.get('variables') or obj.get('renames') or []
    if not target:
        raise Exception('setVariables: missing target')
    if not isinstance(items, list) or not items:
        raise Exception('setVariables: variables[] required, e.g. [{"name":"local_8","newName":"count","newType":"int"}]')
    from ghidra.program.model.symbol import SourceType
    st = SourceType.USER_DEFINED
    dtm = currentProgram.getDataTypeManager()
    addr = resolve_address(str(target))
    f = _function_at(addr)
    if f is None:
        raise Exception('setVariables: no function at ' + str(target))
    applied = []
    failed = []
    with _tx('dsh setVariables'):
        for it in items:
            if not isinstance(it, dict):
                failed.append({'name': '', 'error': 'not an object: ' + str(it)})
                continue
            name = str(it.get('name') or it.get('oldName') or '')
            new_name = it.get('newName') or it.get('rename')
            new_type = it.get('newType') or it.get('type')
            if not name:
                failed.append({'name': '', 'error': 'missing name'})
                continue
            if not new_name and not new_type:
                failed.append({'name': name, 'error': 'give newName and/or newType'})
                continue
            dt = None
            if new_type:
                dt = _resolve_type(dtm, new_type)
                if dt is None:
                    failed.append({'name': name, 'error': 'unknown data type: ' + str(new_type)})
                    continue
            try:
                where = _apply_variable(f, name, new_name, dt, st)
                row = {'name': name, 'via': where}
                if new_name:
                    row['newName'] = str(new_name)
                if dt is not None:
                    row['newType'] = str(dt.getName())
                applied.append(row)
            except Exception as e:
                failed.append({'name': name, 'error': str(e)})
        out = {'function': str(f.getName()), 'address': str(f.getEntryPoint()),
               'signature': str(f.getSignature()),
               'applied': applied, 'failed': failed, 'total': len(applied)}
    return out


def op_create_function(obj):
    address = obj.get('address') or obj.get('target') or ''
    if not address:
        raise Exception('createFunction: missing address')
    name = obj.get('name')
    disasm_first = obj.get('disassembleFirst')
    from ghidra.program.model.symbol import SourceType
    addr = resolve_address(str(address))
    fm = currentProgram.getFunctionManager()
    out = {'address': str(addr)}
    with _tx('dsh createFunction'):
        if fm.getFunctionAt(addr) is None and disasm_first is not False:
            from ghidra.app.cmd.disassemble import DisassembleCommand
            dcmd = DisassembleCommand(addr, None, True)
            dcmd.applyTo(currentProgram, _monitor())
            out['disassembled'] = True
        from ghidra.app.cmd.function import CreateFunctionCmd
        cmd = CreateFunctionCmd(addr)
        out['created'] = bool(cmd.applyTo(currentProgram, _monitor()))
        out['status'] = str(cmd.getStatusMsg())
        f = fm.getFunctionAt(addr)
        if f is None:
            f = fm.getFunctionContaining(addr)
        if f is None:
            raise Exception('createFunction failed at ' + str(addr) + ': ' + str(cmd.getStatusMsg()))
        if name:
            f.setName(str(name), SourceType.USER_DEFINED)
        out['function'] = str(f.getName())
        out['entry'] = str(f.getEntryPoint())
        out['signature'] = str(f.getSignature())
    return out


def op_delete_function(obj):
    address = obj.get('address') or obj.get('target') or ''
    if not address:
        raise Exception('deleteFunction: missing address')
    addr = resolve_address(str(address))
    f = _function_at(addr)
    if f is None:
        raise Exception('deleteFunction: no function at ' + str(address))
    entry = f.getEntryPoint()
    name = str(f.getName())
    from ghidra.app.cmd.function import DeleteFunctionCmd
    with _tx('dsh deleteFunction'):
        cmd = DeleteFunctionCmd(entry)
        # DeleteFunctionCmd.applyTo 不接受 monitor 参数（只有 applyTo(Program) / applyTo(DomainObject)）
        ok = bool(cmd.applyTo(currentProgram))
    if not ok:
        raise Exception('deleteFunction failed: ' + str(cmd.getStatusMsg()))
    return {'deleted': True, 'name': name, 'address': str(entry)}


def op_save(obj):
    """如实报告落盘状态。headless 在程序外层持有事务，进程内 df.save() 拿不到锁；
    真正的落盘时机是服务器【优雅关闭】——脚本 return 后由 headless 收尾保存。
    Node 侧的 ghidra_save 会用「优雅停止 + 重新打开」完成一次真正的 flush。"""
    df = currentProgram.getDomainFile()
    if df is None:
        raise Exception('save: program has no project file (opened standalone?)')
    try:
        changed = bool(currentProgram.isChanged())
    except Exception:
        changed = True
    out = {'program': str(currentProgram.getName()), 'path': str(df.getPathname()),
           'changed': changed, 'saved': False}
    if not changed:
        out['note'] = '没有未保存的改动'
        return out
    try:
        df.save(_monitor())
        out['saved'] = True
        out['note'] = '已直接写盘'
        return out
    except Exception as e:
        out['error'] = str(e)
        out['pending'] = True
        out['note'] = ('headless 在程序外层持有事务，进程内无法直接写盘；'
                       '改动会在服务器优雅关闭（ghidra_close）时由 headless 落盘。')
        return out


def _tag_mgr():
    return currentProgram.getFunctionManager().getFunctionTagManager()


def _func_tag_names(f):
    names = []
    try:
        for t in _take(f.getTags(), 200):
            names.append(str(t.getName()))
    except Exception:
        pass
    return names


def op_tags(obj):
    action = str(obj.get('action') or 'list').lower()
    tm = _tag_mgr()
    fm = currentProgram.getFunctionManager()
    if action == 'list':
        rows = []
        for t in _take(tm.getAllFunctionTags(), 1000):
            row = {'name': str(t.getName())}
            try:
                row['comment'] = str(t.getComment())
            except Exception:
                row['comment'] = ''
            try:
                row['count'] = int(tm.getUseCount(t))
            except Exception:
                row['count'] = None
            rows.append(row)
        return {'list': rows, 'total': len(rows)}
    if action == 'search':
        tag = str(obj.get('tag') or obj.get('name') or '')
        if not tag:
            raise Exception('tags/search: tag required')
        maxn = int(obj.get('max') or 200)
        rows = []
        # Ghidra 12 的 FunctionTagManager 没有 getFunctions(tag)；只能遍历函数查标签集合
        for f in _take(fm.getFunctions(True), 200000):
            if tag in _func_tag_names(f):
                rows.append(_func_row(f))
                if len(rows) >= maxn:
                    break
        return {'tag': tag, 'list': rows, 'total': len(rows)}
    if action == 'create':
        name = str(obj.get('tag') or obj.get('name') or '')
        if not name:
            raise Exception('tags/create: name required')
        with _tx('dsh createTag'):
            t = tm.createFunctionTag(name, str(obj.get('comment') or ''))
        return {'created': True, 'name': str(t.getName())}
    if action == 'delete':
        name = str(obj.get('tag') or obj.get('name') or '')
        if not name:
            raise Exception('tags/delete: name required')
        # 没有 FunctionTagManager.removeFunctionTag —— 删除必须落在 FunctionTag 对象上
        t = tm.getFunctionTag(name)
        if t is None:
            raise Exception('tags/delete: no such tag: ' + name)
        with _tx('dsh deleteTag'):
            t.delete()
        return {'deleted': True, 'name': name}
    if action in ('attach', 'detach'):
        target = obj.get('target') or obj.get('function') or obj.get('address') or ''
        tags = obj.get('tags') or ([obj.get('tag')] if obj.get('tag') else [])
        if not isinstance(tags, list):
            tags = [tags]
        tags = [str(t) for t in tags if t]
        if not target or not tags:
            raise Exception('tags/' + action + ': target + tag(s) required')
        addr = resolve_address(str(target))
        f = _function_at(addr)
        if f is None:
            raise Exception('tags/' + action + ': no function at ' + str(target))
        done = []
        with _tx('dsh ' + action + 'Tag'):
            for t in tags:
                if action == 'attach':
                    # 标签对象不存在时先建，addTag 只负责挂到函数上
                    if tm.getFunctionTag(t) is None:
                        tm.createFunctionTag(t, '')
                    f.addTag(t)
                else:
                    f.removeTag(t)
                done.append(t)
        return {'function': str(f.getName()), 'address': str(f.getEntryPoint()),
                action: done, 'total': len(done), 'tags': _func_tag_names(f)}
    if action == 'get':
        target = obj.get('target') or obj.get('function') or obj.get('address') or ''
        if not target:
            raise Exception('tags/get: target required')
        addr = resolve_address(str(target))
        f = _function_at(addr)
        if f is None:
            raise Exception('tags/get: no function at ' + str(target))
        rows = _func_tag_names(f)
        return {'function': str(f.getName()), 'tags': rows, 'total': len(rows)}
    raise Exception('tags: unknown action ' + str(action) + ' (list|search|create|delete|attach|detach|get)')


def _auto_analysis_manager():
    from ghidra.app.plugin.core.analysis.AutoAnalysisManager import getAnalysisManager
    return getAnalysisManager(currentProgram)


# ---------------------------------------------------------------- 批次 3：分析自动化
# 语义对照 bethington/ghidra-mcp v7.0.0 的 run_script_inline / run_ghidra_script /
# list_analyzers / configure_analyzer / run_analysis / reanalyze / search_byte_patterns /
# find_code_gaps / find_dead_code。上游每个端点都带 program 参数，本插件是单程序，故丢弃。

def _analysis_options():
    """程序里的「分析选项」：每个分析器一个 BOOLEAN 开关，子选项是 '分析器.子项'。
    实测 12.1.4 的 Program.ANALYSIS_PROPERTIES == 'Analyzers'（125 个叶子选项）。"""
    try:
        from ghidra.program.model.listing import Program
        key = str(Program.ANALYSIS_PROPERTIES)
    except Exception:
        key = 'Analyzers'
    return currentProgram.getOptions(key), key


def _opt_type(opts, name):
    try:
        return str(opts.getType(name))
    except Exception:
        return ''


def _opt_value(opts, name):
    """按真实类型取值——对 BOOLEAN 选项调 getBoolean 是对的，对其他类型会抛
    IllegalStateException: Expected option type: BOOLEAN_TYPE, but was type: ...。"""
    t = _opt_type(opts, name)
    try:
        if 'BOOLEAN' in t:
            return bool(opts.getBoolean(name, False))
        if 'LONG' in t:
            return int(opts.getLong(name, 0))
        if 'INT' in t:
            return int(opts.getInt(name, 0))
        if 'DOUBLE' in t or 'FLOAT' in t:
            return float(opts.getDouble(name, 0.0))
        if 'STRING' in t:
            return str(opts.getString(name, ''))
        if 'ENUM' in t:
            # Options 只有 getEnum(String, Enum) 一个读法（没有 getEnum(String)），
            # 传 None 即 null 默认值，能拿到当前常量；没有则返回 None。
            cur = opts.getEnum(name, None)
            return str(cur) if cur is not None else None
    except Exception:
        pass
    return None


def _enum_choices(opts, name):
    """枚举选项的可选值名。Class.getEnumConstants() 比 java.lang.Enum.valueOf 稳。"""
    try:
        cur = opts.getEnum(name, None)
        if cur is None:
            return []
        out = []
        for c in cur.getClass().getEnumConstants():
            try:
                out.append(str(c.name()))
            except Exception:
                out.append(str(c))
        return out
    except Exception:
        return []


def op_analyzers(obj):
    opts, key = _analysis_options()
    filt = str(obj.get('filter') or '').lower()
    only = bool(obj.get('onlyEnabled'))
    maxn = int(obj.get('max') or 200)
    names = [str(x) for x in opts.getOptionNames()]
    tops = []
    sub = {}
    for n in names:
        if '.' in n:
            top = n.split('.', 1)[0]
            sub[top] = sub.get(top, 0) + 1
        else:
            tops.append(n)
    rows = []
    for n in sorted(tops):
        if filt and filt not in n.lower():
            continue
        enabled = _opt_value(opts, n)
        if only and enabled is not True:
            continue
        row = {'name': n, 'enabled': enabled, 'type': _opt_type(opts, n),
               'subOptions': int(sub.get(n, 0))}
        if 'ENUM' in str(row['type']):
            row['choices'] = _enum_choices(opts, n)
        try:
            row['description'] = str(opts.getDescription(n))[:400]
        except Exception:
            pass
        rows.append(row)
    return {'key': key, 'list': rows[:maxn], 'total': len(rows),
            'truncated': len(rows) > maxn, 'registered': len(tops)}


def _coerce_bool(v):
    """JSON 里布尔是布尔；但 Node 工具把 value 声明成 string 传下来，
    所以 'false' 也必须变成 False（bool('false') 是 True，这是个真陷阱）。"""
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    return s in ('1', 'true', 'yes', 'y', 'on', 't')


def _coerce_num(v, as_float=False):
    try:
        if as_float:
            return float(str(v).strip())
        return int(float(str(v).strip()))
    except Exception:
        raise Exception('analyzerConfig: 这个值不是数字: ' + str(v))


def op_analyzer_configure(obj):
    opts, key = _analysis_options()
    name = str(obj.get('name') or obj.get('analyzer') or '').strip()
    if not name:
        raise Exception('analyzerConfig: name required')
    names = [str(x) for x in opts.getOptionNames()]
    if name not in names:
        low = name.lower()
        near = [n for n in names if low in n.lower()][:10]
        raise Exception('analyzerConfig: 没有这个分析选项: ' + name +
                        ('（相近的: ' + ', '.join(near) + '）' if near else ''))
    applied = {}
    with _tx('dsh configure analyzer'):
        if obj.get('enabled') is not None:
            opts.setBoolean(name, bool(obj.get('enabled')))
            applied['enabled'] = bool(obj.get('enabled'))
        if obj.get('value') is not None:
            v = obj.get('value')
            t = _opt_type(opts, name)
            if 'BOOLEAN' in t:
                opts.setBoolean(name, _coerce_bool(v))
                applied['value'] = _coerce_bool(v)
            elif 'LONG' in t:
                opts.setLong(name, _coerce_num(v))
                applied['value'] = _coerce_num(v)
            elif 'INT' in t:
                opts.setInt(name, _coerce_num(v))
                applied['value'] = _coerce_num(v)
            elif 'DOUBLE' in t or 'FLOAT' in t:
                opts.setDouble(name, _coerce_num(v, True))
                applied['value'] = _coerce_num(v, True)
            elif 'STRING' in t:
                opts.setString(name, str(v))
                applied['value'] = str(v)
            elif 'ENUM' in t:
                # 枚举选项只能 setEnum(String, java.lang.Enum)，传字符串会报
                # "No matching overloads found for ... setEnum(str,str)"。
                # 所以按当前常量的枚举类去找同名常量。
                cur = opts.getEnum(name, None)
                if cur is None:
                    raise Exception('analyzerConfig: 读不到这个枚举选项的当前值，无法写入（' + name + '）')
                want = str(v)
                chosen = None
                if str(cur) == want or str(cur.name()) == want:
                    chosen = cur
                else:
                    try:
                        for c in cur.getClass().getEnumConstants():
                            if str(c.name()) == want or str(c) == want:
                                chosen = c
                                break
                    except Exception as e:
                        raise Exception('analyzerConfig: 取枚举常量失败（' + name + '）: ' + str(e))
                if chosen is None:
                    raise Exception('analyzerConfig: 枚举里没有这个值 "' + want + '"（' + name +
                                    '），可选: ' + ', '.join([str(x).split('.')[-1] for x in _enum_choices(opts, name)]))
                opts.setEnum(name, chosen)
                applied['value'] = want
            else:
                raise Exception('analyzerConfig: 这个选项类型不支持写: ' + t + '（' + name + '）')
    reinit = True
    try:
        _auto_analysis_manager().initializeOptions()
    except Exception as e:
        reinit = 'err: ' + str(e)
    out = {'name': name, 'key': key, 'type': _opt_type(opts, name),
           'applied': applied, 'now': _opt_value(opts, name),
           'reinitialized': reinit, 'changed': bool(currentProgram.isChanged())}
    if 'ENUM' in str(out['type']):
        out['choices'] = _enum_choices(opts, name)
    try:
        out['valueString'] = str(opts.getValueAsString(name))
    except Exception:
        pass
    return out


def op_run_analysis(obj):
    """跑自动分析。注意**不**自己开事务：AutoAnalysisManager 的分析线程自己管事务，
    而 headless 在脚本外层本来就持有一个大事务，我们的子事务只用于直接写操作。"""
    am = _auto_analysis_manager()
    force = bool(obj.get('force'))
    before = None
    try:
        before = int(am.getTotalTimeInMillis())
    except Exception:
        pass
    am.startAnalysis(_monitor(), force)
    out = {'ran': True, 'force': force, 'changed': bool(currentProgram.isChanged())}
    try:
        out['totalTimeMs'] = int(am.getTotalTimeInMillis())
        if before is not None:
            out['elapsedMs'] = out['totalTimeMs'] - before
    except Exception:
        pass
    try:
        out['timedTasks'] = [str(x) for x in _take(am.getTimedTasks(), 60)]
    except Exception:
        pass
    try:
        out['taskTimes'] = str(am.getTaskTimesString())[:3000]
    except Exception:
        pass
    try:
        out['analyzing'] = bool(am.isAnalyzing())
    except Exception:
        pass
    return out


def _addr_set_of(target):
    from ghidra.program.model.address import AddressSet
    s = AddressSet()
    addr = resolve_address(str(target))
    f = _function_at(addr)
    if f is not None:
        s.add(f.getBody())
        return s, 'function ' + str(f.getName()), f
    s.add(addr, addr)
    return s, 'address ' + str(addr), None


def op_reanalyze(obj):
    from ghidra.program.model.address import AddressSet
    am = _auto_analysis_manager()
    target = obj.get('target') or obj.get('address')
    if not target and not obj.get('all'):
        raise Exception('reanalyze: 需要 target（函数名/地址）或 all=true（整个已初始化内存）')
    if target:
        setv, scope, _f = _addr_set_of(target)
    else:
        setv = AddressSet()
        for b in currentProgram.getMemory().getBlocks():
            if b.isInitialized():
                setv.add(b.getStart(), b.getEnd())
        scope = 'all-initialized'
    try:
        n = int(setv.getNumAddresses())
    except Exception:
        n = None
    am.reAnalyzeAll(setv)
    am.startAnalysis(_monitor(), bool(obj.get('force')))
    return {'reanalyzed': scope, 'addresses': n, 'scanned': bool(obj.get('scan', True)),
            'changed': bool(currentProgram.isChanged())}


def _parse_byte_pattern(text):
    """'48 8B ?? 4? C3' / '488b??4?' / '48 8B ? ?' → ([byte…], [mask…])
    掩码里 0 = 该位任意（Ghidra Memory.findBytes 的语义）。"""
    s = str(text or '').strip()
    if not s:
        raise Exception('bytePattern: 空模式')
    toks = []
    if ' ' in s or '\t' in s:
        toks = [x for x in s.replace('\t', ' ').split(' ') if x != '']
    else:
        i = 0
        while i < len(s):
            c = s[i]
            if c in '?.':
                toks.append('?')
                i += 1
            else:
                toks.append(s[i:i + 2])
                i += 2
    pat = []
    mask = []
    for t in toks:
        t = t.strip()
        if not t:
            continue
        if t.lower().startswith('0x'):
            t = t[2:]
        if t == '**':
            t = '?'
        if len(t) > 2:
            raise Exception('bytePattern: 一个 token 最多 2 个十六进制位（收到 "' + t + '"）')
        b = 0
        m = 0
        for k in range(2):
            ch = t[k] if k < len(t) else '?'
            if ch in '?.':
                continue
            if ch.lower() not in '0123456789abcdef':
                raise Exception('bytePattern: 非法十六进制位 "' + ch + '"')
            m |= (0xF0 >> (4 * k))
            b |= int(ch, 16) << (4 * (1 - k))
        pat.append(b)
        mask.append(m)
    if not pat:
        raise Exception('bytePattern: 解析后为空')
    return pat, mask


def _signed_bytes(values):
    arr = _new_byte_array(len(values))
    for i in range(len(values)):
        v = int(values[i]) & 0xFF
        arr[i] = v - 256 if v > 127 else v
    return arr


def op_search_bytes(obj):
    alts = str(obj.get('pattern') or '')
    if not alts.strip():
        raise Exception('searchBytes: pattern required')
    limit = int(obj.get('limit') or 100)
    if limit > 1000:
        limit = 1000
    if limit < 1:
        limit = 1
    mem = currentProgram.getMemory()
    mon = _monitor()
    pats = [p.strip() for p in alts.split('|') if p.strip()]
    lo = resolve_address(str(obj.get('start'))) if obj.get('start') else None
    hi = resolve_address(str(obj.get('end'))) if obj.get('end') else None
    rows = []
    truncated = False
    scanned_blocks = 0
    for p in pats:
        pb, mb = _parse_byte_pattern(p)
        jb = _signed_bytes(pb)
        jm = _signed_bytes(mb)
        for blk in mem.getBlocks():
            if not blk.isInitialized():
                continue
            if obj.get('executable') and not blk.isExecute():
                continue
            start = blk.getStart()
            end = blk.getEnd()
            if lo is not None and lo.compareTo(start) > 0:
                start = lo
            if hi is not None and hi.compareTo(end) < 0:
                end = hi
            if start.compareTo(end) > 0:
                continue
            scanned_blocks += 1
            cur = start
            while len(rows) < limit:
                hit = mem.findBytes(cur, end, jb, jm, True, mon)
                if hit is None:
                    break
                rows.append({'pattern': p, 'address': str(hit), 'block': str(blk.getName())})
                cur = hit.add(1)
            if len(rows) >= limit:
                truncated = True
                break
        if truncated:
            break
    return {'list': rows, 'total': len(rows), 'patterns': pats,
            'scannedBlocks': scanned_blocks, 'truncated': truncated}


def _range_len(r):
    """一个范围的长度。输入可能是 AddressSetView（如 op_code_gaps 传的 AddressSet），
    也可能是 MemoryBlock —— 两者的方法面**不一样**：
      AddressRange/AddressSet 有 getLength()/getMinAddress()/getMaxAddress()；
      MemoryBlock 只有 getStart()/getEnd()/getSize()，调 getLength()/getMaxAddress()
      会抛 AttributeError（JPype 实测）。
    旧实现只试 getLength() + getMaxAddress() 两路，遇到 MemoryBlock 两路全失败、
    静默返回 0 —— 批次 4 的 includeRawMemory 因此一个字节都没扫（补丁 11）。"""
    for probe in (lambda: int(r.getLength()),
                  lambda: int(r.getSize()),
                  lambda: int(r.getMaxAddress().subtract(r.getMinAddress())) + 1,
                  lambda: int(r.getEnd().subtract(r.getStart())) + 1):
        try:
            v = probe()
        except Exception:
            continue
        if v > 0:
            return v
    return 0


def op_code_gaps(obj):
    """已初始化（默认仅可执行）内存里**没有任何代码/数据定义**的空洞。
    Listing.getUndefinedRanges(set, doFollowData=True, monitor) 是 Ghidra 自己的实现。"""
    listing = currentProgram.getListing()
    mon = _monitor()
    minsize = int(obj.get('minSize') or 1)
    limit = int(obj.get('limit') or 200)
    if limit > 2000:
        limit = 2000
    rows = []
    scanned = 0
    errors = []
    for blk in currentProgram.getMemory().getBlocks():
        if not blk.isInitialized():
            continue
        if not blk.isExecute() and not obj.get('includeData'):
            continue
        scanned += 1
        if len(rows) >= limit:
            break
        try:
            # 必须传 AddressSetView，不能传 MemoryBlock：
            # getUndefinedRanges(MemoryBlock,…) 会报 "No matching overloads found"。
            from ghidra.program.model.address import AddressSet
            rng = AddressSet()
            rng.add(blk.getStart(), blk.getEnd())
            undef = listing.getUndefinedRanges(rng, True, mon)
        except Exception as e:
            errors.append({'block': str(blk.getName()), 'error': str(e)})
            continue
        it = undef.getAddressRanges()
        while it.hasNext():
            r = it.next()
            size = _range_len(r)
            if size < minsize:
                continue
            rows.append({'block': str(blk.getName()), 'start': str(r.getMinAddress()),
                         'end': str(r.getMaxAddress()), 'size': size,
                         'executable': bool(blk.isExecute())})
            if len(rows) >= limit:
                break
    return {'list': rows, 'total': len(rows), 'scannedBlocks': scanned,
            'truncated': len(rows) >= limit, 'errors': errors}


def op_dead_code(obj):
    """无调用者的函数（排除外部函数与 thunk，默认也避开程序的入口点）。
    这是「死代码**候选**」：间接调用（函数指针表）在这套判据里看不见。"""
    fm = currentProgram.getFunctionManager()
    mon = _monitor()
    limit = int(obj.get('limit') or 200)
    if limit > 2000:
        limit = 2000
    include_thunks = bool(obj.get('includeThunks'))
    include_stubs = bool(obj.get('includeStubs'))
    entries = {}
    for getter in ('getExternalEntryPointIterator',):
        try:
            it = getattr(currentProgram.getSymbolTable(), getter)()
            while it.hasNext():
                entries[str(it.next())] = True
        except Exception:
            pass
    rows = []
    scanned = 0
    for f in fm.getFunctions(True):
        if len(rows) >= limit:
            break
        try:
            if f.isExternal():
                continue
            if f.isThunk() and not include_thunks:
                continue
            if getattr(f, 'isStub', None) is not None and f.isStub() and not include_stubs:
                continue
        except Exception:
            pass
        scanned += 1
        try:
            callers = _take(f.getCallingFunctions(mon), 50)
        except Exception as e:
            rows.append({'name': str(f.getName()), 'address': str(f.getEntryPoint()),
                         'callers': 'err: ' + str(e)})
            continue
        if len(callers) > 0:
            continue
        ep = str(f.getEntryPoint())
        if ep in entries:
            continue
        row = {'name': str(f.getName()), 'address': ep, 'callers': 0}
        try:
            row['size'] = int(f.getBody().getNumAddresses())
        except Exception:
            pass
        try:
            row['signature'] = str(f.getSignature())
        except Exception:
            pass
        rows.append(row)
    return {'list': rows, 'total': len(rows), 'scanned': scanned,
            'includeThunks': include_thunks, 'truncated': len(rows) >= limit}


def _jsonable(v):
    try:
        json.dumps(v)
        return v
    except Exception:
        return str(v)


def _exec_python(code, filename, args, write):
    """在 Ghidra 上下文里跑一段 Python。
    本脚本跑在 **CPython 3.13 + JPype**（pyghidra 3.x），不是 Jython，所以 exec() 是函数。
    stdout 双路捕获：Python 侧 sys.stdout + Java 侧 System.out（Ghidra API 往 JVM stdout 打印）。"""
    import contextlib
    import io
    import traceback
    from java.lang import System
    from java.io import ByteArrayOutputStream, PrintStream
    arglist = [str(a) for a in (args or [])]
    pybuf = io.StringIO()
    jbuf = ByteArrayOutputStream()
    ns = {
        'currentProgram': currentProgram,
        'program': currentProgram,
        'monitor': _monitor(),
        'scriptArgs': arglist,
        'getScriptArgs': lambda: list(arglist),
        'println': lambda *a: pybuf.write(' '.join([str(x) for x in a]) + '\n'),
        'print': lambda *a: pybuf.write(' '.join([str(x) for x in a]) + '\n'),
    }
    reserved = set(ns.keys())
    err = None
    tb = None
    old_out = None
    try:
        old_out = System.out
        System.setOut(PrintStream(jbuf, True))
    except Exception:
        old_out = None
    try:
        src = compile(code, filename, 'exec')
        with contextlib.redirect_stdout(pybuf):
            if write:
                with _tx('dsh script ' + filename):
                    exec(src, ns)
            else:
                exec(src, ns)
    except Exception as e:
        err = str(e)
        tb = traceback.format_exc()
    finally:
        if old_out is not None:
            try:
                System.setOut(old_out)
            except Exception:
                pass
    try:
        jtxt = str(jbuf.toString('UTF-8'))
    except Exception:
        try:
            jtxt = str(jbuf.toString())
        except Exception:
            jtxt = ''
    out = {'stdout': (pybuf.getvalue() + jtxt)[:20000],
           'changed': bool(currentProgram.isChanged())}
    if err is not None:
        out['error'] = err
        out['traceback'] = (tb or '')[:4000]
    for k in ('result', 'RESULT', 'output', 'RESULT_DATA'):
        if k in ns and k not in reserved:
            out['result'] = _jsonable(ns[k])
            break
    defined = [k for k in ns.keys() if k not in reserved and not k.startswith('__')]
    out['defined'] = sorted(defined)[:60]
    return out


def op_run_script_inline(obj):
    code = obj.get('code')
    if code is None or not str(code).strip():
        raise Exception('runScriptInline: code required')
    return _exec_python(str(code), '<dsh-inline>', obj.get('args'), bool(obj.get('write')))


def op_run_script(obj):
    import os
    path = str(obj.get('scriptPath') or obj.get('path') or '').strip()
    if not path:
        raise Exception('runScript: scriptPath required')
    p = os.path.abspath(os.path.normpath(path))
    if not os.path.isfile(p):
        raise Exception('runScript: 文件不存在: ' + p)
    ext = os.path.splitext(p)[1].lower()
    if ext not in ('.py', '.pyw', '.txt', ''):
        raise Exception('runScript: 只支持 Python 脚本（Java/Groovy 脚本要走 headless 的 script provider，'
                        '本桥是 in-process 执行）。当前扩展名: ' + ext)
    fh = open(p, 'rb')
    try:
        raw = fh.read()
    finally:
        fh.close()
    try:
        code = raw.decode('utf-8-sig')
    except Exception:
        code = raw.decode('utf-8', 'replace')
    res = _exec_python(code, p, obj.get('args'), bool(obj.get('write')))
    res['scriptPath'] = p
    res['bytes'] = len(raw)
    return res


# ---------------------------------------------- 批次 3 后半：复合分析 / 指令搜索 / 哈希比较 / 数据流

def _function_required(obj, opname):
    target = obj.get('target') or obj.get('address') or obj.get('function')
    if not target:
        raise Exception(opname + ': target required')
    f = _function_at(resolve_address(str(target)))
    if f is None:
        raise Exception(opname + ': no function at ' + str(target))
    return f


def _decompile_high(func, timeout=60):
    """拿 HighFunction（连带反编译结果）。只读，不开事务，由调用方 dispose。"""
    di = DecompInterface()
    di.openProgram(currentProgram)
    try:
        res = di.decompileFunction(func, timeout, _monitor())
        if res is None or not res.decompileCompleted() or res.getHighFunction() is None:
            msg = ''
            try:
                msg = str(res.getErrorMessage())
            except Exception:
                pass
            raise Exception('decompile failed: ' + msg)
        return di, res.getHighFunction(), res
    except Exception:
        try:
            di.dispose()
        except Exception:
            pass
        raise


def _instruction_rows(f, maxn=200000):
    listing = currentProgram.getListing()
    out = []
    for insn in _take(listing.getInstructions(f.getBody(), True), maxn):
        out.append((str(insn.getAddress()), str(insn.getMnemonicString()), str(insn)))
    return out


def _string_refs_in(f, maxn=50):
    """函数体里指向「看起来是字符串」的数据的引用。是提示，不是定论——
    Ghidra 把 int 也定义成 Data，所以同时回传 type 让调用方自己判断。"""
    listing = currentProgram.getListing()
    refmgr = currentProgram.getReferenceManager()
    rows = []
    seen = {}
    for insn in _take(listing.getInstructions(f.getBody(), True), 20000):
        for r in _take(refmgr.getReferencesFrom(insn.getAddress()), 20):
            try:
                to = r.getToAddress()
            except Exception:
                continue
            key = str(to)
            if key in seen:
                continue
            seen[key] = True
            try:
                d = listing.getDataAt(to)
            except Exception:
                d = None
            if d is None:
                continue
            try:
                s = str(d.getValue())
                tn = str(d.getDataType().getName())
            except Exception:
                continue
            printable = len(s) >= 4 and all(32 <= ord(c) < 127 for c in s) and not s.isdigit()
            if 'string' in tn.lower() or 'char' in tn.lower() or printable:
                rows.append({'from': str(insn.getAddress()), 'to': key,
                             'value': s[:200], 'type': tn})
                if len(rows) >= maxn:
                    return rows
    return rows


def op_function_context(obj):
    """一次调用给出一个函数的全貌：签名/参数/局部变量/调用关系/外部引用/
    字符串引用/指令统计/反编译摘要（基本块、分支、圈复杂度）/可选伪代码。"""
    f = _function_required(obj, 'functionContext')
    mon = _monitor()
    maxn = int(obj.get('max') or 50)
    out = {'name': str(f.getName()), 'address': str(f.getEntryPoint()),
           'signature': str(f.getSignature()),
           'body': {'start': str(f.getBody().getMinAddress()),
                    'end': str(f.getBody().getMaxAddress()),
                    'size': int(f.getBody().getNumAddresses())},
           'thunk': bool(f.isThunk()), 'external': bool(f.isExternal())}
    try:
        out['noReturn'] = bool(f.hasNoReturn())
    except Exception:
        pass
    try:
        out['parameters'] = [{'name': str(p.getName()), 'type': str(p.getDataType().getName()),
                              'storage': str(p.getVariableStorage())} for p in _take(f.getParameters(), 200)]
    except Exception as e:
        out['parametersErr'] = str(e)
    try:
        out['locals'] = [{'name': str(v.getName()), 'type': str(v.getDataType().getName()),
                          'storage': str(v.getVariableStorage())} for v in _take(f.getLocalVariables(), 200)]
    except Exception as e:
        out['localsErr'] = str(e)
    try:
        out['callers'] = [_func_row(x) for x in _take(f.getCallingFunctions(mon), maxn)]
    except Exception as e:
        out['callersErr'] = str(e)
    try:
        out['callees'] = [_func_row(x) for x in _take(f.getCalledFunctions(mon), maxn)]
    except Exception as e:
        out['calleesErr'] = str(e)
    try:
        refs = _take(currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint()), 5000)
        out['xrefsToEntry'] = len(refs)
        out['xrefsSample'] = [{'from': str(r.getFromAddress()), 'type': str(r.getReferenceType())}
                              for r in refs[:maxn]]
    except Exception as e:
        out['xrefsErr'] = str(e)
    out['strings'] = _string_refs_in(f, maxn)
    insns = _instruction_rows(f)
    out['instructionCount'] = len(insns)
    try:
        import hashlib
        ht = hashlib.md5()
        hm = hashlib.md5()
        for _a, mn, t in insns:
            ht.update((t + '\n').encode('utf-8'))
            hm.update((mn + '\n').encode('utf-8'))
        out['codeMd5'] = ht.hexdigest()
        out['mnemonicMd5'] = hm.hexdigest()
    except Exception:
        pass
    di = None
    try:
        di, hf, res = _decompile_high(f)
        blocks = _take(hf.getBasicBlocks(), 5000)
        ops = _take(hf.getPcodeOps(), 200000)
        branches = 0
        for o in ops:
            try:
                if str(o.getMnemonic()) in ('CBRANCH', 'BRANCH', 'BRANCHIND'):
                    branches += 1
            except Exception:
                pass
        edges = 0
        in_edges = 0
        for b in blocks:
            # PcodeBlockBasic 有 getInSize()/getOutSize()/getIn(int)/getOut(int)，
            # 但**没有** getOutgoingEdges()/getOutEdges()（实测 12.1.4）。
            try:
                edges += int(b.getOutSize())
            except Exception:
                pass
            try:
                in_edges += int(b.getInSize())
            except Exception:
                pass
        dec = {'basicBlocks': len(blocks), 'pcodeOps': len(ops), 'branches': branches,
               'edges': edges, 'inEdges': in_edges}
        if blocks:
            # 圈复杂度 M = E - N + 2P（P=1 个连通分量）
            dec['cyclomaticComplexity'] = edges - len(blocks) + 2
        out['decompiler'] = dec
        if obj.get('includeCode', True):
            try:
                out['pseudocode'] = str(res.getDecompiledFunction().getC())[:6000]
            except Exception as e:
                out['pseudocodeErr'] = str(e)
    except Exception as e:
        out['decompilerErr'] = str(e)
    finally:
        if di is not None:
            try:
                di.dispose()
            except Exception:
                pass
    return out


def op_search_instructions(obj):
    """按助记符子串 / 操作数子串 / 整条指令文本的正则搜索指令。"""
    listing = currentProgram.getListing()
    limit = int(obj.get('limit') or 200)
    if limit > 2000:
        limit = 2000
    if limit < 1:
        limit = 1
    mn_filter = str(obj.get('mnemonic') or '').strip().lower()
    op_filter = str(obj.get('operand') or '').strip().lower()
    rx = None
    if obj.get('pattern'):
        flags = 0 if obj.get('caseSensitive') else re.IGNORECASE
        rx = re.compile(str(obj.get('pattern')), flags)
    if not (mn_filter or op_filter or rx):
        raise Exception('searchInstructions: 至少要给 mnemonic / operand / pattern 之一')
    scope = None
    scope_desc = 'whole program'
    if obj.get('target') or obj.get('function'):
        f = _function_required(obj, 'searchInstructions')
        scope = f.getBody()
        scope_desc = 'function ' + str(f.getName())
    it = listing.getInstructions(scope, True) if scope is not None else listing.getInstructions(True)
    rows = []
    truncated = False
    while it.hasNext():
        insn = it.next()
        try:
            mn = str(insn.getMnemonicString())
            txt = str(insn)
        except Exception:
            continue
        if mn_filter and mn_filter not in mn.lower():
            continue
        if op_filter and op_filter not in txt.lower():
            continue
        if rx is not None and not rx.search(txt):
            continue
        row = {'address': str(insn.getAddress()), 'mnemonic': mn, 'text': txt}
        try:
            f2 = currentProgram.getFunctionManager().getFunctionContaining(insn.getAddress())
            if f2 is not None:
                row['function'] = str(f2.getName())
        except Exception:
            pass
        rows.append(row)
        if len(rows) >= limit:
            truncated = True
            break
    return {'list': rows, 'total': len(rows), 'scope': scope_desc, 'truncated': truncated}


def _hash_hex(raw, algo):
    import hashlib
    h = hashlib.new(algo)
    h.update(raw)
    return h.hexdigest()


def _read_bytes(addr, n):
    mem = currentProgram.getMemory()
    arr = _new_byte_array(n)
    got = int(mem.getBytes(addr, arr, 0, n))
    out = bytearray()
    for i in range(got):
        out.append(int(arr[i]) & 0xFF)
    return bytes(out)


def op_hash(obj):
    """函数级：原始字节哈希 + 整条指令文本哈希 + 只取助记符的结构哈希。
    程序级：镜像块的逐块哈希与整体哈希（另外回传 Ghidra 自己记的可执行文件 MD5/SHA256）。"""
    import hashlib
    algo = str(obj.get('algorithm') or 'md5').lower()
    if algo not in ('md5', 'sha1', 'sha256'):
        raise Exception('hash: algorithm 只支持 md5/sha1/sha256')
    has_target = bool(obj.get('target') or obj.get('address') or obj.get('function'))
    if str(obj.get('scope') or '').lower() == 'program' or not has_target:
        out = {'scope': 'program', 'program': str(currentProgram.getName()), 'algorithm': algo}
        for k, fn in (('executableMD5', lambda: currentProgram.getExecutableMD5()),
                      ('executableSHA256', lambda: currentProgram.getExecutableSHA256()),
                      ('executableFormat', lambda: currentProgram.getExecutableFormat()),
                      ('executablePath', lambda: currentProgram.getExecutablePath())):
            try:
                out[k] = str(fn())
            except Exception as e:
                out[k] = 'err: ' + str(e)
        limit_b = int(obj.get('maxBytes') or (64 * 1024 * 1024))
        read = 0
        blocks = []
        total = hashlib.new(algo)
        for b in currentProgram.getMemory().getBlocks():
            if not b.isInitialized() or int(b.getSize()) <= 0:
                continue
            if read >= limit_b:
                out['truncated'] = True
                break
            n = int(min(int(b.getSize()), limit_b - read))
            try:
                raw = _read_bytes(b.getStart(), n)
            except Exception as e:
                blocks.append({'name': str(b.getName()), 'error': str(e)})
                continue
            read += len(raw)
            blocks.append({'name': str(b.getName()), 'size': len(raw), algo: _hash_hex(raw, algo)})
            total.update(str(b.getName()).encode('utf-8'))
            total.update(raw)
        out['blocks'] = blocks
        out['imageHash'] = total.hexdigest()
        out['hashedBytes'] = read
        return out
    f = _function_required(obj, 'hash')
    body = f.getBody()
    size = int(body.getNumAddresses())
    out = {'scope': 'function', 'name': str(f.getName()), 'address': str(f.getEntryPoint()),
           'algorithm': algo, 'size': size}
    try:
        raw = _read_bytes(body.getMinAddress(), size)
        out['bytesHash'] = _hash_hex(raw, algo)
        out['bytesRead'] = len(raw)
    except Exception as e:
        out['bytesErr'] = str(e)
    insns = _instruction_rows(f)
    ht = hashlib.new(algo)
    hm = hashlib.new(algo)
    for _a, mn, t in insns:
        ht.update((t + '\n').encode('utf-8'))
        hm.update((mn + '\n').encode('utf-8'))
    out['instructions'] = len(insns)
    out['codeHash'] = ht.hexdigest()
    out['mnemonicHash'] = hm.hexdigest()
    return out


def op_compare_functions(obj):
    """比较同一个程序里的两个函数：字节哈希、助记符序列相似度、参数表差集、
    被调用函数差集，以及逐条指令的前 N 处差异。"""
    import difflib
    ta_in = obj.get('a') or obj.get('targetA') or obj.get('left')
    tb_in = obj.get('b') or obj.get('targetB') or obj.get('right')
    if not ta_in or not tb_in:
        raise Exception('compareFunctions: 需要 a 与 b 两个函数（名或地址）')
    fa = _function_required({'target': ta_in}, 'compareFunctions(a)')
    fb = _function_required({'target': tb_in}, 'compareFunctions(b)')
    maxn = int(obj.get('max') or 25)
    ia = _instruction_rows(fa)
    ib = _instruction_rows(fb)
    ta = [t for _a, _m, t in ia]
    tb = [t for _a, _m, t in ib]
    ma = [m for _a, m, _t in ia]
    mb = [m for _a, m, _t in ib]

    def _params(f):
        return ['%s %s' % (p.getDataType().getName(), p.getName()) for p in _take(f.getParameters(), 200)]

    def _callees(f):
        return sorted(set([str(x.getName()) for x in _take(f.getCalledFunctions(_monitor()), 5000)]))

    def _sig(f):
        try:
            return str(f.getSignature())
        except Exception:
            return ''

    diff_rows = []
    for i in range(min(len(ta), len(tb))):
        if ta[i] != tb[i]:
            diff_rows.append({'index': i, 'a': ta[i], 'b': tb[i]})
            if len(diff_rows) >= maxn:
                break
    pa = set(_params(fa))
    pb = set(_params(fb))
    ca = _callees(fa)
    cb = _callees(fb)
    return {'a': {'name': str(fa.getName()), 'address': str(fa.getEntryPoint()), 'signature': _sig(fa),
                  'size': int(fa.getBody().getNumAddresses()), 'instructions': len(ta), 'parameters': _params(fa)},
            'b': {'name': str(fb.getName()), 'address': str(fb.getEntryPoint()), 'signature': _sig(fb),
                  'size': int(fb.getBody().getNumAddresses()), 'instructions': len(tb), 'parameters': _params(fb)},
            'instructionCountDelta': len(tb) - len(ta),
            'textSimilarity': round(difflib.SequenceMatcher(None, ta, tb).ratio(), 4),
            'mnemonicSimilarity': round(difflib.SequenceMatcher(None, ma, mb).ratio(), 4),
            'sameMnemonicSequence': ma == mb,
            'paramsOnlyInA': sorted(pa - pb), 'paramsOnlyInB': sorted(pb - pa),
            'calleesOnlyInA': sorted(set(ca) - set(cb)), 'calleesOnlyInB': sorted(set(cb) - set(ca)),
            'firstDifferences': diff_rows, 'differencesShown': len(diff_rows)}


def op_data_flow(obj):
    """用反编译器的高层 p-code 追一个变量的定义/使用链（Varnode 的 def 与 descendants）。
    list=true 且不给 variable 时列出该函数全部高层符号。"""
    f = _function_required(obj, 'dataFlow')
    direction = str(obj.get('direction') or 'both').lower()
    if direction not in ('forward', 'backward', 'both'):
        raise Exception('dataFlow: direction 只能是 forward/backward/both')
    depth = int(obj.get('depth') or 4)
    if depth > 12:
        depth = 12
    if depth < 0:
        depth = 0
    maxn = int(obj.get('max') or 200)
    if maxn > 2000:
        maxn = 2000
    want = str(obj.get('variable') or '').strip()
    di = None
    try:
        di, hf, _res = _decompile_high(f)
        lsm = hf.getLocalSymbolMap()
        syms = _take(lsm.getSymbols(), 4000)
        if obj.get('list') and not want:
            return {'function': str(f.getName()), 'params': int(lsm.getNumParams()),
                    'variables': [{'name': str(s.getName()), 'type': str(s.getDataType().getName()),
                                   'size': int(s.getSize()), 'storage': str(s.getStorage())} for s in syms],
                    'total': len(syms)}
        sym = None
        if want:
            for s in syms:
                if str(s.getName()) == want:
                    sym = s
                    break
            if sym is None:
                raise Exception('dataFlow: 没有变量 ' + want + '（可选: ' +
                                ', '.join([str(s.getName()) for s in syms][:30]) + '）')
        else:
            for s in syms:
                hv0 = s.getHighVariable()
                if hv0 is not None and _take(hv0.getInstances(), 1):
                    sym = s
                    break
            if sym is None:
                raise Exception('dataFlow: 这个函数里没有可追踪的变量')
        hv = sym.getHighVariable()
        if hv is None:
            raise Exception('dataFlow: ' + str(sym.getName()) + ' 没有 HighVariable（可能被优化掉了）')
        instances = _take(hv.getInstances(), 200)
        seen = {}
        rows = []

        def rec(op, dep, via):
            key = str(op.getSeqnum())
            if key in seen or len(rows) >= maxn or dep > depth:
                return
            seen[key] = True
            rows.append({'seq': key, 'depth': dep, 'via': via,
                         'mnemonic': str(op.getMnemonic()), 'op': str(op)[:300]})
            if dep >= depth:
                return
            if direction in ('forward', 'both'):
                ov = op.getOutput()
                if ov is not None:
                    for nxt in _take(ov.getDescendants(), 500):
                        rec(nxt, dep + 1, 'def')
            if direction in ('backward', 'both'):
                for iv in _take(op.getInputs(), 8):
                    d = iv.getDef()
                    if d is not None:
                        rec(d, dep + 1, 'use')

        first = []
        for v in instances:
            d = v.getDef()
            if d is not None and direction in ('backward', 'both'):
                first.append(d)
            if direction in ('forward', 'both'):
                first.extend(_take(v.getDescendants(), 500))
        for op in first:
            rec(op, 0, 'instance')
        defs = []
        for v in instances:
            d = v.getDef()
            defs.append({'address': str(v.getAddress()), 'size': int(v.getSize()),
                         'def': str(d)[:200] if d is not None else None})
        return {'function': str(f.getName()), 'variable': str(sym.getName()),
                'type': str(sym.getDataType().getName()), 'direction': direction,
                'depth': depth, 'instances': defs, 'ops': rows, 'total': len(rows),
                'truncated': len(rows) >= maxn}
    finally:
        if di is not None:
            try:
                di.dispose()
            except Exception:
                pass


# ---------------------------------------------------------------- 批次 4：恶意代码分析
#
# 四个工具的共同原则：**只给证据，不给结论**。每条命中都带地址/来源/原始文本，由调用方
# 自己判断；启发式（例如「RDTSC 与 GetTickCount 同时出现」）只作为 indicators 里的一条，
# 绝不写成「这是恶意软件」。假阳性（把普通程序判成恶意）比漏报更难排查。


# ==== BATCH4-CONSTS-BEGIN ====
# 下面这段**纯 Python**（不 import java/jpype），可以在 Ghidra 之外单测：
#   py -3.13 kat-consts.py
# 之所以全部运行时算出而不是手抄十六进制表：手抄 256 字节 S-box 或 64 个 K 常量极易错
# 一个字节，而错一个字节的签名就是「永远搜不到」——不报错、只是没有结果（假绿家族）。
# 这样做的原因：错一个字节的签名永不出错、只是搜不到（同「假绿」家族）。

def _iroot(n, k):
    """整数 k 次方根（向下取整），整数牛顿法。"""
    n = int(n)
    if k < 1:
        raise ValueError('k must be >= 1')
    if n < 0:
        raise ValueError('n must be >= 0')
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // (x ** (k - 1))) // k
        if y >= x:
            return x
        x = y


def _primes(count):
    out = []
    cand = 2
    while len(out) < count:
        ok = True
        for p in out:
            if p * p > cand:
                break
            if cand % p == 0:
                ok = False
                break
        if ok:
            out.append(cand)
        cand += 1
    return out


def _frac_bits(root_of, count, bits):
    """第 i 个物理常量的「小数部分 × 2^bits」：整数根的**低位**就是小数部分
    （前 80 个素数的平方根整数部分 < 2^5、立方根 < 2^3，不会溢出到低位里）。"""
    out = []
    mask = (1 << bits) - 1
    for p in _primes(count):
        out.append(int(root_of(p)) & mask)
    return out


def _words_le(words, width):
    out = []
    for w in words:
        v = int(w) & ((1 << (8 * width)) - 1)
        for i in range(width):
            out.append((v >> (8 * i)) & 0xFF)
    return out


def _words_be(words, width):
    out = []
    for w in words:
        v = int(w) & ((1 << (8 * width)) - 1)
        for i in range(width - 1, -1, -1):
            out.append((v >> (8 * i)) & 0xFF)
    return out


def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_inv(a):
    """GF(2^8) 求逆：a^254（a=0 时逆元定义为 0）。"""
    if a == 0:
        return 0
    r = 1
    n = 254
    base = a
    while n:
        if n & 1:
            r = _gf_mul(r, base)
        base = _gf_mul(base, base)
        n >>= 1
    return r


def _aes_sbox():
    """FIPS-197 5.1.1：先求 GF(2^8) 逆，再做仿射变换。KAT: sbox[0]=0x63。"""
    out = []
    for i in range(256):
        x = _gf_inv(i)
        y = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            y ^= x
        out.append(y ^ 0x63)
    return out


def _aes_inv_sbox(sbox):
    out = [0] * 256
    for i in range(256):
        out[sbox[i]] = i
    return out


def _crc_table(poly):
    """反射式 CRC 表（低位优先）：poly 取反射形式，如 0xEDB88320 / 0x82F63B78。"""
    out = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if (c & 1) else (c >> 1)
        out.append(c & 0xFFFFFFFF)
    return out


def _md5_t():
    """T[i] = floor(abs(sin(i+1)) * 2^32)。KAT: T[0]=0xd76aa478。"""
    import math
    return [int(abs(math.sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64)]


def _keccak_rc():
    """Keccak/SHA-3 轮常量：rc(t) LFSR（x^8+x^6+x^5+x^4+1）。KAT: rc[0]=1, rc[1]=0x8082。"""
    rc = []
    lfsr = 1
    for _ in range(24):
        v = 0
        for j in range(7):
            if lfsr & 1:
                v |= 1 << ((1 << j) - 1)
            lfsr = ((lfsr << 1) ^ (0x71 if (lfsr & 0x80) else 0)) & 0xFF
        rc.append(v)
    return rc


def _crypto_signatures():
    """[(name, algorithm, [字节…], note)]——全部由上面的生成器算出。"""
    sigs = []
    sbox = _aes_sbox()
    sigs.append(('AES S-box', 'AES', sbox, 'FIPS-197 替换表（整表 256 字节）'))
    sigs.append(('AES S-box prefix', 'AES', sbox[:16], 'S-box 前 16 字节（表被截断或只用了首行时）'))
    sigs.append(('AES inverse S-box', 'AES', _aes_inv_sbox(sbox), '解密用逆 S-box（整表 256 字节）'))
    crc = _crc_table(0xEDB88320)
    sigs.append(('CRC32 table prefix', 'CRC-32', _words_le(crc[:16], 4), 'poly 0xEDB88320 前 16 项'))
    sigs.append(('CRC32 table (full)', 'CRC-32', _words_le(crc, 4), 'poly 0xEDB88320 全表（256 项）'))
    crcc = _crc_table(0x82F63B78)
    sigs.append(('CRC32C table prefix', 'CRC-32C', _words_le(crcc[:16], 4), 'poly 0x82F63B78 前 16 项'))
    init4 = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    sigs.append(('MD5/SHA-1 init', 'MD5', _words_le(init4, 4), 'MD4 系初始向量（小端存放）'))
    sigs.append(('MD5/SHA-1 init (big-endian)', 'MD5', _words_be(init4, 4), '同一组常量的大端存放'))
    t = _md5_t()
    sigs.append(('MD5 T table prefix', 'MD5', _words_le(t[:16], 4), 'T[i]=floor(abs(sin(i+1))*2^32) 前 16 项'))
    sigs.append(('MD5 T table prefix (big-endian)', 'MD5', _words_be(t[:16], 4), '同上，大端存放'))
    sigs.append(('MD5 T table (full)', 'MD5', _words_le(t, 4), '全 64 项'))
    sha1h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    sigs.append(('SHA-1 init', 'SHA-1', _words_be(sha1h, 4), 'SHA-1 初始向量（大端）'))
    sigs.append(('SHA-1 init (little-endian)', 'SHA-1', _words_le(sha1h, 4), '同上，小端存放'))
    h256 = _frac_bits(lambda p: _iroot(p << 64, 2), 8, 32)
    sigs.append(('SHA-256 init', 'SHA-256', _words_be(h256, 4), 'sqrt 前 8 素数小数部分（大端）'))
    sigs.append(('SHA-256 init (little-endian)', 'SHA-256', _words_le(h256, 4), '同上，小端存放'))
    k256 = _frac_bits(lambda p: _iroot(p << 96, 3), 64, 32)
    sigs.append(('SHA-256 K prefix', 'SHA-256', _words_be(k256[:16], 4), 'cbrt 前 16 素数小数部分'))
    sigs.append(('SHA-256 K (full)', 'SHA-256', _words_be(k256, 4), '全 64 个轮常量'))
    k512 = _frac_bits(lambda p: _iroot(p << 192, 3), 80, 64)
    sigs.append(('SHA-512 K prefix', 'SHA-512', _words_be(k512[:8], 8), 'cbrt 前 8 素数的 64 位小数部分'))
    h512 = _frac_bits(lambda p: _iroot(p << 128, 2), 8, 64)
    sigs.append(('SHA-512/384 init', 'SHA-512', _words_be(h512, 8), 'sqrt 前 8 素数的 64 位小数部分'))
    rc = _keccak_rc()
    sigs.append(('Keccak/SHA-3 round constants', 'SHA-3', _words_le(rc[:4], 8), 'rc(t) LFSR 生成的前 4 个轮常量（小端）'))
    sigs.append(('ChaCha/Salsa "expand 32-byte k"', 'ChaCha20', [ord(c) for c in 'expand 32-byte k'], 'ChaCha/Salsa20 状态常量（ASCII）'))
    sigs.append(('ChaCha/Salsa "expand 16-byte k"', 'ChaCha20', [ord(c) for c in 'expand 16-byte k'], '128 位密钥版本的同一常量'))
    sigs.append(('Base64 alphabet', 'encoding', [ord(c) for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'], '标准 Base64 字母表（ASCII）'))
    sigs.append(('Base64 URL-safe alphabet', 'encoding', [ord(c) for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'], 'URL-safe Base64 字母表（ASCII）'))
    sigs.append(('Blowfish P-array', 'Blowfish', [0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3], 'pi 的十六进制小数前 8 字节'))
    for nm, val in (('Curve25519 prime', (1 << 255) - 19),
                    ('secp256k1 prime', (1 << 256) - (1 << 32) - 977),
                    ('P-256 prime', (1 << 256) - (1 << 224) + (1 << 192) + (1 << 96) - 1)):
        sigs.append((nm, 'ECC', _words_be([val], 32), '椭圆曲线素域模数（大端 32 字节）'))
    return sigs
# ==== BATCH4-CONSTS-END ====


_CRYPTO_SIGS = None


def _crypto_signature_list():
    global _CRYPTO_SIGS
    if _CRYPTO_SIGS is None:
        _CRYPTO_SIGS = _crypto_signatures()
    return _CRYPTO_SIGS


def _containing_function_name(addr):
    try:
        f = _function_at(addr)
        return str(f.getName()) if f is not None else None
    except Exception:
        return None


def _scan_signature_bytes(sig, limit, block_filter, monitor):
    """在已初始化内存里找一段**精确**字节序列的全部出现位置（最多 limit 个）。"""
    mem = currentProgram.getMemory()
    jb = _signed_bytes(sig)
    jm = _signed_bytes([0xFF] * len(sig))
    hits = []
    for blk in mem.getBlocks():
        if not blk.isInitialized():
            continue
        if block_filter and block_filter.lower() not in str(blk.getName()).lower():
            continue
        cur = blk.getStart()
        end = blk.getEnd()
        while len(hits) < limit:
            hit = mem.findBytes(cur, end, jb, jm, True, monitor)
            if hit is None:
                break
            hits.append((hit, str(blk.getName())))
            cur = hit.add(1)
        if len(hits) >= limit:
            break
    return hits


def op_detect_crypto_constants(obj):
    """按**已知常量签名**找加密实现：AES S-box、CRC 表、MD5/SHA 家族常量、Keccak 轮常量、
    ChaCha/Salsa 魔数、Base64 字母表、椭圆曲线模数。全部签名运行时算出（见 kat-consts.py）。
    命中是「这里有一张已知的表」，不等于「这段代码在加密数据」——表也可能来自库或编译器。"""
    flt = str(obj.get('filter') or '').lower()
    bflt = str(obj.get('blockFilter') or '')
    limit = int(obj.get('limit') or 8)
    if limit > 64:
        limit = 64
    if limit < 1:
        limit = 1
    mon = _monitor()
    sigs = _crypto_signature_list()
    rows = []
    used = 0
    truncated = False
    for name, algo, sig, note in sigs:
        if flt and flt not in (name + ' ' + algo + ' ' + note).lower():
            continue
        used += 1
        hits = _scan_signature_bytes(sig, limit, bflt, mon)
        if len(hits) >= limit:
            truncated = True
        for addr, blkname in hits:
            row = {'constant': name, 'algorithm': algo, 'address': str(addr),
                   'block': blkname, 'length': len(sig), 'note': note}
            fn = _containing_function_name(addr)
            if fn:
                row['function'] = fn
            rows.append(row)
    return {'list': rows, 'total': len(rows), 'signaturesScanned': used,
            'signaturesAvailable': len(sigs), 'truncated': truncated}


def _behavior_table():
    """(分类, 严重度, [API 名…])。名字是 Windows 导出名；Linux/Android 名字留待后续批次。"""
    return [
        ('process-injection', 'high', [
            'VirtualAllocEx', 'VirtualAllocExNuma', 'WriteProcessMemory', 'CreateRemoteThread',
            'CreateRemoteThreadEx', 'NtCreateThreadEx', 'RtlCreateUserThread', 'QueueUserAPC',
            'NtQueueApcThread', 'SetThreadContext', 'Wow64SetThreadContext', 'NtUnmapViewOfSection',
            'ZwUnmapViewOfSection', 'ZwMapViewOfSection', 'NtMapViewOfSection', 'SetWindowsHookExA',
            'SetWindowsHookExW', 'NtWriteVirtualMemory']),
        ('execution', 'medium', [
            'CreateProcessA', 'CreateProcessW', 'CreateProcessAsUserA', 'WinExec', 'ShellExecuteA',
            'ShellExecuteW', 'ShellExecuteExA', 'system', 'popen', 'LoadLibraryA', 'LoadLibraryW',
            'LoadLibraryExA', 'GetProcAddress', 'CreateThread', '_beginthreadex', 'CreateProcessWithLogonW']),
        ('persistence', 'high', [
            'RegCreateKeyExA', 'RegCreateKeyExW', 'RegSetValueExA', 'RegSetValueExW', 'RegOpenKeyExA',
            'RegOpenKeyExW', 'RegDeleteValueA', 'CreateServiceA', 'CreateServiceW', 'StartServiceA',
            'StartServiceW', 'ChangeServiceConfigA', 'OpenSCManagerA', 'SchTasks', 'CreateScheduledTask',
            'NetScheduleJobAdd', 'InitiateSystemShutdownA']),
        ('credential-access', 'high', [
            'CredReadA', 'CredReadW', 'CredEnumerateA', 'CredEnumerateW', 'CryptUnprotectData',
            'LsaEnumerateLogonSessions', 'LsaRetrievePrivateData', 'SamQueryInformationUser',
            'MiniDumpWriteDump', 'LogonUserA', 'LogonUserW', 'WNetGetUserA', 'CredUIPromptForCredentialsA']),
        ('c2-network', 'high', [
            'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW', 'HttpOpenRequestA',
            'HttpOpenRequestW', 'HttpSendRequestA', 'HttpSendRequestW', 'InternetReadFile',
            'InternetWriteFile', 'URLDownloadToFileA', 'URLDownloadToFileW', 'WinHttpOpen',
            'WinHttpConnect', 'WinHttpSendRequest', 'WinHttpReceiveResponse', 'WinHttpReadData',
            'WSAStartup', 'WSASocketA', 'getaddrinfo', 'gethostbyname', 'inet_addr', 'inet_ntoa',
            'socket', 'connect', 'send', 'recv', 'sendto', 'recvfrom', 'bind', 'listen', 'accept',
            'DnsQuery_A', 'DNSQuery']),
        ('evasion-anti-debug', 'high', [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
            'ZwQueryInformationProcess', 'NtSetInformationThread', 'NtQuerySystemInformation',
            'OutputDebugStringA', 'OutputDebugStringW', 'DebugActiveProcess', 'GetTickCount',
            'GetTickCount64', 'QueryPerformanceCounter', 'timeGetTime', 'GetSystemTimeAsFileTime',
            'Sleep', 'SleepEx', 'NtDelayExecution', 'GetSystemInfo', 'GlobalMemoryStatusEx',
            'FindWindowA', 'FindWindowW', 'GetForegroundWindow', 'EnumWindows', 'BlockInput',
            'SetUnhandledExceptionFilter', 'VirtualProtect', 'VirtualProtectEx']),
        ('cryptography', 'medium', [
            'CryptAcquireContextA', 'CryptAcquireContextW', 'CryptEncrypt', 'CryptDecrypt',
            'CryptGenKey', 'CryptDeriveKey', 'CryptCreateHash', 'CryptHashData', 'CryptStringToBinaryA',
            'CryptBinaryToStringA', 'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenerateSymmetricKey',
            'BCryptOpenAlgorithmProvider', 'BCryptHashData', 'RtlEncryptMemory', 'CryptGenRandom',
            'SystemFunction032', 'SystemFunction041']),
        ('collection-exfiltration', 'medium', [
            'GetComputerNameA', 'GetComputerNameW', 'GetUserNameA', 'GetUserNameW',
            'GetVolumeInformationA', 'GetAdaptersInfo', 'GetHostName', 'gethostname', 'NetUserEnum',
            'NetShareEnum', 'GetKeyboardState', 'GetAsyncKeyState', 'GetKeyState', 'GetClipboardData',
            'RegisterHotKey', 'GetDC', 'BitBlt', 'CreateCompatibleDC', 'GetWindowDC', 'EnumProcesses']),
        ('file-registry-ops', 'low', [
            'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile', 'DeleteFileA', 'DeleteFileW',
            'MoveFileA', 'MoveFileW', 'CopyFileA', 'CopyFileW', 'FindFirstFileA', 'FindFirstFileW',
            'GetTempPathA', 'GetTempPathW', 'SetFileAttributesA', 'GetWindowsDirectoryA',
            'GetSystemDirectoryA', 'SHGetFolderPathA']),
        ('privilege-escalation', 'high', [
            'AdjustTokenPrivileges', 'OpenProcessToken', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW',
            'ImpersonateLoggedOnUser', 'SetTokenInformation', 'DuplicateTokenEx', 'NtSetInformationToken',
            'OpenProcess', 'OpenThread', 'ZwOpenProcess']),
    ]


def _name_indexes(cap=400000):
    """(外部符号, 函数) 的小写名 → 地址字符串。"""
    ext = {}
    n = 0
    try:
        it = currentProgram.getSymbolTable().getExternalSymbols()
    except Exception:
        it = None
    if it is not None:
        while it.hasNext() and n < cap:
            n += 1
            try:
                s = it.next()
                ext.setdefault(str(s.getName()).lower(), str(s.getAddress()))
            except Exception:
                pass
    funcs = {}
    n = 0
    fit = currentProgram.getFunctionManager().getFunctions(True)
    while fit.hasNext() and n < cap:
        n += 1
        try:
            f = fit.next()
            funcs.setdefault(str(f.getName()).lower(), str(f.getEntryPoint()))
        except Exception:
            pass
    return ext, funcs


def _defined_string_rows(minlen=4, cap=50000):
    rows = []
    for d, s in _string_data_rows(minlen, cap):
        try:
            rows.append((str(d.getAddress()), s))
        except Exception:
            pass
    return rows


def _boundary_regex(names):
    """API 名的词边界匹配：`(?<![A-Za-z0-9]) name (?![A-Za-z0-9])`。
    既避免 connect 命中 connection、system 命中 filesystem，又允许 _CreateProcessW@40 这种修饰名。"""
    uniq = []
    for nm in names:
        low = nm.lower()
        if low not in uniq:
            uniq.append(low)
    uniq.sort(key=len, reverse=True)
    body = '|'.join(re.escape(x) for x in uniq)
    return re.compile('(?<![A-Za-z0-9])(?:' + body + ')(?![A-Za-z0-9])', re.IGNORECASE)


def _string_matches_for(rx, minlen=4, cap=50000):
    """一次扫描所有已定义字符串，返回 {小写名: (地址, 原文摘要)}（每个名字只留第一条证据）。"""
    hits = {}
    for saddr, text in _defined_string_rows(minlen, cap):
        for m in rx.finditer(text):
            k = m.group(0).lower()
            if k not in hits:
                hits[k] = (saddr, text[:200])
    return hits


def op_detect_malware_behaviors(obj):
    """按「API 名 × 行为分类」扫导入表/函数名/已定义字符串，给出带来源的证据清单。
    这是**行为线索**而不是判决：同一个 VirtualAllocEx 在调试器、注入器、游戏外挂里都会出现。"""
    want = obj.get('categories')
    if isinstance(want, str):
        want = [x.strip().lower() for x in want.split(',') if x.strip()]
    elif want:
        want = [str(x).strip().lower() for x in want]
    limit = int(obj.get('limit') or 200)
    if limit > 1000:
        limit = 1000
    table = _behavior_table()
    if want:
        table = [t for t in table if t[0].lower() in want]
    ext, funcs = _name_indexes()
    allnames = []
    for cat, sev, apis in table:
        allnames.extend(apis)
    rx = _boundary_regex(allnames)
    shits = _string_matches_for(rx)
    cats = []
    found_total = 0
    sev_count = {'high': 0, 'medium': 0, 'low': 0}
    for cat, sev, apis in table:
        rows = []
        for api in apis:
            low = api.lower()
            sources = []
            addr = None
            where = None
            if low in ext:
                sources.append('import')
                addr = ext[low]
            if low in funcs:
                sources.append('function')
                if addr is None:
                    addr = funcs[low]
            if low in shits:
                sources.append('string')
                if addr is None:
                    addr = shits[low][0]
                where = shits[low][1]
            if not sources:
                continue
            row = {'api': api, 'sources': sources}
            if addr:
                row['address'] = addr
                fn = _containing_function_name(_safe_addr(addr))
                if fn:
                    row['function'] = fn
            if where:
                row['string'] = where
            rows.append(row)
        if rows:
            sev_count[sev] = sev_count.get(sev, 0) + 1
            found_total += len(rows)
            cats.append({'category': cat, 'severity': sev,
                         'found': len(rows), 'apis': rows[:limit]})
    return {'categories': cats, 'categoriesFound': len(cats),
            'categoriesScanned': len(table), 'apisFound': found_total,
            'severityCounts': sev_count,
            'note': '行为线索，不是判决：每条都请回读地址处的上下文。'}


def _safe_addr(s):
    try:
        return resolve_address(str(s))
    except Exception:
        return None


_IOC_TYPES = [
    # 前后都加 [\d.] 边界：否则 "1.3.6.1.4.1.311.21.4" 这类 OID 会被切出
    # "3.6.1.4" 之类的假 IPv4（certutil.exe 实测：80 条里 59 条是这种切片）。
    ('ipv4', r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])'),
    # 点分十进制里的 OID（2.5.29.14 这种没法从形式上与 IPv4 区分，按 ITU-T 首弧规则归类）
    ('oid', r'(?<![\d.])\d+(?:\.\d+){2,}(?![\d.])'),
    ('ipv6', r'(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}'),
    # %ws://%ws/ct/v1/%ws 这种 printf 模板不是 URL，故排除前置的 %
    ('url', r'(?<![A-Za-z0-9_%])(?:https?|ftps?|wss?|tcp|udp)://[^\s"\'<>\]]{3,}'),
    ('email', r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,12}'),
    ('domain', r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|uk|de|fr|nl|br|in|jp|kr|us|cc|me|site|online|club|shop|app|dev|gov|edu|mil|pw|su|tk|ml|ga|cf|gq|icu|rest|fun|live|pro|link|click|download|stream|host|space|website|tech|store|press|wiki|work|zone)\b'),
    ('registry', r'(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]{2,})[\\][^\s"\'|]{2,}'),
    ('winpath', r'[A-Za-z]:\\[^\s"\'|*?<>]{2,}'),
    ('uncpath', r'\\\\[A-Za-z0-9._-]{2,}\\[^\s"\'|]{0,}'),
    ('unixpath', r'/(?:etc|tmp|var|usr|home|opt|dev|proc|root|sbin|bin)/[^\s"\'|]{2,}'),
    ('mutex', r'(?:Global|Local|Session)\\[^\s"\'|]{2,}'),
    ('btc', r'\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'),
    ('eth', r'\b0x[a-fA-F0-9]{40}\b'),
    ('md5', r'\b[a-fA-F0-9]{32}\b'),
    ('sha1', r'\b[a-fA-F0-9]{40}\b'),
    ('sha256', r'\b[a-fA-F0-9]{64}\b'),
    ('guid', r'\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b'),
]


def _ioc_regexes(types):
    out = []
    for name, pat in _IOC_TYPES:
        if types and name not in types:
            continue
        out.append((name, re.compile(pat)))
    return out


def _looks_like_oid(value):
    """点分十进制串是 OID 还是 IPv4 —— 形式上无法区分，用 ITU-T 的弧取值规则判定：
    第一弧 ∈{0,1,2} 且第二弧 ≤39 即合法的 OID 起始，判为 OID。
    代价：1.x/2.x 且第二段 ≤39 的真实地址会被归到 oid（仍出现在结果里，只是类型不同）；
    收益：证书类样本里成百上千条 OID 表项不再淹没 ipv4 通道（certutil.exe 实测 59→0）。
    段数 >4 的点分串一定不是 IPv4。"""
    parts = value.split('.')
    if len(parts) < 4:
        return False
    if len(parts) > 4:
        return True
    try:
        first = int(parts[0])
        second = int(parts[1])
    except Exception:
        return False
    return first <= 2 and second <= 39


def _ioc_ok(kind, value):
    """逐类型的额外校验：正则只是粗筛。"""
    if kind == 'ipv4':
        parts = value.split('.')
        if len(parts) != 4:
            return False
        for p in parts:
            if not p.isdigit() or int(p) > 255:
                return False
            if len(p) > 1 and p[0] == '0':
                return False
        if value.startswith('0.') or value == '0.0.0.0' or value.startswith('255.255.255'):
            return False
        if _looks_like_oid(value):
            return False
        return True
    if kind == 'oid':
        return _looks_like_oid(value)
    if kind == 'ipv6':
        return value.count(':') >= 2 and ':::' not in value
    if kind == 'domain':
        low = value.lower()
        if re.match(r'^[\d.]+$', low):
            return False
        for bad in ('.dll', '.exe', '.sys', '.dat', '.tmp'):
            if low.endswith(bad):
                return False
        return True
    if kind == 'md5' or kind == 'sha1' or kind == 'sha256':
        low = value.lower()
        if low.strip('0') == '' or low.strip('f') == '':
            return False
        return True
    return True


def _raw_printable_rows(minlen, max_bytes, chunk=262144):
    """原始内存里的可打印 ASCII 串（含未定义数据）——用于抓没有交叉引用的 IOC。
    返回 (rows, bytes_read, blocks_seen, blocks_read)：后两个用来在「一个字节都没读到」时
    把话说清楚，而不是静默返回空结果（补丁 11 的教训）。"""
    mem = currentProgram.getMemory()
    rows = []
    total = 0
    seen = 0
    read = 0
    for blk in mem.getBlocks():
        if not blk.isInitialized():
            continue
        seen += 1
        if total >= max_bytes:
            break
        length = _range_len(blk)
        if length <= 0:
            continue
        read += 1
        off = 0
        text = ''
        text_start = None
        while off < length and total < max_bytes:
            # max_bytes 是硬上限：最后一次读也按剩余额度裁剪，不会因为「整块读」而超出额度。
            n = int(min(chunk, length - off, max_bytes - total))
            base = blk.getStart().add(off)
            raw = _read_bytes(base, n)
            for i in range(len(raw)):
                b = int(raw[i]) & 0xFF
                if 32 <= b < 127:
                    if not text:
                        text_start = base.add(i)
                    text += chr(b)
                else:
                    if len(text) >= minlen:
                        rows.append((str(text_start), text))
                    text = ''
                    text_start = None
            total += len(raw)
            off += n
        if len(text) >= minlen:
            rows.append((str(text_start), text))
    return rows, total, seen, read


def op_extract_iocs_with_context(obj):
    """从已定义字符串（可选再加原始内存）里抽 IOC：IP/域名/URL/邮箱/注册表键/路径/
    互斥体/钱包地址/哈希/GUID。每条给出来源地址、所在函数、原文；同值只留首条并计数。
    includeRawMemory=true 会扫未定义数据（更全，但慢且噪音多），扫描量由 maxBytes 限。"""
    types = obj.get('types')
    if isinstance(types, str):
        types = [x.strip().lower() for x in types.split(',') if x.strip()]
    elif types:
        types = [str(x).strip().lower() for x in types]
    minlen = int(obj.get('minLength') or 4)
    maxn = int(obj.get('max') or 500)
    if maxn > 5000:
        maxn = 5000
    rxs = _ioc_regexes(types)
    known = [x[0] for x in _IOC_TYPES]
    bad = [t for t in (types or []) if t not in known]
    if bad:
        raise Exception('ioc: 未知类型 ' + ', '.join(bad) + '（可用：' + ', '.join(known) + '）')
    sources = []
    for saddr, text in _defined_string_rows(minlen, 50000):
        sources.append(('string', saddr, text))
    bytes_scanned = 0
    raw_blocks = 0
    if obj.get('includeRawMemory'):
        max_bytes = int(obj.get('maxBytes') or (4 * 1024 * 1024))
        rows, bytes_scanned, raw_seen, raw_read = _raw_printable_rows(minlen, max_bytes)
        raw_blocks = raw_seen
        if bytes_scanned <= 0:
            raise Exception('ioc: includeRawMemory=true 但原始内存读了 0 字节'
                            '（初始化块 %d，可读块 %d）——扫描没生效，不是「没有 IOC」'
                            % (raw_seen, raw_read))
        for saddr, text in rows:
            sources.append(('memory', saddr, text))
    seen = {}
    order = []
    by_type = {}
    for src, saddr, text in sources:
        for kind, rx in rxs:
            for m in rx.finditer(text):
                val = m.group(0)
                if not _ioc_ok(kind, val):
                    continue
                key = kind + '\x00' + val
                if key in seen:
                    seen[key]['count'] += 1
                    continue
                row = {'type': kind, 'value': val, 'source': src, 'address': saddr,
                       'string': text[:200], 'count': 1}
                fn = _containing_function_name(_safe_addr(saddr))
                if fn:
                    row['function'] = fn
                seen[key] = row
                order.append(row)
                by_type[kind] = by_type.get(kind, 0) + 1
                if len(order) >= maxn:
                    break
            if len(order) >= maxn:
                break
        if len(order) >= maxn:
            break
    return {'list': order, 'total': len(order), 'byType': by_type,
            'typesScanned': [k for k, _ in rxs], 'stringsScanned': len(sources),
            'bytesScanned': bytes_scanned, 'rawBlocksScanned': raw_blocks,
            'truncated': len(order) >= maxn}


_ANTI_DEBUG_APIS = [
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
    'ZwQueryInformationProcess', 'NtSetInformationThread', 'NtQuerySystemInformation',
    'OutputDebugStringA', 'OutputDebugStringW', 'DebugActiveProcess', 'DebugBreak',
    'SetUnhandledExceptionFilter', 'RaiseException', 'NtClose', 'CloseHandle',
]
_ANTI_VM_STRING_HINTS = [
    'VMware', 'VirtualBox', 'VBOX', 'VBoxService', 'VBoxTray', 'vboxguest', 'vmmouse',
    'vmci', 'vm3dservice', 'vmwareuser', 'vmwaretray', 'vmtoolsd', 'QEMU', 'qemu-ga',
    'Xen', 'xenservice', 'Sandboxie', 'SbieDll', 'SbieSvc', 'Cuckoo', 'cuckoomon',
    'Wine', 'wine_get_unix_file_name', 'sample.exe', 'malware.exe', 'sandbox',
]
_DEBUGGER_TOOL_HINTS = [
    'OllyDbg', 'ollydbg', 'x64dbg', 'x32dbg', 'IDA', 'WinDbg', 'windbg', 'gdb',
    'Wireshark', 'wireshark', 'Procmon', 'ProcessMonitor', 'ProcessHacker', 'procexp',
    'API Monitor', 'apimonitor', 'Fiddler', 'Burp', 'Charles', 'dbghelp', 'DbgUiRemoteBreakin',
    'Scylla', 'PE-bear', 'pestudio', 'PEiD', 'DetectItEasy', 'dnSpy', 'ILSpy',
]


def op_find_anti_analysis_techniques(obj):
    """反分析线索：反调试 API、反虚拟机/沙箱字符串、调试器/分析工具字符串、
    RDTSC/CPUID 指令数量（字节级扫描，0F 31 / 0F A2）。每条都是「有证据」而不是「确定在做反调试」；
    risk 只是把线索数压成一个便于排序的标签。"""
    maxn = int(obj.get('max') or 100)
    if maxn > 500:
        maxn = 500
    ext, funcs = _name_indexes()
    allnames = _ANTI_DEBUG_APIS + _ANTI_VM_STRING_HINTS + _DEBUGGER_TOOL_HINTS
    rx = _boundary_regex(allnames)
    shits = _string_matches_for(rx)
    indicators = []
    api_ev = []
    for api in _ANTI_DEBUG_APIS:
        low = api.lower()
        src = []
        if low in ext:
            src.append('import')
        if low in funcs:
            src.append('function')
        if low in shits:
            src.append('string')
        if src:
            ev = {'kind': 'api', 'value': api, 'sources': src}
            if low in ext:
                ev['address'] = ext[low]
            elif low in funcs:
                ev['address'] = funcs[low]
            elif low in shits:
                ev['address'] = shits[low][0]
            api_ev.append(ev)
    if api_ev:
        indicators.append({'name': 'anti-debug APIs', 'category': 'anti-debug',
                           'severity': 'high', 'count': len(api_ev),
                           'evidence': api_ev[:maxn]})
    vm_ev = []
    for hint in _ANTI_VM_STRING_HINTS:
        low = hint.lower()
        if low in shits:
            vm_ev.append({'kind': 'string', 'value': hint, 'address': shits[low][0],
                          'context': shits[low][1]})
    if vm_ev:
        indicators.append({'name': 'VM / sandbox artifacts', 'category': 'anti-vm',
                           'severity': 'high', 'count': len(vm_ev),
                           'evidence': vm_ev[:maxn]})
    dbg_ev = []
    for hint in _DEBUGGER_TOOL_HINTS:
        low = hint.lower()
        if low in shits:
            dbg_ev.append({'kind': 'string', 'value': hint, 'address': shits[low][0],
                           'context': shits[low][1]})
    if dbg_ev:
        indicators.append({'name': 'debugger / analysis tool artifacts', 'category': 'anti-analysis',
                           'severity': 'medium', 'count': len(dbg_ev),
                           'evidence': dbg_ev[:maxn]})
    mon = _monitor()
    counts = {}
    for label, pat in (('rdtsc', [0x0F, 0x31]), ('cpuid', [0x0F, 0xA2]), ('int3', [0xCC])):
        hits = _scan_signature_bytes(pat, 2000, None, mon)
        counts[label] = len(hits)
        if label == 'int3':
            continue
        if hits:
            ev = [{'kind': 'bytes', 'address': str(a), 'block': b} for a, b in hits[:maxn]]
            indicators.append({'name': label.upper() + ' instruction',
                               'category': 'timing' if label == 'rdtsc' else 'anti-vm',
                               'severity': 'medium', 'count': len(hits), 'evidence': ev})
    high = len([i for i in indicators if i['severity'] == 'high'])
    med = len([i for i in indicators if i['severity'] == 'medium'])
    risk = 'low'
    if high >= 2 or (high >= 1 and med >= 2):
        risk = 'high'
    elif high >= 1 or med >= 2:
        risk = 'medium'
    if 'rdtsc' in counts and counts['rdtsc'] > 0 and api_ev:
        indicators.append({'name': 'timing check plausible (RDTSC + debug/timing APIs)',
                           'category': 'timing', 'severity': 'medium', 'count': 1,
                           'evidence': [{'kind': 'heuristic', 'value': 'rdtsc + api hits'}]})
    return {'indicators': indicators, 'indicatorCount': len(indicators), 'risk': risk,
            'counts': counts,
            'note': '线索清单，不是判定：普通程序也会调用 GetTickCount 或含 "IDA" 字样。'}


_HANDLES = {
    'program': lambda: currentProgram,
    'symtab': lambda: currentProgram.getSymbolTable(),
    'fm': lambda: currentProgram.getFunctionManager(),
    'dtm': lambda: currentProgram.getDataTypeManager(),
    'tagmgr': lambda: currentProgram.getFunctionManager().getFunctionTagManager(),
    'listing': lambda: currentProgram.getListing(),
    'refmgr': lambda: currentProgram.getReferenceManager(),
    'mem': lambda: currentProgram.getMemory(),
    'analysis': lambda: _auto_analysis_manager(),
}


def op_probe(obj):
    """开发者诊断用（只走 socket，不注册 Node 工具）：反射 Java 类的方法/字段，
    或 dump 反编译器与 DB 两侧的变量名，用来在无法交互调试时确定真实 API。"""
    if obj.get('tx'):
        try:
            ti = currentProgram.getCurrentTransactionInfo()
        except Exception as e:
            ti = 'err: ' + str(e)
        out = {'tx': str(ti) if ti is not None else 'none',
               'changed': bool(currentProgram.isChanged())}
        try:
            out['openTx'] = [str(x) for x in currentProgram.getOpenTransactions()]
        except Exception as e:
            out['openTxErr'] = str(e)
        return out
    if obj.get('save'):
        addr = resolve_address(str(obj.get('addr') or '0x1400013c0'))
        out = {}
        try:
            out['pclass'] = str(currentProgram.getClass().getName())
        except Exception as e:
            out['pclass'] = 'err: ' + str(e)
        for label, fn in (
            ('progChanged', lambda: bool(currentProgram.isChanged())),
            ('domainChanged', lambda: bool(currentProgram.getDomainFile().isChanged())),
            ('domainPath', lambda: str(currentProgram.getDomainFile().getPathname())),
            ('comment', lambda: str(currentProgram.getComment(addr))),
            ('tx', lambda: str(currentProgram.getCurrentTransactionInfo())),
        ):
            try:
                out[label] = fn()
            except Exception as e:
                out[label] = 'err: ' + str(e)
        for meth in ('getChanges', 'getChangeSet', 'getTransactionManager'):
            try:
                v = getattr(currentProgram, meth)()
                try:
                    n = len(v)
                except Exception:
                    n = None
                out[meth] = (str(v) + (' len=' + str(n) if n is not None else ''))[:600]
            except Exception as e:
                out[meth] = 'err: ' + str(e)
        return out
    if obj.get('analysis'):
        out = {}
        keys = []
        try:
            from ghidra.program.model.listing import Program as _P
            keys.append(str(_P.ANALYSIS_PROPERTIES))
        except Exception as e:
            out['constErr'] = str(e)
        keys += ['Analysists', 'Analysis Options', 'Analysis']
        out['triedKeys'] = keys
        rows = []
        for k in keys:
            try:
                o = currentProgram.getOptions(k)
                names = [str(x) for x in o.getOptionNames()]
                rows.append({'key': k, 'count': len(names), 'first': names[:12]})
            except Exception as e:
                rows.append({'key': k, 'error': str(e)})
        out['options'] = rows
        try:
            o = currentProgram.getOptions(keys[0])
            sample = []
            for n in [str(x) for x in o.getOptionNames()][:20]:
                try:
                    sample.append({'name': n, 'enabled': bool(o.getBoolean(n, False)),
                                   'desc': str(o.getDescription(n))[:100]})
                except Exception as e:
                    sample.append({'name': n, 'err': str(e)})
            out['sample'] = sample
        except Exception as e:
            out['sampleErr'] = str(e)
        return out
    if obj.get('handles'):
        rows = []
        for k in sorted(_HANDLES):
            try:
                rows.append({'handle': k, 'class': str(_HANDLES[k]().getClass().getName())})
            except Exception as e:
                rows.append({'handle': k, 'error': str(e)})
        return {'handles': rows}
    key = str(obj.get('handle') or '')
    cls_name = str(obj.get('class') or '')
    match = str(obj.get('match') or '').lower()
    out = {}
    if key or cls_name:
        if key:
            h = _HANDLES.get(key)
            if h is None:
                raise Exception('probe: unknown handle ' + key)
            target_cls = h().getClass()
        else:
            from java.lang import Class
            target_cls = Class.forName(cls_name)
        methods = []
        try:
            for m in target_cls.getMethods():
                s = str(m.toString())
                if match and match not in s.lower():
                    continue
                methods.append(s)
        except Exception as e:
            methods.append('getMethods failed: ' + str(e))
        out = {'class': str(target_cls.getName()), 'methods': sorted(set(methods))}
        if obj.get('fields'):
            fields = []
            try:
                for fd in target_cls.getFields():
                    fields.append(str(fd.toString()))
            except Exception as e:
                fields.append('getFields failed: ' + str(e))
            out['fields'] = sorted(set(fields))
    elif not obj.get('locals'):
        raise Exception('probe: give handle= / class= / locals=')
    if obj.get('locals'):
        tgt = str(obj.get('locals'))
        f = _function_at(resolve_address(tgt))
        if f is None:
            raise Exception('probe: no function at ' + tgt)
        dbvars = []
        for v in f.getParameters():
            dbvars.append('param ' + str(v.getName()) + ' | ' + str(v.getDataType()))
        for v in f.getLocalVariables():
            dbvars.append('local ' + str(v.getName()) + ' | ' + str(v.getDataType()))
        out['db_vars'] = dbvars
        from ghidra.app.decompiler import DecompInterface
        di = DecompInterface()
        try:
            di.openProgram(currentProgram)
            res = di.decompileFunction(f, 60, _monitor())
            hf = res.getHighFunction() if res is not None else None
            names = []
            if hf is not None:
                for s in _take(hf.getLocalSymbolMap().getSymbols(), 4000):
                    try:
                        names.append(str(s.getName()) + ' | ' + str(s.getStorage()))
                    except Exception:
                        names.append(str(s.getName()))
            out['decompiler_vars'] = names
        finally:
            di.dispose()
    return out


# ---- 统一模式（unified）：把上游 GhidraMCP 的 226 个 REST 端点拉进**本 JVM** ----
# 上游扩展 jar（GhidraMCP-7.0.0.jar）装在用户扩展目录
#   %APPDATA%\ghidra\ghidra_<ver>_PUBLIC\Extensions\GhidraMCP\lib\
# 因此任何用同一用户目录启动的 Ghidra（含本 PyGhidra JVM）都在 classpath 上看得见它。
# HeadlessProgramProvider.setCurrentProgram(Program) 允许把**本桥已打开的同一个程序**
# 交给 REST 层 —— 于是 47 个原生工具与 168 个 REST 工具作用于同一程序、同一 JVM，
# 不再需要第二个 Ghidra 进程（省一份 JVM 内存，且两边状态不再分叉）。
# launch() 会阻塞在 keep-alive 循环里，所以必须跑在 daemon 线程上。
_mcp_server = None
_mcp_lock = threading.Lock()


def _mcp_port():
    try:
        return int(_mcp_server.getPort()) if _mcp_server is not None else None
    except Exception:
        return None


def _sync_mcp_program():
    """把本桥当前程序绑给 REST 层（切程序后重新调用即可保持一致）。"""
    if _mcp_server is None:
        return False
    prov = _mcp_server.getProgramProvider()
    if prov is None:
        return False
    prov.setCurrentProgram(currentProgram)
    try:
        if prov.getProject() is None:
            prov.setProject(currentProject)
    except Exception:
        pass
    return True


def op_mcp_serve(obj):
    """在本 JVM 内启动上游 GhidraMCP REST 服务器并绑定当前程序（统一模式）。"""
    global _mcp_server
    port = int(obj.get('port') or 8123)
    bind = str(obj.get('bind') or '127.0.0.1')
    with _mcp_lock:
        if _mcp_server is not None:
            try:
                if _mcp_server.isRunning():
                    _sync_mcp_program()
                    return {'ok': True, 'running': True, 'port': _mcp_port(), 'reused': True,
                            'mode': 'unified', 'program': currentProgram.getName(), 'pid': server_pid()}
            except Exception:
                pass
            _mcp_server = None
        from com.xebyte.headless import GhidraMCPHeadlessServer
        from ghidra import GhidraApplicationLayout
        srv = GhidraMCPHeadlessServer()
        holder = {}

        def boot():
            try:
                srv.launch(GhidraApplicationLayout(), ['--port', str(port), '--bind', bind])
            except Exception as e:  # keep-alive 循环退出/启动失败
                holder['error'] = str(e)

        t = threading.Thread(target=boot, daemon=True)
        t.start()
        deadline = time.time() + 45
        while time.time() < deadline:
            if 'error' in holder:
                raise RuntimeError('MCP launch failed: ' + holder['error'])
            try:
                if srv.isRunning():
                    break
            except Exception:
                pass
            time.sleep(0.25)
        try:
            ready = bool(srv.isRunning())
        except Exception:
            ready = False
        if not ready:
            raise RuntimeError('MCP server did not become ready within 45s (port %d)' % port)
        _mcp_server = srv
        _sync_mcp_program()
        return {'ok': True, 'running': True, 'port': _mcp_port(), 'reused': False,
                'mode': 'unified', 'program': currentProgram.getName(), 'pid': server_pid()}


def op_mcp_stop(obj):
    global _mcp_server
    with _mcp_lock:
        if _mcp_server is None:
            return {'ok': True, 'running': False, 'note': 'in-process MCP server not started'}
        srv = _mcp_server
        _mcp_server = None
    try:
        srv.stop()
    except Exception as e:
        return {'ok': True, 'running': False, 'note': 'stop() raised: ' + str(e)}
    return {'ok': True, 'running': False}


def op_mcp_state(obj):
    if _mcp_server is None:
        return {'running': False, 'mode': 'unified', 'note': 'in-process MCP server not started'}
    try:
        running = bool(_mcp_server.isRunning())
    except Exception:
        running = False
    return {'running': running, 'port': _mcp_port(), 'mode': 'unified',
            'program': currentProgram.getName(), 'pid': server_pid()}


OPS = {
    'info': op_info,
    'functions': op_functions,
    'decompile': op_decompile,
    'strings': op_strings,
    'xrefs': op_xrefs,
    'segments': op_segments,
    'imports': op_imports,
    'exports': op_exports,
    'searchStrings': op_search_strings,
    'searchFunctions': op_search_functions,
    'calls': op_calls,
    'callGraph': op_call_graph,
    'readMemory': op_read_memory,
    'disassemble': op_disassemble,
    'variables': op_variables,
    'pcode': op_pcode,
    'getComments': op_get_comments,
    'setComment': op_set_comment,
    'rename': op_rename,
    'labels': op_labels,
    'setPrototype': op_set_prototype,
    'setVariables': op_set_variables,
    'createFunction': op_create_function,
    'deleteFunction': op_delete_function,
    'save': op_save,
    'tags': op_tags,
    'probe': op_probe,
    'analyzers': op_analyzers,
    'analyzerConfig': op_analyzer_configure,
    'runAnalysis': op_run_analysis,
    'reanalyze': op_reanalyze,
    'searchBytes': op_search_bytes,
    'codeGaps': op_code_gaps,
    'deadCode': op_dead_code,
    'runScriptInline': op_run_script_inline,
    'runScript': op_run_script,
    'functionContext': op_function_context,
    'searchInstructions': op_search_instructions,
    'hash': op_hash,
    'compareFunctions': op_compare_functions,
    'dataFlow': op_data_flow,
    'detectCrypto': op_detect_crypto_constants,
    'malwareBehaviors': op_detect_malware_behaviors,
    'extractIocs': op_extract_iocs_with_context,
    'antiAnalysis': op_find_anti_analysis_techniques,
    # 统一模式（本 JVM 内跑上游 REST 服务器，与原生工具共用同一程序）
    'mcpServe': op_mcp_serve,
    'mcpStop': op_mcp_stop,
    'mcpState': op_mcp_state,
    'ping': lambda obj: {'pong': True},
    # 注意：main() 的退出判据是响应里出现字面量 "shutdown"，
    # 这里必须回 {'shutdown': True}；回别的（如 {'bye': True}）会让发送循环永不退出，
    # 于是 Node 侧只能强杀 JVM，headless 永远没有机会把改动落盘。
    'shutdown': lambda obj: {'shutdown': True},
}


def handle(line):
    try:
        obj = json.loads(line)
        op = obj.get('op')
        if op is None:
            return json.dumps({'ok': False, 'error': 'missing op'})
        handler = OPS.get(op)
        if handler is None:
            return json.dumps({'ok': False, 'error': 'unknown op: ' + str(op)})
        result = handler(obj)
        return json.dumps({'ok': True, 'result': result})
    except Exception as e:
        return json.dumps({'ok': False, 'error': str(e)})


def main():
    args = list(sys.argv)[1:]
    portFile = args[0] if len(args) > 0 else ''
    logFile = args[1] if len(args) > 1 else ''
    server = ServerSocket(0, 8, InetAddress.getLoopbackAddress())
    port = server.getLocalPort()
    if portFile:
        f = open(portFile, 'w')
        # "<port> <pid>"：pid 让 Node 侧能整树清理真正的 JVM
        f.write(str(port) + ' ' + str(server_pid()))
        f.close()
    log('listening port=%d program=%s' % (port, currentProgram.getName()), logFile)
    while True:
        sock = None
        try:
            sock = server.accept()
            sock.setSoTimeout(120000)
            reader = BufferedReader(InputStreamReader(sock.getInputStream(), 'UTF-8'))
            writer = PrintWriter(OutputStreamWriter(sock.getOutputStream(), 'UTF-8'), True)
            line = reader.readLine()
            while line is not None:
                resp = handle(line)
                writer.println(resp)
                writer.flush()
                if '"shutdown"' in resp:
                    server.close()
                    log('shutdown', logFile)
                    return
                line = reader.readLine()
        except Exception as e:
            log('conn error: ' + str(e), logFile)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


main()
