"""Extract all @McpTool endpoints from the upstream ghidra-mcp Java sources.

Scans upstream-src/**/*.java, parses each @McpTool(...) annotation (paren
matching, multi-line safe), the following method signature, and every @Param
inside it. Writes UPSTREAM-TOOLS.json (machine) and prints a summary.
"""
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "upstream-src")


def match_parens(text, open_idx):
    """Given index of '(', return index of matching ')' or -1."""
    depth = 0
    i = open_idx
    in_str = None
    while i < len(text):
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
        elif c in "\"'":
            in_str = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def parse_annotation(body):
    """Parse the inside of @McpTool(...) -> dict of named args."""
    out = {}
    # named args: name = "value" possibly with arrays {..}
    for m in re.finditer(r'(\w+)\s*=\s*("(?:[^"\\]|\\.)*"|\{[^}]*\}|[\w.]+)', body):
        out[m.group(1)] = unquote(m.group(2))
    return out


def parse_params(param_list):
    """Parse a Java parameter list, honoring @Param annotations."""
    params = []
    if not param_list.strip():
        return params
    # Split top-level commas (respect parens/brackets/strings)
    parts, depth, cur, in_str = [], 0, "", None
    i = 0
    while i < len(param_list):
        c = param_list[i]
        if in_str:
            if c == "\\":
                cur += param_list[i : i + 2]
                i += 2
                continue
            cur += c
            if c == in_str:
                in_str = None
        elif c in "\"'":
            in_str = c
            cur += c
        elif c in "([{":
            depth += 1
            cur += c
        elif c in ")]}":
            depth -= 1
            cur += c
        elif c == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    if cur.strip():
        parts.append(cur)

    for part in parts:
        p = {"name": None, "type": None, "defaultValue": None,
             "description": "", "paramType": "", "aliases": [],
             "source": "QUERY", "fieldsJson": False, "allowEmpty": False}
        pm = re.search(r"@Param\s*\(", part)
        # java type = last identifier before the param name
        # strip @Param(...) blocks first for type detection
        stripped = re.sub(r"@Param\s*\((?:[^()]|\([^()]*\))*\)", "", part).strip()
        toks = stripped.split()
        if len(toks) >= 2:
            p["type"] = toks[-2]
            p["name"] = toks[-1]
        elif len(toks) == 1:
            p["name"] = toks[-1]
        if pm:
            body_start = part.index("(", pm.start())
            body_end = match_parens(part, body_start)
            ann = parse_annotation(part[body_start + 1 : body_end])
            if "value" in ann:
                p["name"] = ann["value"]
            for k in ("defaultValue", "description", "paramType", "source"):
                if k in ann:
                    p[k] = ann[k]
            if "aliases" in ann:
                a = ann["aliases"]
                p["aliases"] = re.findall(r'"([^"]*)"', a) if a else []
            p["fieldsJson"] = "fieldsJson = true" in part or "fieldsJson=true" in part
            p["allowEmpty"] = "allowEmpty = true" in part or "allowEmpty=true" in part
        if p["name"]:
            params.append(p)
    return params


def main():
    tools = []
    for dirpath, _dirs, files in os.walk(ROOT):
        for fn in sorted(files):
            if not fn.endswith(".java"):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, ROOT).replace("\\", "/")
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for m in re.finditer(r"@McpTool\s*\(", text):
                open_idx = text.index("(", m.start())
                close_idx = match_parens(text, open_idx)
                if close_idx < 0:
                    print(f"!! unmatched @McpTool in {rel} @ {m.start()}", file=sys.stderr)
                    continue
                ann = parse_annotation(text[open_idx + 1 : close_idx])
                # method signature after the annotation
                rest = text[close_idx + 1 :]
                sig = re.match(
                    r"\s*(?:@\w+\s*\([^)]*\)\s*|\w+\s+)*?public\s+[\w<>\[\], .]+?\s+(\w+)\s*\(([^)]*)\)",
                    rest,
                )
                method_name, param_list = (sig.group(1), sig.group(2)) if sig else (None, "")
                tool = {
                    "file": rel,
                    "path": ann.get("path"),
                    "http_method": ann.get("method", "GET"),
                    "description": ann.get("description", ""),
                    "category": ann.get("category", ""),
                    "java_method": method_name,
                    "params": parse_params(param_list),
                }
                tools.append(tool)
    tools.sort(key=lambda t: (t["category"], t["path"] or ""))
    out_json = os.path.join(os.path.dirname(os.path.abspath(__file__)), "UPSTREAM-TOOLS.json")
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(tools, fh, indent=1, ensure_ascii=False)
    cats = {}
    for t in tools:
        cats[t["category"] or "(none)"] = cats.get(t["category"] or "(none)", 0) + 1
    print(f"total tools: {len(tools)}")
    for c in sorted(cats):
        print(f"  {c}: {cats[c]}")
    no_path = [t for t in tools if not t["path"]]
    if no_path:
        print(f"tools without path: {len(no_path)}")
    no_method = [t for t in tools if not t["java_method"]]
    if no_method:
        print(f"tools without java method: {len(no_method)}")
        for t in no_method[:10]:
            print(f"  {t['file']} {t['path']}")


if __name__ == "__main__":
    main()
