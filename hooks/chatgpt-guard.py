#!/usr/bin/env python3
"""PreToolUse guard: agents must reach ChatGPT only through `gpt-chat`.

Reads hook JSON from stdin. Blocks (exit 2) a shell tool call that combines a
browser/network tool (ego-browser, agent-browser, playwright, curl, osascript,
...) with chatgpt.com / chat.openai.com / auth.openai.com, unless the segment is
the `gpt-chat` script itself. Everything else is allowed (exit 0).
"""

import json
import os
import re
import sys

SHELL_TOOLS = {
    "bash",
    "shell",
    "shell_command",
    "exec_command",
    "functions.exec_command",
    "functions.exec",
    "exec",
    "run_shell_command",
    "terminal",
}
DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[\w-]+\.)*(?:chatgpt\.com|chat\.openai\.com|auth\.openai\.com)\b",
    re.I,
)
TOOL_RE = re.compile(
    r"(?:^|[\s;&|(`'\"=/])(?:ego-browser|agent-browser|playwright(?:-cli)?|puppeteer|curl|wget|osascript|"
    r"terminal-browser|pinchtab(?:-safe-wrapper\.sh)?|lightpanda|web-read\.py|chromium|chrome|"
    r"google-chrome|aside)(?=$|[\s;&|)`'\"])|(?:^|[;&|(]\s*)open\s",
    re.I,
)
SEP_CHARS = ";&|\n"
MAX_FILE = 1_000_000
BODY_MARK = "\x00"

REASON = (
    "chatgpt.com 직접 접근은 막혀 있습니다. `gpt-chat send|read|list|status` 를 사용하세요 "
    "(scripts/gpt-chat). / Direct access to chatgpt.com is blocked; "
    "use the `gpt-chat` CLI."
)


def get_command(data):
    ti = data.get("tool_input") or data.get("input") or {}
    if isinstance(ti, str):
        return ti
    for key in ("command", "cmd", "script"):
        v = ti.get(key)
        if isinstance(v, list):
            return " ".join(str(x) for x in v)
        if isinstance(v, str):
            return v
    return ""


def split_segments(cmd):
    """Quote-aware split on ; & | newline. Yields (segment, heredoc_delim_or_None)."""
    segs, buf, quote, i = [], [], None, 0
    while i < len(cmd):
        ch = cmd[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(cmd):
                i += 1
                buf.append(cmd[i])
            elif ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch == "\\" and i + 1 < len(cmd):
            buf.append(ch)
            i += 1
            buf.append(cmd[i])
        elif ch in SEP_CHARS:
            segs.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    segs.append("".join(buf))
    return [s for s in segs if s.strip()]


def is_gpt_chat(seg):
    toks = seg.strip().split()
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
        toks.pop(0)
    return bool(toks) and os.path.basename(toks[0].strip("'\"")) == "gpt-chat"


def fold_heredocs(cmd):
    """Attach each heredoc body to its command line so newline-splitting keeps them together.
    Bodies of gpt-chat heredocs are dropped (prompts may mention sites)."""
    lines, out, i = cmd.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        i += 1
        m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", line)
        if not m:
            out.append(line)
            continue
        body = []
        while i < len(lines) and lines[i].strip() != m.group(1):
            body.append(lines[i])
            i += 1
        i += 1  # delimiter line
        keep = (
            ""
            if is_gpt_chat(line.split("<<")[0])
            else BODY_MARK + re.sub(r"[;&|\\'\"]", " ", " ".join(body))
        )
        out.append(line + keep)
    return "\n".join(out)


def referenced_files(seg):
    files = re.findall(r"<\s*([^\s<>|;&]+)", seg)
    files += re.findall(r"file://(/[^\s'\"`)]+)", seg)
    files += [t for t in re.findall(r"[^\s'\"`]+\.(?:mjs|js|ts|py|sh)\b", seg)]
    return files


def file_mentions_domain(path):
    try:
        p = os.path.expanduser(path)
        if os.path.isfile(p) and os.path.getsize(p) <= MAX_FILE:
            with open(p, errors="ignore") as f:
                return bool(DOMAIN_RE.search(f.read()))
    except OSError:
        pass
    return False


def should_block(cmd):
    cmd = fold_heredocs(cmd)
    for seg in split_segments(cmd):
        if is_gpt_chat(seg):
            continue
        # Tool detection looks at the command line only; heredoc bodies are data
        # (e.g. `cat > doc.md <<EOF` mentioning a tool) unless the command itself is a tool.
        if not TOOL_RE.search(seg.split(BODY_MARK)[0]):
            continue
        seg = seg.replace(BODY_MARK, " ")
        if DOMAIN_RE.search(seg):
            return True
        if re.search(
            r"ego-browser|agent-browser|playwright|puppeteer", seg, re.I
        ) and any(file_mentions_domain(f) for f in referenced_files(seg)):
            return True
    return False


def main():
    try:
        data = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    name = str(data.get("tool_name") or "").lower()
    if name and name not in SHELL_TOOLS and not name.endswith("bash"):
        return 0
    if should_block(get_command(data)):
        print(REASON, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
