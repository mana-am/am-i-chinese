#!/usr/bin/env python3
"""
am-i-chinese — scan text/code for hidden-Unicode & homoglyph steganography.

Did your AI coding agent secretly tag you as a Chinese user? This checks — and audits
any text for the broader family of hidden-Unicode tampering.

Catches, in a single deterministic pass:
  • region-fingerprint tells (non-ASCII "apostrophe" look-alikes, YYYY/MM/DD date
    separators, Asia/Shanghai · Asia/Urumqi leakage) — the class of marker exposed
    in the 2026 Claude Code steganography incident;
  • general hidden text used for prompt-injection & tampering: zero-width chars,
    bidirectional controls (Trojan Source), the Unicode Tags block (invisible ASCII
    smuggling), variation selectors, mixed-script homoglyph identifiers, and
    look-alike whitespace.

Stdlib only. Python 3.8+. No network, no side effects — reads and reports.

Usage:
  python3 scan.py FILE ...            # scan files
  python3 scan.py DIR  ...            # walk a directory (text/code files)
  echo "text" | python3 scan.py -     # scan stdin
  python3 scan.py --env               # inspect local agent env (base-url, timezone)
  python3 scan.py --json FILE         # machine-readable output

Exit: 0 = clean · 1 = suspicious characters found · 2 = usage/error
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
import unicodedata

# ---------------------------------------------------------------------------
# Code-point tables
# ---------------------------------------------------------------------------

ZERO_WIDTH = {
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E,
    0x2061, 0x2062, 0x2063, 0x2064,
}
BIDI_CONTROL = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F}
# Unicode Tags block U+E0000..U+E007F — invisible; smuggles hidden ASCII payloads.
TAGS = set(range(0xE0000, 0xE0080))
VARIATION_SELECTORS = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))
NONSTANDARD_SPACE = {0x00A0, 0x2007, 0x202F, 0x205F, 0x3000, 0x1680} | set(range(0x2000, 0x200B))

# Look-alikes for the ASCII apostrophe U+0027. Any of these standing in for a plain
# ' is the exact tell used to covertly tag requests.
APOSTROPHE_HOMOGLYPHS = {
    0x2018, 0x2019, 0x201B, 0x02BC, 0x02B9, 0x02BB, 0x2032,
    0x055A, 0xFF07, 0xA78C, 0x00B4, 0x0374,
}

SEVERITY_RANK = {"info": 0, "warn": 1, "critical": 2}


def classify(cp: int):
    """Return (category, severity, why) for a single code point, or None."""
    if cp in ZERO_WIDTH:
        return ("zero_width", "critical",
                "零宽隐身字符 —— 肉眼看不见,专门用来夹带私货、把你的 token 从中间劈开")
    if cp in BIDI_CONTROL:
        return ("bidi_control", "critical",
                "双向控制符 —— 能把文字/代码偷偷倒着排(Trojan Source),你看到的和跑起来的是两回事")
    if cp in TAGS:
        return ("unicode_tag", "critical",
                "Unicode 隐形标签 —— 走私专用通道,零痕迹给你塞一整串看不见的 ASCII 指令")
    if cp in VARIATION_SELECTORS:
        return ("variation_selector", "warn",
                "变体选择符 —— 隐形的,能背着你偷运一段编码私货")
    if cp in APOSTROPHE_HOMOGLYPHS:
        return ("apostrophe_homoglyph", "warn",
                "山寨撇号(不是老实的 U+0027)—— 当年就是这玩意儿被拿去当“你是不是中国人”的暗号")
    if cp in NONSTANDARD_SPACE:
        return ("nonstandard_space", "info",
                "山寨空格(不是老实的 U+0020)—— 长得像空格,身份存疑")
    return None


def _script_of(ch: str):
    if ch.isascii():
        return "Latin" if ch.isalpha() else None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    if "FULLWIDTH" in name and ("LETTER" in name or "DIGIT" in name):
        return "Fullwidth"
    for s in ("CYRILLIC", "GREEK", "LATIN", "ARMENIAN"):
        if s in name:
            return s.capitalize()
    return None


def mixed_script_tokens(line: str):
    """Yield (col, token, offenders) for word tokens that mix Latin with a
    confusable script (Cyrillic/Greek/Fullwidth) — the homoglyph identifier trick."""
    for m in re.finditer(r"\w+", line, re.UNICODE):
        token = m.group(0)
        scripts = {}
        for i, ch in enumerate(token):
            s = _script_of(ch)
            if s:
                scripts.setdefault(s, []).append((i, ch))
        confusable = {"Cyrillic", "Greek", "Fullwidth"} & set(scripts)
        if "Latin" in scripts and confusable:
            offenders = [(m.start() + i, ch) for s in confusable for (i, ch) in scripts[s]]
            yield (m.start(), token, sorted(offenders))


def _char_name(ch: str) -> str:
    try:
        return unicodedata.name(ch)
    except ValueError:
        return "UNNAMED"


def _display(ch: str) -> str:
    cp = ord(ch)
    if cp in ZERO_WIDTH or cp in BIDI_CONTROL or cp in TAGS or cp in VARIATION_SELECTORS or ch.isspace():
        return f"<U+{cp:04X}>"
    return ch


def scan_text(text: str, path: str, fingerprint_ctx: bool = True):
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for col, ch in enumerate(line, 1):
            res = classify(ord(ch))
            if res:
                cat, sev, why = res
                findings.append({
                    "path": path, "line": lineno, "col": col,
                    "cp": f"U+{ord(ch):04X}", "char": _display(ch),
                    "name": _char_name(ch), "category": cat,
                    "severity": sev, "why": why,
                })
        for col, token, offenders in mixed_script_tokens(line):
            off = ", ".join(f"'{c}' U+{ord(c):04X}" for _, c in offenders)
            findings.append({
                "path": path, "line": lineno, "col": col + 1,
                "cp": "-", "char": token, "name": "MIXED-SCRIPT TOKEN",
                "category": "homoglyph_identifier", "severity": "warn",
                "why": f"混血标识符:拉丁字母里掺了同形字({off})—— 长得一模一样,来路不明",
            })

        if fingerprint_ctx:
            for m in re.finditer(r"\b\d{4}/\d{2}/\d{2}\b", line):
                findings.append({
                    "path": path, "line": lineno, "col": m.start() + 1,
                    "cp": "-", "char": m.group(0), "name": "DATE SEPARATOR '/'",
                    "category": "date_separator", "severity": "info",
                    "why": "日期用了 / 而不是 ISO 的 - —— 指纹暗号的另一半就藏在这刀口上",
                })
            for tz in ("Asia/Shanghai", "Asia/Urumqi"):
                idx = line.find(tz)
                if idx != -1:
                    findings.append({
                        "path": path, "line": lineno, "col": idx + 1,
                        "cp": "-", "char": tz, "name": "TIMEZONE LEAK",
                        "category": "timezone", "severity": "info",
                        "why": "时区暗号 —— 那套逻辑当年就死死盯着这个值看",
                    })
    return findings


# ---------------------------------------------------------------------------
# Local environment inspection (--env)
# ---------------------------------------------------------------------------

def _local_timezone() -> str:
    tz = os.environ.get("TZ")
    if tz:
        return tz
    try:
        link = os.readlink("/etc/localtime")
        if "zoneinfo/" in link:
            return link.split("zoneinfo/")[-1]
    except (OSError, ValueError):
        pass
    try:
        import time
        return "/".join(t for t in time.tzname if t) or "unknown"
    except Exception:
        return "unknown"


def inspect_env():
    lines = ["am-i-chinese —— 本机环境体检(它们当年就盯这几项)", "-" * 40]
    base = os.environ.get("ANTHROPIC_BASE_URL")
    if base:
        official = "api.anthropic.com" in base
        lines.append(f"ANTHROPIC_BASE_URL = {base}")
        lines.append("  → 非官方端点。当年那套隐藏逻辑,正是在 base-url 不是 api.anthropic.com 时才“开机”。"
                     if not official else "  → 官方端点,乖。")
    else:
        lines.append("ANTHROPIC_BASE_URL = (未设置)")
    tz = _local_timezone()
    flagged = tz in ("Asia/Shanghai", "Asia/Urumqi")
    lines.append(f"时区               = {tz}" + ("   ⚠ 就是这个值,当年被拿去对暗号" if flagged else ""))
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        if os.environ.get(var):
            lines.append(f"{var:<18} = {os.environ[var]}")
    if flagged:
        lines.append("")
        lines.append("结论:在它眼里,你大概率是个“中国人”。放轻松,这只是个 Unicode 而已。")
    return "\n".join(lines), (1 if flagged else 0)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

TEXT_EXT = {".md", ".txt", ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml",
            ".yml", ".toml", ".html", ".css", ".sh", ".go", ".rs", ".java", ".c",
            ".cpp", ".h", ".swift", ".rb", ".php", ".mdx", ".xml", ".env", ""}


def iter_paths(paths, follow_ext=True):
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                if any(part in (".git", "node_modules", ".venv") for part in root.split(os.sep)):
                    continue
                for f in files:
                    fp = os.path.join(root, f)
                    if not follow_ext or os.path.splitext(f)[1].lower() in TEXT_EXT:
                        yield fp
        else:
            yield p


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="am-i-chinese",
        description="查一查:你的 AI 是不是背着你,在文字里给你盖了个隐形戳。")
    ap.add_argument("paths", nargs="*", help="files or dirs to scan; use - for stdin")
    ap.add_argument("--env", action="store_true", help="inspect local agent environment instead of scanning text")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-fingerprint", action="store_true", help="skip date/timezone context checks")
    ap.add_argument("--min-severity", choices=["info", "warn", "critical"], default="info")
    args = ap.parse_args(argv)

    if args.env:
        report, code = inspect_env()
        print(report)
        return code

    if not args.paths:
        ap.print_help()
        return 2

    findings = []
    for p in iter_paths(args.paths):
        try:
            if p == "-":
                text, label = sys.stdin.read(), "<stdin>"
            else:
                with open(p, "r", encoding="utf-8", errors="surrogatepass") as fh:
                    text, label = fh.read(), p
        except (OSError, UnicodeError) as e:
            print(f"skip {p}: {e}", file=sys.stderr)
            continue
        findings.extend(scan_text(text, label, fingerprint_ctx=not args.no_fingerprint))

    floor = SEVERITY_RANK[args.min_severity]
    findings = [f for f in findings if SEVERITY_RANK[f["severity"]] >= floor]

    if args.json:
        print(json.dumps(findings, ensure_ascii=False, indent=2))
    else:
        if not findings:
            print("am-i-chinese:一身清白 —— 没揪出任何隐形字符或山寨同形字。\n"
                  "这段文字没背着你打小抄,你暂时是自由的。")
        else:
            icon = {"critical": "🔴", "warn": "🟠", "info": "🔵"}
            for f in sorted(findings, key=lambda x: (-SEVERITY_RANK[x["severity"]], x["path"], x["line"])):
                print(f"{icon[f['severity']]} {f['path']}:{f['line']}:{f['col']}  "
                      f"{f['cp']:<8} [{f['category']}]  {f['char']!r}  {f['name']}\n"
                      f"      {f['why']}")
            crit = sum(1 for f in findings if f["severity"] == "critical")
            warn = sum(1 for f in findings if f["severity"] == "warn")
            info = sum(1 for f in findings if f["severity"] == "info")
            print(f"\n共揪出 {len(findings)} 处可疑:🔴{crit} 红 · 🟠{warn} 橙 · 🔵{info} 蓝")
            if crit:
                print("红色那几个是隐形的,你刚才根本没看见 —— 这就是重点。")

    return 1 if any(SEVERITY_RANK[f["severity"]] >= 1 for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
