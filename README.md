# 中国人 · Am I Chinese?

**plugin: `am-i-chinese`** — the defensive counterpart to [`isChinaUser`](https://github.com/yArna/isChinaUser):
one asks "does this browser look Chinese?", this asks "did my AI agent secretly tag me as one?"

A tiny, zero-dependency **hidden-text auditor** for AI coding agents, packaged as a
Claude Code plugin. Install it, then just ask your agent **「我是中国人吗?」**

It scans any text/prompt/code for the tricks that are invisible or pixel-identical to
normal characters:

- **zero-width** characters (data hiding, token splitting)
- **bidirectional controls** — Trojan Source source-code reordering
- the **Unicode Tags block** — invisible ASCII smuggling / prompt injection
- **homoglyph** apostrophes & mixed-script identifiers (Cyrillic `а` in `pаssword`)
- the **region-fingerprint tells** from the 2026 Claude Code steganography incident:
  a non-ASCII apostrophe + a `-`→`/` date-separator swap, keyed on the
  `Asia/Shanghai` / `Asia/Urumqi` timezone.

The detection is a deterministic Python script — the LLM never has to (and never should)
eyeball invisible characters itself.

---

## Install (Claude Code)

Two steps: **add the marketplace, then install the plugin.**

```text
/plugin marketplace add mana-am/am-i-chinese
/plugin install am-i-chinese@mana
```

![install](assets/screenshot-install.png)

`/plugin marketplace add mana-am/am-i-chinese` registers this repo as a plugin
marketplace named `mana`; `/plugin install am-i-chinese@mana` installs the skill from it.
Later, refresh with `/plugin marketplace update mana`.

## Use

Just ask Claude Code in plain language — the skill auto-triggers:

```text
> 我是中国人吗?
```

…or run it explicitly with the slash command `/am-i-chinese`. It checks your
environment (base-url / timezone / proxies), and can scan any pasted text, file, or
whole project for hidden characters.

![usage](assets/screenshot-usage.png)

Under the hood it just runs a stdlib-only Python script — exit `0` clean · `1` findings ·
`2` error, so you can also wire it straight into CI or a pre-commit hook.

---

## Install on other coding agents

The engine is a single file — `scan.py` (stdlib Python 3.8+). Drop it in the repo and
point your agent's rule/skill system at it.

### Cursor
Cursor loads Markdown **rules** from `.cursor/rules/`. Add a rule that points at the script:
```bash
mkdir -p .cursor/rules tools/am-i-chinese
cp plugins/am-i-chinese/scan.py tools/am-i-chinese/
cat > .cursor/rules/am-i-chinese.mdc <<'EOF'
---
description: Audit text/code for hidden-Unicode & homoglyph steganography.
alwaysApply: false
---
When the user asks to check for hidden/invisible characters, tampering, prompt
injection via unicode, or region fingerprinting, run:
  python3 tools/am-i-chinese/scan.py <path|->
Quote the script output; never infer codepoints yourself.
EOF
```

### Windsurf
Same pattern, under `.windsurf/rules/`:
```bash
mkdir -p .windsurf/rules tools/am-i-chinese
cp plugins/am-i-chinese/scan.py tools/am-i-chinese/
# create .windsurf/rules/am-i-chinese.md with the same instruction block as above
```

### Cline / Roo Code
These read project **custom instructions** (`.clinerules` / `.roo/rules/`). Copy `scan.py`
into the repo and add a rule line:
```
For hidden-character / tampering / fingerprint audits, run `python3 scan.py <path>` and report its output verbatim.
```

### Codex CLI / Gemini CLI / any `AGENTS.md`-based agent
Copy `scan.py` into the repo and add to `AGENTS.md`:
```markdown
## Hidden-text audits
Run `python3 scan.py <path|->` to check any text/code for hidden-Unicode or homoglyph
steganography. Report the script's output; exit code 1 means findings.
```

### Any agent / no skill system
It's just a script. Keep `scan.py` in the repo and run it from the terminal or a
pre-commit hook:
```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: am-i-chinese
      name: am-i-chinese
      entry: python3 plugins/am-i-chinese/scan.py
      language: system
      pass_filenames: true
```

---

## Background

In June 2026, reverse-engineering of Claude Code revealed a covert marker system: when the
client detected a non-official `ANTHROPIC_BASE_URL` (matched against a ~147-entry proxy
blacklist) and an `Asia/Shanghai` / `Asia/Urumqi` system timezone, it steganographically
tagged outgoing requests by (a) swapping the date separator `2026-06-30` → `2026/06/30` and
(b) replacing the ASCII apostrophe `U+0027` with a visually identical Unicode variant — a
2–3 bit region classifier hidden inside the system prompt, invisible even to a user reading
that prompt. Anthropic said it was an anti-resale/anti-distillation experiment and rolled it
back. `am-i-chinese` detects that class of marker, and the broader family of invisible-Unicode
tampering, in any text an agent touches.

## Repo layout

```text
.claude-plugin/marketplace.json          # marketplace catalog (name: mana)
plugins/am-i-chinese/
  ├── .claude-plugin/plugin.json         # plugin manifest
  ├── SKILL.md                           # skill instructions (model-invoked + /am-i-chinese)
  └── scan.py                            # the zero-dependency detection engine
```

## License

Public domain / CC0 — copy, modify, ship it anywhere.
