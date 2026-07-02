# 中国人 · Am I Chinese?

**插件名:`am-i-chinese`** —— 站在用户这边的一个反向审计器:
别人忙着问「这个用户看起来像中国人吗?」,它替你问一句「我的 AI 是不是背着我,把我标成了中国人?」

一个零依赖的**隐藏文字审计器**,自包含在单个 `SKILL.md` 里。既是 Claude Code 插件,也遵循
**跨 agent 的 `SKILL.md` 开放标准** —— Claude Code / Codex CLI / Cursor / Gemini CLI 通用。
装好之后,直接问你的 agent 一句 **「我是中国人吗?」** 就行。

它会扫描任意文字 / prompt / 代码里那些**肉眼看不见、或跟正常字符长得一模一样**的花招:

- **零宽字符**(藏数据、把 token 从中间劈开)
- **双向控制符** —— Trojan Source 源码顺序调包攻击
- **Unicode Tags 区块** —— 隐形 ASCII 走私 / prompt 注入
- **同形字**:山寨撇号、混血标识符(`pаssword` 里掺了西里尔字母 `а`)
- 2026 年 Claude Code 隐写事件里那套**地区指纹暗号**:非 ASCII 撇号 + 日期分隔符
  `-`→`/` 调包,以 `Asia/Shanghai` / `Asia/Urumqi` 时区为触发条件。

检测由一段确定性的 Python 代码完成(**内嵌在 `SKILL.md` 里**,agent 直接执行)—— **LLM 永远不需要(也不应该)自己用肉眼去看那些隐形字符**。

---

## 安装(Claude Code)

两步:**先加市场,再装插件。**

```text
/plugin marketplace add mana-am/am-i-chinese
/plugin install am-i-chinese@mana
```

![安装](assets/screenshot-install.png)

`/plugin marketplace add mana-am/am-i-chinese` 把本仓库注册成一个名为 `mana` 的插件市场;
`/plugin install am-i-chinese@mana` 从市场里把这个 skill 装上。以后想更新:`/plugin marketplace update mana`。

> 上图是**真实安装**的终端输出(真的跑了一遍 `claude plugin` 命令,连「SSH 没配、改用 HTTPS 克隆」这种真实细节都在)。

## 使用

装好后,直接用大白话问 Claude Code,skill 会自动触发:

```text
> 我是中国人吗?
```

……或者显式敲斜杠命令 `/am-i-chinese`。它会体检你的环境(端点 / 时区 / 代理),
也能扫任意粘贴的文字、指定文件、或整个项目里的隐藏字符。

![使用](assets/screenshot-usage.png)

> 上图是**真实运行**的输出:安装后的 skill 被 `我是中国人吗?` 自动唤起,先把 `SKILL.md`
> 内嵌的扫描器物化到临时文件,再跑 `--env`,
> 给出真实结论。为避免截图泄露自己的私有端点,`--env` **默认对 `ANTHROPIC_BASE_URL` 脱敏**
> (只报「是否自定义端点」,不打印完整 URL);本地想看全的加 `--show-endpoint`。

底层就是一个只用标准库的 Python 脚本 —— 退出码 `0` 干净 · `1` 有发现 · `2` 出错,
所以也能直接塞进 CI 或 pre-commit 钩子。

---

## 装到其它编程 agent 上(Codex / Cursor / Gemini CLI …)

`SKILL.md` 是**跨 agent 的开放标准** —— 同一个 `SKILL.md`,Claude Code / Codex CLI /
Cursor / Gemini CLI 都能直接读,格式一模一样,**只是各家的技能目录不同**。而我们这个
skill 已经**自包含在单个 `SKILL.md`** 里(检测引擎内嵌其中),所以「装到别的 agent」=
把这一个文件丢进对应目录,不用改一个字。

**一条命令,装到任意 agent(以 Codex 为例,换目录即换 agent):**

```bash
mkdir -p ~/.codex/skills/am-i-chinese
curl -fsSL https://raw.githubusercontent.com/mana-am/am-i-chinese/main/plugins/am-i-chinese/SKILL.md \
  -o ~/.codex/skills/am-i-chinese/SKILL.md
```

装完之后,用法和 Claude Code 一样 —— 直接问它 **「我是中国人吗?」**,或用各家的技能唤起方式
(Codex:`/skills` 或 `$am-i-chinese`;Gemini CLI:匹配到描述自动 `activate_skill`;Cursor:斜杠/自然语言)。

**各 agent 的技能目录**(把上面 `~/.codex/skills` 换成对应路径即可):

| Agent | 个人级(所有项目) | 项目级(签进仓库) |
|-------|------------------|-------------------|
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex CLI | `~/.codex/skills/` | `.codex/skills/` |
| Cursor | `~/.cursor/skills/` | `.cursor/skills/` |
| Gemini CLI | `~/.gemini/skills/` | `.gemini/skills/` |
| 工具无关别名 | `~/.agents/skills/` | `.agents/skills/` |

> `~/.agents/skills/` 是正在成型的**工具无关**通用位置,放这儿一份,多家 agent 都能发现。

### 老式的「只认规则文件」的 agent(Cline / Roo Code / 纯 `AGENTS.md`)

它们没有 SKILL.md 技能系统,只读规则/指令文件。这时先把内嵌扫描器**物化**成一个
`scan.py`:跑一遍 `SKILL.md` 里的 **Step 1** 代码块(它会把扫描器写到
`${TMPDIR:-/tmp}/am-i-chinese.py`),再拷出来:

```bash
mkdir -p tools/am-i-chinese
cp "${TMPDIR:-/tmp}/am-i-chinese.py" tools/am-i-chinese/scan.py
```

然后在 `.clinerules` / `.roo/rules/` / `AGENTS.md` 里加一行:

```markdown
做隐藏字符 / 篡改 / 地区指纹审计时,运行 `python3 tools/am-i-chinese/scan.py <path|->`
(自查本机加 `--env`),并原样汇报脚本输出;退出码 1 表示有发现。绝不自己臆断码点。
```

### 任何 agent / 没有技能系统:直接当脚本或 pre-commit 钩子

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: am-i-chinese
      name: am-i-chinese
      entry: python3 tools/am-i-chinese/scan.py
      language: system
      pass_filenames: true
```

---

## 来龙去脉

2026 年 6 月,有人逆向 Claude Code,扒出一套隐蔽的打标机制:当客户端检测到
`ANTHROPIC_BASE_URL` 不是官方地址(比对一份约 147 条的代理黑名单),且系统时区为
`Asia/Shanghai` / `Asia/Urumqi` 时,它会用隐写术给发出去的请求盖戳 ——
(a) 把日期分隔符 `2026-06-30` 换成 `2026/06/30`,(b) 把 ASCII 撇号 `U+0027` 换成一个
长得一模一样的 Unicode 变体 —— 相当于在 system prompt 里缝进一个 2~3 bit 的地区分类器,
连读这段 prompt 的用户都看不见。Anthropic 称这是一次防转售 / 防蒸馏的实验并已回滚。
`am-i-chinese` 就是用来检测这一类标记,以及更广义的隐形 Unicode 篡改 —— 只要是 agent 碰过的文字。

## 仓库结构

```text
.claude-plugin/marketplace.json          # 市场目录(名为 mana)
plugins/am-i-chinese/
  ├── .claude-plugin/plugin.json         # 插件清单
  └── SKILL.md                           # 技能说明 + 内嵌的零依赖检测引擎(自包含单文件)
```

> 检测引擎的完整代码就**内嵌在 `SKILL.md` 里**:skill 触发时,coding agent 执行其中的
> Step 1 代码块把扫描器物化到临时文件,再运行 —— 单文件、免路径解析、拷到哪都能跑。

## 许可

公有领域 / CC0 —— 随便抄、随便改、随便用到任何地方。
