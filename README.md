# 中国人 · Am I Chinese?

**插件名:`am-i-chinese`** —— 站在用户这边的一个反向审计器:
别人忙着问「这个用户看起来像中国人吗?」,它替你问一句「我的 AI 是不是背着我,把我标成了中国人?」

一个零依赖的**隐藏文字审计器**,打包成 Claude Code 插件。装好之后,直接问你的 agent 一句 **「我是中国人吗?」** 就行。

它会扫描任意文字 / prompt / 代码里那些**肉眼看不见、或跟正常字符长得一模一样**的花招:

- **零宽字符**(藏数据、把 token 从中间劈开)
- **双向控制符** —— Trojan Source 源码顺序调包攻击
- **Unicode Tags 区块** —— 隐形 ASCII 走私 / prompt 注入
- **同形字**:山寨撇号、混血标识符(`pаssword` 里掺了西里尔字母 `а`)
- 2026 年 Claude Code 隐写事件里那套**地区指纹暗号**:非 ASCII 撇号 + 日期分隔符
  `-`→`/` 调包,以 `Asia/Shanghai` / `Asia/Urumqi` 时区为触发条件。

检测由一个确定性的 Python 脚本完成 —— **LLM 永远不需要(也不应该)自己用肉眼去看那些隐形字符**。

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

> 上图是**真实运行**的输出:安装后的 skill 被 `我是中国人吗?` 自动唤起,跑了 `scan.py --env`,
> 给出真实结论。为避免截图泄露自己的私有端点,`--env` **默认对 `ANTHROPIC_BASE_URL` 脱敏**
> (只报「是否自定义端点」,不打印完整 URL);本地想看全的加 `--show-endpoint`。

底层就是一个只用标准库的 Python 脚本 —— 退出码 `0` 干净 · `1` 有发现 · `2` 出错,
所以也能直接塞进 CI 或 pre-commit 钩子。

---

## 装到其它编程 agent 上

引擎就一个文件 —— `scan.py`(标准库,Python 3.8+)。丢进仓库,让你的 agent 的
规则 / 技能系统指向它即可。

### Cursor
Cursor 从 `.cursor/rules/` 加载 Markdown **规则**。加一条指向脚本的规则:
```bash
mkdir -p .cursor/rules tools/am-i-chinese
cp plugins/am-i-chinese/scan.py tools/am-i-chinese/
cat > .cursor/rules/am-i-chinese.mdc <<'EOF'
---
description: 审计文字/代码里的隐藏 Unicode 与同形字隐写。
alwaysApply: false
---
当用户要求检查隐藏 / 不可见字符、篡改、通过 unicode 做的 prompt 注入,或地区指纹时,运行:
  python3 tools/am-i-chinese/scan.py <path|->
引用脚本原样输出;绝不自己臆断码点。
EOF
```

### Windsurf
同样的套路,放在 `.windsurf/rules/`:
```bash
mkdir -p .windsurf/rules tools/am-i-chinese
cp plugins/am-i-chinese/scan.py tools/am-i-chinese/
# 在 .windsurf/rules/am-i-chinese.md 里写上和上面一样的指令块
```

### Cline / Roo Code
它们读项目的**自定义指令**(`.clinerules` / `.roo/rules/`)。把 `scan.py` 拷进仓库,加一行规则:
```
做隐藏字符 / 篡改 / 指纹审计时,运行 `python3 scan.py <path>` 并原样汇报输出。
```

### Codex CLI / Gemini CLI / 任何基于 `AGENTS.md` 的 agent
把 `scan.py` 拷进仓库,在 `AGENTS.md` 里加:
```markdown
## 隐藏文字审计
运行 `python3 scan.py <path|->` 检查任意文字/代码里的隐藏 Unicode 或同形字隐写。
原样汇报脚本输出;退出码 1 表示有发现。
```

### 任何 agent / 没有技能系统
它就是个脚本。把 `scan.py` 留在仓库里,从终端或 pre-commit 钩子跑:
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
  ├── SKILL.md                           # 技能说明(模型自动触发 + /am-i-chinese 斜杠命令)
  └── scan.py                            # 零依赖检测引擎
```

## 许可

公有领域 / CC0 —— 随便抄、随便改、随便用到任何地方。
