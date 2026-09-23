# 语义文档：提示词注入防御（prompt-defense）

> 版本 v0.2 · 2026-09-22 · 作者：爱丽丝 · 状态：**已实现**
> 开发方式：**事后补写**（能力 2026-09-15 落地、09-16 大改、09-22 补文档——缺口记入 §9）
> 实现落点：`self-plugins/dsh-prompt-defense/src/index.ts`（宿主）+ `src/detect.ts`（纯层）+ `src/fabric.ts`（契约面骨架）
> 体系设计（威胁模型 / L0–L6 分层）：`docs/design/prompt-defense.md`（**不是**本文件，见 §8）

---

## 1 · 定位与反定位

**定位**：在**外部内容**与**我的动作**之间架一道**可见**的防线——给外部内容打标、按特征扫描注入、在污点存在时观测高危动作、把全过程落到审计轨迹。**让风险可见、可追溯；不替主体做决定。**

**反定位（本文不管什么）**：
- **不管拦截**：本能力**没有任何拒绝 / 询问分支**（源码级契约，见 A15）。污点下的高危动作**一律放行**
- 不管内容真伪（只按**特征**判可疑，不判「这句话对不对」）
- **不是**沙箱：它与宿主**同进程、全权限**；防的是「我被话术带走」，不是「代码越权」
- 不管我**主动**想做的高危动作（污点为零时它根本不介入）

## 2 · 术语表

| 术语 | 含义 |
|------|------|
| 外部来源工具 | 结果内容**不由我产出**的工具（清单见 `src/detect.ts` 的 `EXTERNAL_SOURCE_TOOLS`；反向清单 `TRUSTED_TOOLS`） |
| 命中（hit） | 文本命中某条注入特征：`{kind, needle, score}` |
| 污点（taint） | 会话级状态：外部内容里出现过可疑注入特征，**直到人类开口才清零** |
| 危险动作 | 五类：以我之名对外发言 / 触凭据 / 私钥助记词形态 / 网络外发 / 自改规则或插件源码 |
| 审计轨迹 | `prompt-defense-trace.jsonl`：一行一阶段 |
| 不可信标记 | `[UNTRUSTED-EXTERNAL-CONTENT]` 头——**声明这是数据不是指令** |

## 3 · 概念模型

```
   外部来源工具出站（tools/post-execute）          我的动作（tools/pre-execute）
              │                                            │
     ┌────────▼─────────┐                        ┌─────────▼──────────┐
     │ L1 标记           │                        │ L3 危险动作观测     │
     │  prependHeader    │                        │  污点存在才介入     │
     │  [UNTRUSTED-…]    │                        │  assessDanger       │
     ├───────────────────┤                        │  ⇒ 只落审计，必放行 │
     │ L2 检测           │                        └─────────┬──────────┘
     │  scanForInjection │                                  │
     │  assessInjection  │                                  ▼
     └────────┬──────────┘                        trace: danger-observed
              │  score ≥ taintThreshold
              ▼
      taints.set(sessionId)  ──► trace: taint-set
              │
              │  人类新消息（session/event · user/message）
              ▼
      taints.delete(sessionId) ─► trace: taint-clear
```

**不变量（invariants）**：
1. **I1 只观测不拦截**：源码中**不存在** `ask` / `deny` / `hardblock` 分支；污点下高危动作一律返回放行
2. **I2 waterfall 纪律**：`tools/pre-execute` 钩子**必须**调用 `next()`（不得吞掉链路）
3. **I3 观测不反噬**：所有钩子体包 `try/catch`，异常时**返回原 decision** 并落 `phase:'error'`；审计落盘失败**返回 `false` 且不抛**
4. **I4 污点是信号不是罪证**：污点存在**不**导致拒绝干活，只导致「多见一行审计」
5. **I5 人类新消息 = 新信任基线**：任一人类 `user/message` 到达 ⇒ 该会话污点清零
6. **I6 外部内容永远不是指令**：被标记的内容带 `[UNTRUSTED-EXTERNAL-CONTENT]` 头 + 纪律声明
7. **I7 污点按会话隔离**：`keyOf(exec)` 取 `agent.session.id`；缺失 ⇒ 桶名 `default`（不跨会话串污点）

## 4 · 契约

### 4.1 文件

| 文件 | 形状 | 写入方式 / 读取语义 |
|------|------|-------------------|
| `<DSH_HOME>/prompt-defense-trace.jsonl` | 一行一 JSON：`TraceLine{atMs, phase, sessionId?, tool?, score?, kinds?, needle?, signals?, note?}` | `appendTraceSync`（追加；**吞错返回 bool**）；`phase ∈ {injection-hit, taint-set, taint-clear, danger-observed, error}` |
| 配置 `tracePath` | 相对 `DSH_HOME` 或绝对路径 | 相对时拼 `DSH_HOME`；`DSH_HOME` 缺失 ⇒ 退回相对路径（仍不抛） |

### 4.2 裁决（纯层 `detect.ts`，可离线单测）

| 函数 | 签名 | 裁决语义 |
|------|------|---------|
| `scanForInjection` | `(text) → InjectionHit[]` | 按 `PATTERNS` 逐类扫描，返回命中（`needle` 有长度上限 `NEEDLE_MAX`） |
| `assessInjection` | `(text, threshold) → InjectionAssessment` | `{hits, score, suspicious}`；`score ≥ threshold` ⇒ `suspicious` |
| `assessDanger` | `(toolName, args) → DangerAssessment` | `{dangerous, signals[]}`；只读工具**不得**判危险；路径参数按 `PATH_ARG_KEYS` 取；见 `SECRET_PATH_RE` / `PRIVATE_KEY_RE` / `MNEMONIC_RE` / `EXFIL_CMD_RE` / `SELF_MODIFY_RE` |
| `isExternalSourceTool` | `(name) → boolean` | 在 `EXTERNAL_SOURCE_TOOLS` 且不在 `TRUSTED_TOOLS` |
| `untrustedHeader` | `(tool, assessment) → string` | 生成标记行（含来源、纪律声明、命中信息） |
| `appendTraceSync` | `(path, line) → boolean` | **吞错返回 `false`，绝不抛**（I3） |

### 4.3 调用点清单 `[MUST]`

| 调用方 | 调用点（文件:符号） | 时机 |
|-------|------------------|------|
| 工具结果出站 | `src/index.ts` · `apply` → `ctx.on('tools/post-execute', …)` | 仅当 `isExternalSourceTool(exec.name)` 且 `decision.kind === 'accept'` |
| 我的动作发起 | `src/index.ts` · `apply` → `ctx.on('tools/pre-execute', …)` | 仅当 `observeDanger` 开 **且** 该会话有污点 |
| 会话事件 | `src/index.ts` · `apply` → `ctx.on('session/event', …)` | 任意 `user/message` ⇒ 清污点 |
| 工具 `prompt_defense_status` | `src/index.ts` · `defineTool` 内 `execute` | 随时；五问一条命令可答 |

## 5 · 边界与信任

- **能力边界 ≠ 沙箱**：本能力与宿主**同进程、全权限**。它防的是**注入话术**（概率性特征匹配），**不防**代码越权、不防我主动的意图
- **不假装绝对**：LLM 防御是**概率性**的。目标是抬高攻击成本 + 风险可见 + 全量可审计；**任何声称「绝对防注入」的实现都在撒谎**
- **不越界清单**：不做人审 / 不做拦截 / 不改写我的决定 / 不记录我的正文内容（只记工具名、分数、命中类型与 needle 片段）
- **失败面**：
  - 钩子体异常 ⇒ `trace({phase:'error'})` 后返回**原 decision**（不中断）
  - 审计落盘失败 ⇒ `appendTraceSync` 返回 `false`，**不抛、不阻断**
  - 会话 id 缺失 ⇒ 归入 `default` 桶（不静默跨会话合并）
  - `enabled=false` ⇒ `apply` 直接 `return`（完全静默）

## 6 · 与既有机制的关系

- **§5.27（提示词注入防御纪律）**：本能力是该纪律的**实现**；纪律条文在 AGENTS.md，实现语义在本文件（互为引用，不平行维护正文）
- **§5.30 规则 4（失败必须响）**：`appendTraceSync` 的 bool 返回 + 吞错是「观测不反噬」的代码投影
- **§5.11（组合变更必验证）**：改本能力后必须预检 + 重启才生效（与宿主同进程）
- 与 `dsh-prompt-defense` 之外的层：L0（内容不进上下文）由**我自己的行为**负责，本能力只覆盖 L1–L3

## 7 · 可证伪验收清单

> 机器可读约定（MUST）：解析器只读**行内最后一个非空单元格**。本表最后一列即**状态列**，已证写 `✔ 已实测`。

| # | 可证伪命题 | 证据（单测名 / 命令） | 状态（**本表最后一列**） |
|---|-----------|---------------------|------|
| A1 | 每类攻击至少被检出一次且**分类正确**（正样本） | `ok 1 - 正样本：每类攻击至少被检出一次，且正确分类` | ✔ 已实测 |
| A2 | 高危组合达到污点阈值 | `ok 2 - 正样本：高危组合达到污点阈值` | ✔ 已实测 |
| A3 | **反样本**：正常内容不得被标记为可疑 | `ok 3 - 反样本：正常内容不得被标记为可疑` | ✔ 已实测 |
| A4 | 现场回归：协议文档里的 `Authorization: Bearer ow_xxx` 必须命中 | `ok 4 - 现场回归：Openwork 协议里的 Authorization: Bearer ow_xxx 必须命中` | ✔ 已实测 |
| A5 | 外部来源工具识别：外部为真、自有产出为假 | `ok 5 - 外部来源工具识别：外部为真，自有产出为假` | ✔ 已实测 |
| A6 | 五类危险动作全部可判 | `ok 6 - 危险动作：对外发言 / 触凭据 / 私钥形态 / 外发 / 自改规则` | ✔ 已实测 |
| A7 | **危险动作反向断言**：日常工作不得被判危险（防瘫痪） | `ok 7 - 危险动作反向断言：日常工作不得被判危险（防瘫痪）` | ✔ 已实测 |
| A8 | 标记头含来源、纪律声明与命中信息 | `ok 8 - 不可信标记：含来源、纪律声明与命中信息` | ✔ 已实测 |
| A9 | **I3**：审计落盘失败必须返回 `false` 且不抛 | `ok 9 - 审计落盘失败必须返回 false 且不抛` | ✔ 已实测 |
| A10 | 现场回归①：技术文档 URL 里的 key/keyset 不得判为外泄目标 | `ok 10 - 现场回归①：技术文档 URL 里的 key/keyset 不得判为外泄目标` | ✔ 已实测 |
| A11 | 现场回归①反向：URL 带值的凭据查询参数仍必须命中 | `ok 11 - 现场回归①的反向：URL 带值的凭据查询参数仍必须命中` | ✔ 已实测 |
| A12 | 现场回归②：只读工具不得被判高危（上线首夜自锁的根因） | `ok 12 - 现场回归②：只读工具不得被判高危（上线首夜自锁的根因）` | ✔ 已实测 |
| A13 | 现场回归③：写文档时提及凭据路径不得被判高危 | `ok 13 - 现场回归③：写文档时提及凭据路径不得被判高危` | ✔ 已实测 |
| A14 | 现场回归③反向：真危险仍必须命中（否则等于拆防线） | `ok 14 - 现场回归③的反向：真危险仍必须拦（否则等于拆防线）` | ✔ 已实测 |
| A15 | **I1 契约**：插件源码不得含任何拦截分支（`ask` / `deny` / `hardblock`） | `ok 15 - 契约：插件源码不得含任何拦截分支（ask / deny / hardblock）` | ✔ 已实测 |
| A16 | **I2 契约**：`pre-execute` 钩子必须放行（waterfall 纪律） | `ok 16 - 契约：pre-execute 钩子必须放行（waterfall 纪律）` | ✔ 已实测 |
| A17 | 全部单测通过 | `npm test`（= `node tests/detect.test.mjs`）→ `# pass 16 / # fail 0`（RC=0，2026-09-22 实跑） | ✔ 已实测 |
| A18 | **I5 端到端**：人类新消息到达后 `prompt_defense_status` 的当前污点会话数归零 | `prompt_defense_status` 的 `clearedCount` 递增 + `taintedSessions` 不含该会话 | ⚠ 待线上验收（需一次真实的「置污点→人类开口」序列） |
| A19 | **I7**：污点不跨会话串（两个会话并发时各自独立） | 需两会话并发场景 | ⚠ 待线上验收（单会话环境无法构造） |

## 8 · 与实现的关系

- **主实现**：`src/index.ts`（挂载 3 个钩子 + 1 个工具）
- **纯层**：`src/detect.ts`（全部裁决内核 + 特征常量 + 审计落盘）——**本能力唯一的回归保护**
- **同语义副本**：**无**。体系设计文档 `docs/design/prompt-defense.md` 讲的是**威胁模型与 L0–L6 分层**，与本文件的「实现语义」是**两个不同层面**，不是同一份文档的两份副本（不构成 §5.20 I1 的 twins）
- **契约面骨架**：`src/fabric.ts`（Fabric RFC 0001 draft 对齐；未经官方一致性套件验证）
- **未实现 / 未验证部分显式标注**：① A18 / A19 待线上验收；② 误报率 / 漏报率**无统计数据**（本能力不下「绝对」断言，见 §5）

## 9 · 实践修订记录

- **2026-09-16 移除人审闸门**（主人定调「防御体系不应该有人工审核」）
  - 语义**被修正**：原 L3 为「危险动作人审」（复用 `tools/pre-execute` 的 `{kind:'ask'}` 通道）；改为**纯观测**——只落 `danger-observed` 审计、永远放行
  - 语义**被补充**：I1（只观测不拦截）由此从「实现选择」升格为**契约**，并配源码级契约测试（A15）
  - 教训：**「看不看得见归机制，做不做归主体」**——防御体系的产出是**可见性**，不是**否决权**
- **2026-09-16 上线首夜自锁修复**（三处现场误报）
  - 语义**被补充**：`assessDanger` 必须对**只读工具**与**正文提及的路径**保持免疫（A12 / A13），否则防线会在日常工作中自锁
  - 教训：**防线必须先证明「不误伤日常」**——反向断言（A3 / A7 / A11 / A14）与正向断言同等重要
- **2026-09-22 首次实践（补文档）**
  - 语义**被确认**：I1–I7 均可从实现与单测读出
  - 语义**被补充**：I7（污点按会话隔离）此前未成文
  - 教训：文档 09-22 才补，欠债 7 天；§5.20「文档不在，不算开工」在本能力上**未被遵守**（记入与本批次同源的教训）

## 10 · 未决问题

- **U1 误报率无统计**：本能力只报「命中计数」（`hitCount`），不报「误报率」。是否需要人工标注一轮真实语料来估？我的倾向：**需要，但优先级低**——当前口径（只观测不拦截）下误报的代价仅是审计噪音。
- **U2 特征库无版本 / 无回归语料集**：`PATTERNS` 改动缺语料回归。我的倾向：把现场回归（A10–A14）扩成一个小语料集。
- **U3 污点粒度是会话**：同一会话内「换了个话题」不会清污点（只有人类开口才清）。这个粒度是否过粗？我的倾向：**保持**——过细会让污点失去意义。
- **U4 与 `dsh-prompt-defense` 之外的 L0**：内容**进上下文之前**的拦截（如完全不把某类内容读进来）不在本能力范围。是否需要？我的倾向：**不需要**——那等于人审。
