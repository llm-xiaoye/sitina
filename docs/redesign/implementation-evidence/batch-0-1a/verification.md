# 批次 0 与 1a 实施验证

目标规范：`sitina-loop-v1-r4`。工作副本：`/Users/moss/SitinaHub-r4-b0-1a`；分支：`codex/sitina-r4-b0-1a`；基线提交：`27edb59f2ff592fb793a717c6a71ffd8d3d9610a`。

当前结论是：**1a 最小持久骨架已在隔离开发副本通过定向及相关回归；批次 0 的四个程序评分与八个独立模型评审 verdict 都匹配私有人工参考标签，但实际图像内容、图与数据的绑定及标题／坐标可读性没有运行核验，所以批次总证据状态仍为 `NEEDS_EVIDENCE`。** 没有合并、推送、生产切流或 1b 业务执行。

源仓库的 HEAD 和 14 个既有 tracked 修改文件哈希均保持冻结基线；但有一次旧 Provider 探针漏设 `SITINA_HOME`，启动器默认使用 `/Users/moss/SitinaHub`，更新了其中被忽略的 `data/sitina.db` 的 `deepseek` 健康行。该边界错误及完整命令输出已落证；由于没有捕获原行值，没有进行猜测性回滚。

## 已接入

- 一个后台协调入口与五个内部职责模块：状态／调度、Agent 请求绑定、操作执行、验证、上下文／内容；Journal/CAS 是共享持久基础，不是第二任务权威。
- 新命名空间先显式持久化 Keychain 数据密钥，再由新 provider 对象取回原 key ID，以 Journal HMAC、CAS commitment、DEK wrap/unwrap 三条路径验证；公开 bindings 使用临时文件、文件同步、原子替换、目录同步及严格磁盘重读，最后才允许 Journal 任务事件。
- 稳定任务与运行身份、目标／验收／事件版本、输入顺序与去重、唯一条件提交入口、操作和执行段身份、恢复政策、意图先于副作用、结果与未知效果记录。
- 只对业务写入取得全局保守修改通道；只读不占用。写入在排队后重新核对任务、输入、版本与资源前提。
- 写入意图取得规范化项目资源归属，成功结果不会自动释放；另一任务对相同、祖先或子路径的写入被拒绝，直到持久的稳定交接或终态。未知结果和已登记但无结果的意图在重开后恢复冻结占用。
- 验收回执保留评审开始时的完整版本绑定；迟到旧回执可追溯但不进入当前有效验收集合。
- 案例评分显式声明期望任务状态和任务类型证据，不统一要求 diff/test；程序 `FAIL` 不可被评审覆盖，`NOT_RUN` 不改写，版本不一致不可比较。日常与 benchmark 的合同复用目前仅在 evaluator 单元层，正式 Loop/runtime 接线属于 1b。

## 验证命令与结果

```text
SITINA_HOME=/Users/moss/SitinaHub-r4-b0-1a .venv-r4/bin/pytest -q \
  tests/test_loop_batch_1a.py tests/test_loop_contract_r4.py \
  tests/test_provider_tool_protocols.py tests/test_local_journal.py \
  tests/test_local_cas.py tests/test_cas_crypto.py tests/test_journal_model.py \
  tests/test_journal_codec.py tests/test_read_only_diagnostics_cli.py

70 passed in 0.99s
```

`git diff --check` 和相关模块 `compileall` 均通过。监督提供的两个隔离复现脚本也确认：迟到验收不再升级、UNKNOWN 和无结果意图不释放占用、项目归属不会在任务两次操作之间消失、普通失败／取消／等待状态不会被评分为成功。

监督从应用任务历史提取了 Provider、只读 Agent 和真实 Keychain 的 8 条正式命令及完整捕获输出，全部标记为 `truncated=false`；该输出是应用捕获的终端流，未冒充为重建后的独立 stdout/stderr。独立校准完整性审计另确认八个 reviewer 的只读包逐文件等于原始完整单包，原始模型 JSON、汇总 verdict 和 stdout/stderr 哈希互相一致。

真实 Keychain 使用独立 runtime root 和三个全新 `bin/sitina` 解释器。第一次创建任务时 `existing_only_reopen=false`；第二次取回相同 key IDs 和 verification fingerprint 后写入唯一 recovery dock；第三次仍读到 task revision 2，没有重复 dock。任务停在 `RECOVERY_BLOCKED / RECOVERY_NOT_CONNECTED`，这只证明 1a 诚实停靠，不证明批次 3 恢复。

## 四例校准

程序检查与人工参考完全一致：

| 案例 | 程序 | 当前两名正式评审 | 结论 |
|---|---|---|---|
| case-001 正确图 | PASS | PASS / PASS | 匹配参考 |
| case-002 单位错误 | FAIL | BLOCK / BLOCK | 程序硬失败；双评审匹配参考 |
| case-003 合法配色替代 | PASS | PASS / PASS | 配色差异未被误阻断 |
| case-004 证据不足 | NEEDS_EVIDENCE | NEEDS_EVIDENCE / NEEDS_EVIDENCE | 分类一致 |

每位评审只收到一个 workspace，其中只读 `packet/` 恰含该案例的白名单交付：`requirements.md`、`packet.md`、`chart.png`，以及前三例实际提供的 `source.csv`、`plot-data.csv`、`provenance.json`、`render_plot.py`；case-004 只有前三个文件。顶层 `generate_fixtures.py`、相邻案例、QA 与 evaluator-only 标签均未进入 workspace。八个最终运行后，`packet/` 的递归文件清单与哈希全部不变，所有绝对工具路径均保持在对应 workspace 内。

修复 `provider_messages_for_wire` 后，`tool_calls: []` 不再发给 OpenAI-compatible Provider；非空调用和 tool result 配对保持。完整白名单入口的第一次运行有 3 个 reviewer 因选择需批准的 shell/desktop 工具而达到显式 8 回合边界；没有扩大轮次，只在中性提示中明确限定目录枚举与文本读取工具，并只重试这些 `NOT_RUN` 槽位，随后三者均产出匹配参考的结论。初次失败仍保存在 `prior_attempts` 与 `raw-results/`，没有改写成通过。该 8 回合只用于旧入口校准隔离，不是 r4 Loop 的总轮数规则。

完整入口命令为 `.venv-r4/bin/python scripts/r4_review_calibration.py --source /Users/moss/Documents/ChatGPT/sitinaRedesign/r4-review-calibration-2026-09-06 --output docs/redesign/implementation-evidence/batch-0-1a/calibration-full --repository /Users/moss/SitinaHub-r4-b0-1a --profile deepseek`；仅重试未运行槽位时在同一命令末尾增加 `--retry-not-run`。最终汇总 SHA-256 为 `c0b9020054dbce58d400af5c8c3b4d8e3c7afbe4cda13e6589382155ad6dbbd6`，每次调用的原始 stdout/stderr 与完整哈希均由汇总文件指向 `calibration-full/raw-results/`。

这些匹配结论的覆盖边界必须单列：两名 case-001 评审都声明无法安全读取 `chart.png`，而 `program_check` 只检查图像存在，不校验像素内容或图与 `plot-data.csv` 的绑定；监督用 case-002 图替换 case-001 图的临时副本后，程序检查仍为 `PASS`。因此图像内容、标题／坐标可读性及图—数据一致性都是 `NOT_RUN`，不能据此声称完整视觉成果验收通过。

## 已知边界

- 新 `loop-state` 是 1a 开发控制面，不执行 1b 真实业务任务。
- 完整重连、未知效果探测与解冻、长期进程管理、上下文、记忆、Skill 使用和发布均未实现。
- 未跑破坏性的真实掉电/fsync 故障；当前证据是注入写入／读回失败与真实跨解释器读回。
- 现有 `provider status` 基线把联网结果与健康状态保存混在旧 SQLite 路径；最终开发根复核联网成功，但健康状态保存仍以 `OperationalError` 失败。原始输出、完整 stdout 哈希和错误字符串哈希已分字段保存，没有标成新合同通过。
- `tests/test_provider_secret_references.py` 另有两个已有回归：unknown custom endpoint 缺显式 wire protocol。它们不来自本批修改，单列而未隐藏。

机器可读覆盖清单见 [batch-report.json](batch-report.json)，初态见 [baseline-manifest.json](baseline-manifest.json)，Keychain 证据见 [keychain-cli-evidence.json](keychain-cli-evidence.json)，最终校准见 [calibration-results.json](calibration-full/calibration-results.json)，父级标签对照见 [comparison.json](calibration-full/comparison.json)。早期裁剪输入校准保留在 `calibration/`，只作为诊断历史，不是最终入口证据。
