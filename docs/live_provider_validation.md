# Live Provider Validation

## 概述

本文档说明 Sitina Live Provider 的三套独立验收标准：

1. **Mock Runtime 验收**
2. **DeepSeek-only Live 验收**
3. **Multi-Provider Live 验收**

## 核心原则

### All-DeepSeek 是合法测试配置

**重要声明**: 

**all-deepseek 配置不是失败，是完全合法的测试配置。**

多 Agent 系统的真实性不取决于使用不同的模型名字，而取决于：

1. ✅ **Agent ID 隔离**: 每个 agent 有唯一 agent_id
2. ✅ **Role 隔离**: 每个 agent 有明确 role (controller, planner, coder, reviewer, etc.)
3. ✅ **Input/Output 隔离**: 每个 agent 的输入输出独立记录
4. ✅ **协作协议结构化**: proposal, evaluation, selection, arbitration, handoff 有明确结构
5. ✅ **审计完整性**: ledger, audit, trace, replay 保留每个 agent 的身份和决策
6. ✅ **Runtime 状态约束**: runtime 状态真实约束 agent 后续执行
7. ✅ **执行边界真实**: selected/rejected/blocked/non-selected agent 有真实执行边界
8. ✅ **Provider Identity 可审计**: provider/profile/model 作为安全摘要可审计
9. ✅ **Secret 安全**: secret 不泄露到 ledger/audit/trace
10. ✅ **Live Provider 闭环**: live provider 能在受控边界内跑完整闭环

**不取决于**:
- ❌ controller 是否用 GPT-4
- ❌ coder 是否用 Qwen
- ❌ reviewer 是否用不同模型

### 为什么 All-DeepSeek 是合法的？

在真实生产环境中：

1. **成本考虑**: 单一 provider 可能提供最优性价比
2. **延迟考虑**: 单一 provider 减少跨服务延迟
3. **配额管理**: 单一 provider 简化配额管理
4. **合规考虑**: 某些环境可能只允许特定 provider
5. **测试一致性**: 单一 provider 提供更一致的测试环境

只要 **agent 身份隔离** 和 **协作协议** 真实存在，系统就是真正的多 Agent 系统。

## 三套验收标准

### 1. Mock Runtime 验收（v1 Baseline）

**目标**: 验证多 Agent 协作协议的正确性，不依赖外部 provider。

**适用场景**:
- 开发阶段快速迭代
- CI/CD 自动化测试
- 协议逻辑验证
- 不消耗 API quota

**必须通过项**:
- [x] Config validate
- [x] Policy validate
- [x] Full unittest (mock)
- [x] Code-change fixture
- [x] Handoff-reject fixture
- [x] Arbitration-ask-user fixture
- [x] Lease-conflict-block fixture
- [x] High-risk-full-gate fixture
- [x] Side-effect-descriptor fixture
- [x] Proposal competition
- [x] Retry/rework loop
- [x] Multi-reviewer merge
- [x] Replay simulate (dry-run)
- [x] Secret scan 0

**验收命令**:
```bash
# 详见 Sitina_v1_acceptance_baseline.md
PYTHONPATH=core bin/sitina run "code-change-fixture mock baseline" --provider-mode mock
PYTHONPATH=core bin/sitina replay <run_id>
```

**通过标准**: 
- Status: done
- Replay: replay_ok
- Simulate: dry-run
- Secret scan: 0

---

### 2. DeepSeek-only Live 验收（v2 Baseline）

**目标**: 验证 live provider 可以在受控边界内完成最小多 Agent 协作闭环。

**配置**:
- Provider: DeepSeek
- All roles: deepseek profile
- Model: deepseek-v4-pro (or current)

**适用场景**:
- 验证 live provider 集成
- 验证 single-provider multi-role 路径
- 验证 timeout, checkpoint, cancellation
- 验证 secret safety
- 验证 terminal event

**最小闭环必须覆盖**:
1. Controller classify
2. 至少 2 个 proposer agent 提交 proposal
3. 至少 1 个 evaluator agent 评价 proposal
4. Selection 选出 1 个 proposal
5. Receiver handoff decision
6. Blackboard context 注入
7. Ledger/audit 写入
8. Trace 可观测
9. Replay 可重建
10. Replay simulate dry-run
11. Terminal event
12. Secret scan 0
13. 无真实副作用

**不在最小闭环中**:
- 不做真实文件写入
- 不做真实 git apply
- 不跑 high-risk full gate
- 不跑长链路 rework
- 不跑远程 MCP
- 不自动 accept memory

**验收命令**:
```bash
# 环境准备
export SITINA_LIVE_TEST=1

# 运行最小闭环
SITINA_LIVE_TEST=1 PYTHONPATH=core \
python -m unittest tests.test_live_minimal.LiveMinimalCollaborationTests.test_live_minimal_collaboration_smoke

# 验证结果
PYTHONPATH=core bin/sitina trace <live_run_id>
PYTHONPATH=core bin/sitina replay <live_run_id>
PYTHONPATH=core bin/sitina replay simulate <live_run_id> --sandbox
```

**通过标准**:
- Terminal event: exists
- Replay: replay_ok
- Simulate: dry-run, changed_real_files=false
- Agent_id: at least 2 different
- Provider_mode: live
- Profile_name: deepseek
- Secret scan: 0
- No real side effect

**当前状态**: 
- ⚠️ 基础设施已准备（timeout, checkpoint, terminal event 框架）
- ⚠️ 测试框架已准备
- ❌ 未实际运行验证（需要 SITINA_LIVE_TEST=1 环境）

---

### 3. Multi-Provider Live 验收（未实施）

**目标**: 验证不同 provider 承载不同 role 的多 Agent 协作。

**配置示例**:
- Controller: GPT-4 (OpenAI)
- Coder: Qwen (Alibaba)
- Reviewer: DeepSeek
- Security: DeepSeek
- Arbiter: DeepSeek

**适用场景**:
- 验证跨 provider 协作
- 验证 provider fallback
- 验证 profile-level policy
- 优化成本/性能组合

**当前状态**: 
- ❌ **未实施**
- ❌ **不得声称已验证**

**如果实施，必须验证**:
- [ ] 不同 provider 的 agent 可以协作
- [ ] Provider fallback 正确
- [ ] Profile-level policy 限制生效
- [ ] Rate limit 正确处理
- [ ] Provider timeout 独立配置
- [ ] Provider health 正确追踪
- [ ] Secret 不跨 provider 泄露
- [ ] Replay 记录所有 provider identity

---

## 验收决策树

```
开始
 │
 ├─ 是否有 SITINA_LIVE_TEST=1？
 │   │
 │   ├─ NO → 运行 Mock Baseline
 │   │        └─ 通过 → Mock 验收通过
 │   │        └─ 失败 → 修复后重试
 │   │
 │   └─ YES → 是否有 DeepSeek profile？
 │       │
 │       ├─ NO → Skip live tests
 │       │
 │       └─ YES → 运行 Live Minimal
 │                  │
 │                  ├─ 通过 → DeepSeek-only Live 验收通过
 │                  │
 │                  └─ 失败 → 检查失败类型
 │                             │
 │                             ├─ Timeout → 调整 timeout 或优化
 │                             ├─ Parse Error → 修复 parser
 │                             ├─ Provider Error → 检查 profile/quota
 │                             └─ Logic Error → 修复逻辑
```

## 声明规范

### 可以声称（当前）

如果 **Mock Baseline 通过**:

1. ✅ "Sitina 是 Controlled Multi-Agent Collaboration Runtime"
2. ✅ "Mock provider 多 Agent 协作验证通过"
3. ✅ "支持 proposal competition"
4. ✅ "支持 handoff negotiation"
5. ✅ "支持 arbitration (ask_user, block)"
6. ✅ "支持 lease-based resource protection"
7. ✅ "支持 retry/rework loop"
8. ✅ "支持 multi-reviewer merge"
9. ✅ "支持 high-risk patch gate"
10. ✅ "支持 side-effect descriptor"
11. ✅ "支持 audit & replay (dry-run)"
12. ✅ "支持 agent identity isolation (single provider, multi-role)"

如果 **DeepSeek-only Live 最小闭环通过**:

13. ✅ "Live provider single-provider multi-role path 验证通过"
14. ✅ "Live provider terminal event 强制"
15. ✅ "Live provider secret safety"
16. ✅ "Live provider identity audit"
17. ✅ "Live replay dry-run"

### 不能声称（当前）

1. ❌ "Live provider 完整验证" (只有最小闭环)
2. ❌ "Multi-provider live" (未测试)
3. ❌ "Fully autonomous" (受控边界)
4. ❌ "Automatic merge" (不存在)
5. ❌ "Real side-effect replay" (replay 是 dry-run)
6. ❌ "Remote MCP enabled" (默认 disabled)
7. ❌ "Memory auto-accept" (需要 review)
8. ❌ "Long-running auto-execute" (需要 approval)

### 永远不能声称

1. ❌ "All-deepseek 是失败" → 应该: "All-deepseek 是合法测试配置"
2. ❌ "必须用不同模型才是多 Agent" → 应该: "Agent 身份隔离即可"
3. ❌ "Live provider 默认执行" → 应该: "需要显式 provider_mode=live"

## Skipped Tests 判定

### 合法 Skip 原因

1. ✅ `SITINA_LIVE_TEST != 1` (环境变量未设置)
2. ✅ Profile 不可用 (配置文件缺失)
3. ✅ Network 不可达 (网络故障)
4. ✅ Provider quota 耗尽 (临时，可恢复)
5. ✅ Provider unavailable (temporary health check failure)

### 非法 Skip 原因

1. ❌ "Live tests too slow" (不是 skip 理由)
2. ❌ "Live tests cost money" (这是 live test 的本质)
3. ❌ "Mock is good enough" (mock 和 live 是两套验收)

### Skipped ≠ Passed

**重要**: 
- Skipped tests 不等于 passed tests
- 报告必须明确区分 passed / skipped / failed
- Skipped 原因必须记录

## 故障排查

### Live Test Timeout

**症状**: Live run 卡住或超时

**排查**:
1. 检查 provider 是否可达
2. 检查 read_timeout 配置
3. 检查 run_deadline 配置
4. 检查 provider quota
5. 检查网络延迟

**解决**:
- 调整 timeout 配置
- 使用 checkpoint resume
- 优化 prompt 减少 token
- 限制 evaluator 数量

### Live Test Parse Error

**症状**: Provider 返回无法解析

**排查**:
1. 检查 provider output 格式
2. 检查 schema validation
3. 检查 repair 逻辑

**解决**:
- 完善 parser
- 增加 repair attempts
- Fail-closed (block run)

### Live Test Secret Leak

**症状**: Secret scan 发现泄露

**排查**:
1. 检查 provider identity redaction
2. 检查 ledger/audit/trace
3. 检查 error message
4. 检查 debug log

**解决**:
- 强化 redaction
- 移除 secret from error
- 清理已泄露数据

## 版本历史

- **v1.0** (2026-07-09): 初始版本，明确三套验收标准
