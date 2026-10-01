# Sitina 重建设计文档

2026-09-09 · T5 当前执行：用户已授权真实只读子任务接线，采用 sitina-delegation-v1；当前为方案与合同准备，runtime 尚未验收。实施使用 gpt-5.6-luna / xhigh，监督通过 wait_threads。旧 V1 CONTRACT_ONLY 和批次 3 报告保持历史含义。范围与放行见[T5 只读子任务实施计划](/Users/moss/Documents/ChatGPT/sitinaRedesign/Sitina-r4-T5只读子任务实施计划-2026-09-09.md)及[T5 当前监督状态](/Users/moss/Documents/ChatGPT/sitinaRedesign/implementation-supervision-t5-2026-09-09/state.json)；批次 4—7 与生产切流不在本轮范围。

制定日期：2026-09-04；本版同步：2026-09-08。规范版本：`sitina-loop-v1-r4`。

状态：规范仍以本目录合同为准；独立开发副本已完成批次 0–2 的开发范围实现与验收，但尚未合并、推送或切换生产入口。已授权的批次 3A—3D 已完成声明范围验收；本批通过不能解释为完整首版通过。批次 4—7 未开始。

当前补强：2026-09-08 的终止机制七项优化已完成本轮声明范围，执行 00 R11 T1—T7，标识为 `sitina-termination-v1`。冻结源码通过 189 项独立组合测试，并完成真实 DeepSeek 思考模式下的只读、单文件修改与 Review V2、运行中取消路径验证；取消后的真实 CLI 离线状态读取保持 4,079 个状态文件哈希不变。T5 为纯合同与验证器 `CONTRACT_ONLY`，没有通用 spawn 接线。具体范围、非通过尝试、发送计量和证据见[本轮审查与验收](/Users/moss/Documents/ChatGPT/sitinaRedesign/Sitina-r4-终止机制七项优化审查与验收-2026-09-08.md)。本目录是独立开发副本的生效文档，原目录与既有 G3 快照保留历史身份。

本次 r4 采纳独立复审：获权后再核对，Journal 统一发布决议与可重建登记，候选清单逐项结算，最小持久骨架前置及规则覆盖登记，四类参考成果校准。原五模块与其他已解决约定保留；采用理由见[r4 修订说明](/Users/moss/Documents/ChatGPT/sitinaRedesign/Sitina-r4-复审采纳与执行细则-2026-09-06.md)。批次 0–2 的源码、配置、测试与证据仅存在于独立开发副本；生产入口保持不变。先读[有效决策基线](/Users/moss/Documents/ChatGPT/sitinaRedesign/阶段4-当前有效决策与审查基线.md)与[阶段 4 报告](/Users/moss/Documents/ChatGPT/sitinaRedesign/阶段4-Sitina-Loop-Agent重设计审查报告.md)，不要把历史分析的旧规则当作当前要求。

当前工作：[批次 3 后台连续性与恢复实施计划](/Users/moss/Documents/ChatGPT/sitinaRedesign/Sitina-r4-批次3后台连续性与恢复实施计划-2026-09-08.md)，合同 `sitina-continuity-v1`，执行 00 C1—C8。依次接通常驻宿主/重连、同版本新进程恢复、已有工具效果核实及跨任务崩溃验收。实施使用 gpt-5.6-luna / xhigh，监督通过 wait_threads 分阶段审查。3A—3D 已通过最终 388 项组合门禁及两例有限真实 CLI 验收，T5 真实子任务仍为 CONTRACT_ONLY。3A 证据见计划链接的监督目录，scheduled 回执误报已在 3B 修正并验证。

批次 3A—3D 的声明范围现已通过 [388 项独立组合测试](/Users/moss/Documents/ChatGPT/sitinaRedesign/implementation-supervision-batch-3-2026-09-08/3d-supervisor-gate-01.json)，400 份源码、测试、配置与合同文件在门禁和随后两例真实 DeepSeek 思考模式任务期间保持一致。可核实资源交接、稳定控制地址、UNKNOWN 下取消，以及原 main/check 的来源和跨进程接续已纳入最终验证。真实只读任务与“写入后检查运行中终止后台、新后台核实原结果”案例均通过声明范围验收；后者使用一次明确 resume，原验收脚本的 NOT_PASS 与补验依据分别保留，不能称为全自动脱困。详细调用、用量、限制、失败记录及文档更新身份见[批次 3 审查验收](/Users/moss/Documents/ChatGPT/sitinaRedesign/Sitina-r4-批次3后台连续性与恢复审查验收-2026-09-08.md)。shell 目前仅支持隔离的 `python -m unittest`，config validate、doctor、eval 仍为 NOT_RUN。T5 真实子任务仍为 CONTRACT_ONLY；批次 4—7、完整首版、合并与生产切流未完成。

## 实施状态

- 批次 0–1b：开发骨架、正式开发 CLI、短代码返工、只读／无需修改任务及输入屏障已完成其声明范围。
- 批次 2：有界请求、任务级历史查询、真实 Provider 长资料、独立只读 reviewer、思考模式私有续接、输出截断停靠及中途纠偏／取消已经过 G1、G2、G3 验证；最终证据见 [G3 live report](implementation-evidence/batch-2/g3-live-report.json)。
- 批次 3：后台、同版本恢复、已接入效果核实和交错已通过声明范围验收；一般 `UNKNOWN` 缺乏证据时仍须停靠。
- 后续待接入／验收：T5 真实只读子任务，批次 4–6 的 Skill 发布／中断矩阵／完整经验处置，以及批次 7 的长任务整体恢复、视觉和完整首版验收。生产切流、旧路径退役、merge、commit 与 push 均未执行。

## 这套文档是什么

将 Sitina 重建为个人使用的 Loop Agent，优先完成代码修改与验证、只读调查审查，以及需要多次试错的长期任务。代表性任务包含从 GitHub 获取能力、安装到 Sitina、在当前任务真实使用，并在新会话中继续使用。

现有正式执行路径已经接入 Forge 工具循环、有限验证返工、Journal/CAS 和部分制品验证。重设计的重点是统一入口、任务状态、验收、长期上下文、能力刷新和恢复。必须区分代码存在、实际接线与产品验收，不能根据一个角色接口推断整条链没有工具。

复用真实工具反馈、独立验证、Journal/CAS、受控执行和可追溯成果。首版必须包含记忆、长期运行、关闭窗口后后台继续和同机同版本恢复。多个助手并行编写候选方案与 computer use 属于后续范围；computer use 暂缓，不展开本轮实现。

## 生效顺序与阅读顺序

[00-本版生效规则与执行契约.md](00-本版生效规则与执行契约.md) 是本版规范入口，其 R01–R12 与同步后的正文共同描述 `sitina-loop-v1-r4`。历史方案和参考文章用于说明来源，不能覆盖用户最新要求。本轮已直接修订冲突正文；以后发现差异时应同时更新入口、相关正文与验收规则，不能把冲突留给实现者选择。

| 文件 | 内容 | 什么时候读 |
|---|---|---|
| [00-本版生效规则与执行契约.md](00-本版生效规则与执行契约.md) | 本版生效合同、责任、状态与关键提交约定 | 首先读取 |
| [01-总体设计.md](01-总体设计.md) | 范围、架构、决策与可复用能力 | 开工前 |
| [02-循环内核规格.md](02-循环内核规格.md) | Loop、任务状态、完成门、spawn、输入与恢复 | 循环实施前 |
| [03-记忆与检索.md](03-记忆与检索.md) | 任务连续性、检索、结项经验及生命周期 | 记忆实施前 |
| [04-实施步骤.md](04-实施步骤.md) | 分步接线、交付物、验收和回滚 | 每步开始前 |
| [05-危险区地图.md](05-危险区地图.md) | 实际加载、身份、执行和恢复依赖 | 跨边界修改前 |
| [06-禁止操作清单.md](06-禁止操作清单.md) | 保留用户内容、证据有效性与本版禁止项 | 开工前 |
| [07-基准规范.md](07-基准规范.md) | 真实用例、评分器、回归与保留集 | 基线和每步验收前 |

## 给执行者的规则

1. 功能验收第一。正式 CLI 的目标任务必须真正做成；组件测试通过、工具已注册或程序拒绝了错误输入，均不等于产品可用。
2. 按真实调用链确定依赖。修改文件内容也可能影响运行身份；删除前处理导入、manifest、配置和实际消费者。旧路径退役遵循先替代、再切流、最后删除。
3. 日常完成门与版本评分器必须采用相同的任务语义。没有统一 diff 非空或测试计数要求；等待用户输入不算任务完成。
4. 按 [04](04-实施步骤.md) 和各批证据报告区分设计、开发接线、真实案例与生产切流；批次 2 已接线并在独立开发副本验证，后续批次仍按各自前置验收推进。

## 资料与历史边界

- 当前代码事实及入口证据见[阶段 1 分析](/Users/moss/Documents/ChatGPT/sitinaRedesign/阶段1-Sitina现有代码与运行路径分析.md)和[阶段 2 对照](/Users/moss/Documents/ChatGPT/sitinaRedesign/阶段2-重设计理解与代码差距分析.md)。旧行号只作定位线索，动手时重开当前文件核实。
- 用户意图见[阶段 3 记录](/Users/moss/Documents/ChatGPT/sitinaRedesign/阶段3-设计意图与待确认事项.md)，证据化问题见[新架构审查](/Users/moss/Documents/ChatGPT/sitinaRedesign/Sitina新架构-证据化审查-2026-09-05.md)。
- 知识参考见[设计审查知识上下文](/Users/moss/Desktop/sitina/knowledge-context/设计审查知识上下文.md)。历史文档中引用的 `项目复盘/` 不作为本轮读取目标或高于当前用户要求的规范来源。
- 原八份文档的修订前快照保存在 `/Users/moss/Documents/ChatGPT/sitinaRedesign/phase3-contract-baseline-2026-09-05/redesign/`，用于追溯被替代决策，不继续执行其中已替代条款。

当前 T5 使用[T5 只读子任务实施计划](/Users/moss/Documents/ChatGPT/sitinaRedesign/Sitina-r4-T5只读子任务实施计划-2026-09-09.md)推进，实际状态见[T5 当前监督状态](/Users/moss/Documents/ChatGPT/sitinaRedesign/implementation-supervision-t5-2026-09-09/state.json)。T5 runtime 完成前仍明确标注未验收，批次 3 和旧纯合同结果仅证明各自历史范围。
