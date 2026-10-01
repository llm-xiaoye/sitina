# Batch 2 G0: bounded-context and query design

Status: design only. This gate made no source-code change and made no Provider call.

Scope is limited to `sitina-loop-v1-r4` R10 and Batch 2: bounded requests,
usable task-history queries, and continued input processing. It retains one
background coordinator and the existing five internal responsibilities. Recovery,
capability publication, experience publication, and Batch 3-7 work remain out of
scope.

## Read-only audit findings

| Concern | Current concrete entry point | G0 finding |
|---|---|---|
| Effective task input | `core/sitina/loop/task_runtime.py:LoopTaskRunner._effective_goal` | Reads the immutable goal and concatenates every handled MESSAGE/CORRECTION body. Request size therefore grows with all user input. |
| Main tool loop | `core/sitina/extensions/runtime.py:AutonomousRuntime._run_active` | Starts with the whole task, appends every assistant turn and every complete `ToolResult.content()`, then submits the ever-growing list. It preserves protocol pairing, but has no context compaction/admission. |
| Large tool results | `core/sitina/loop/task_runtime.py:LoopOperationAdapter.tool_call` and `core/sitina/loop/coordinator.py:LoopBackend.execute_operation` | The complete result is already committed to encrypted CAS before it returns to the runtime, which is a usable persistence base. The runtime nevertheless injects the full result in the next request. |
| Large Provider output | `LoopOperationAdapter.provider_call` | The full Provider turn and tool calls are persisted before returning. The runtime still keeps the full assistant text in subsequent messages. |
| Check/review growth | `LoopTaskRunner._program_check`, `_run_cycles` | Complete stdout/stderr are persisted, embedded again in the artifact, and interpolated into reviewer input together with the full main response. Reviewer requests can therefore overflow independently of main requests. |
| Actual wire request | `core/sitina/runners/provider.py:AnthropicCompatibleClient._tool_turn_openai` and `_tool_turn_anthropic` | These methods finally construct the exact Provider body, including protocol conversion. No pre-send counter or context-capacity check exists. |
| Capacity identity | `ProviderProfile` and current configuration | The profile binds provider/model/wire but carries no declared model context capacity. `config/context_policy.json` is a generic conversation policy, not an exact profile/model capacity source. |
| Old token budget | `core/sitina/conversation/context_management.py:ContextWindowPlanner` and `ContextBudgetAllocator` | They subtract cumulative `TokenBudgetContract.consumed_tokens` from a maximum. That is a run/task budget and must not be reused as a Batch 2 total-task token/turn/cost limit. |
| History helper | `AuthorizedContextHistory` in the same module | This is an in-memory list/ACL helper. It is not built from Loop Journal/CAS and is not exposed as a callable model tool, so it is not a Batch 2 history query. |
| Task projection | `LoopBackend._project` and `TaskProjection` | Recovery replay retains all inputs, operations, acceptances, and attempt settlements. This remains authoritative state, but it must never be serialized wholesale into a model request. |
| Mid-run input | `LoopControlAuthority`, `handle_next_input`, and `LoopOperationAdapter.input_or_control_changed` | Persisted input already advances goal/acceptance/handled-input versions and cancels stale main/reviewer work. Batch 2 should extend this binding across context assembly, query, and summary commits. |
| Context wait state | `core/sitina/loop/model.py:TaskStatus` and `LoopBackend.dock_waiting` | There is no `CONTEXT_BLOCKED`. Existing `STALLED`/`WAITING_INPUT` would conflate context coverage failure with no-progress or another blocker. |

## Proposed implementation boundary

Keep context/history inside the existing context/memory responsibility. Add no
service, database, worker role, or task authority. The implementation should have
four small, explicit pieces:

1. A task-local `LoopContextIndex` built from the task's Journal events and their
   verified CAS references. It is a rebuildable view, not an authority.
2. A `TaskContextProjector` that produces a bounded, version-bound current task
   record rather than serializing `TaskProjection` or concatenating all input.
3. A protocol-aware `ProviderRequestPlanner` that renders and admits the exact
   next wire body before any physical send.
4. A real read-only `sitina_history_query` tool bound to the current task/session
   and backed by the index plus verified CAS reads.

The existing state/scheduling, agent binding, operation execution, validation, and
context/memory responsibilities remain the five modules. These pieces belong to
the last responsibility or are narrow adapters at existing Provider/runtime
boundaries.

## Request data flow and limits

```text
immutable goal + input events + current task versions + evidence/operation refs
  -> task-local index (Journal-derived; CAS refs verified)
  -> bounded TaskContextProjection
       current execution unit and applicable hard constraints
       acceptance summary and open obligations
       current blocker
       eliminated-method index
       recent complete protocol groups
       selected retrieval receipts
  -> protocol-neutral request messages
  -> exact OpenAI/Anthropic wire rendering
  -> count exact rendered body + reserves
  -> binding/capacity recheck
  -> existing Loop provider operation intent
  -> physical send
```

### Exact request accounting

The source of truth for one admission must be the exact immutable request body
that `_tool_turn_openai` or `_tool_turn_anthropic` would pass to `_request_json`.
Rendering and sending must share that object or its verified hash; duplicating the
conversion in the caller would allow accounting drift. A protocol fallback, if a
caller permits one, must render and admit the fallback shape separately before it
is sent.

The admission receipt records component counts for system text, converted tool
schemas, task/constraint projection, protocol-neutral/wire message wrapper,
recent complete assistant-tool groups, summaries, and retrieval receipts. It also
records the count/hash of the exact complete body, so component labels cannot
hide uncounted JSON/message overhead.

For each call:

`exact_input_bound + output_reserve + next_tool_turn_receipt_reserve <= declared_model_capacity`

`output_reserve` is the actual `max_tokens` value for that call. The next-tool
reserve is one configurable aggregate allowance for all bounded receipts produced
by the next tool-call group, not an unbounded allowance per parallel call. If a
tool group cannot be represented within it, the group is persisted but the next
model call becomes `CONTEXT_BLOCKED`.

Provider-reported usage remains post-call actual usage. It is diagnostic and does
not decrement a hidden task total. `max_turns` remains `None` for this path, and
neither `TokenBudgetContract` nor `max_live_tokens_per_run` may stop the task.

The model-capacity source must be an explicit configuration entry keyed by exact
provider profile, endpoint host, exact model, and wire protocol. A missing or mismatched entry is
not inferred from a model name or the current generic 24k conversation policy; it
causes pre-send `CONTEXT_BLOCKED`.

When an exact provider tokenizer is configured and available, record its identity
and use it. Otherwise use a documented conservative upper-bound counter over the
UTF-8 bytes of the exact serialized wire body plus explicit message/protocol
overhead, label the result `conservative-fallback`, and never report it as actual
tokens. If the active wire/tokenizer cannot be safely upper-bounded, fail closed
as `CONTEXT_BLOCKED` instead of guessing.

### Bounded task projection

Replace `_effective_goal` with a version-bound task projection. The immutable
original goal and every input body stay in CAS. The model-facing record contains:

- current execution unit and its complete applicable hard constraints;
- the current goal/acceptance/handled-input versions and source refs;
- required outcomes, acceptance-method identity, and open obligations;
- current blocker and structured progress;
- a compact key-eliminated-method table whose rows retain evidence refs;
- recent protocol groups and a deterministic directory of older source refs.

The projection has its own serialized-byte/token ceiling before request assembly.
It contains counts and bounded rows, never the full `inputs`, `operations`, or
`attempt_settlements` collections from `TaskProjection`.

User-authored goal/correction text is not silently shortened. A summary may replace
compressible dialog, outputs, and evidence descriptions only when a coverage
manifest binds every replaced source range/ref and preserves the current
requirement ledger. Re-summarization consumes the last verified ledger/manifest,
not only the previous prose. A failed or unverifiable summary leaves originals
and the last verified projection unchanged. If all applicable hard constraints
cannot fit and coverage cannot be proven, the task is `CONTEXT_BLOCKED`.

### Persist-first receipts

Every tool result and Provider turn continues through the existing
`LoopBackend.execute_operation` commit before it can enter model context. After
that commit, `LoopOperationAdapter` returns a prompt receipt containing status,
source ref, content hash, total byte size, bounded excerpt/summary, and exact
history-query instructions. Small values may be included completely when the
aggregate receipt budget permits it. Large stdout, file contents, directory
listings, Provider text, and program output are never injected in full merely
because they were returned in the recent turn.

Assistant tool-call messages and all results for those calls form one atomic
protocol group. Selection either retains the complete group (including exact call
IDs and arguments) or drops the whole old group after its durable receipt/index
exists. It must never produce an orphan tool message or a result paired with a
different call.

The reviewer initial request uses the same projector/planner. It receives bounded
goal/constraint and changed-path summaries plus refs to the artifact, program
result, main result, and preflight evidence. It can read those refs through the
same task-local query tool. It no longer interpolates full program output or main
text.

## Usable history query contract

Expose `sitina_history_query` in both main and read-only reviewer catalogs. Its
schema has two operations:

- `list`: stable `cursor`, `limit`, optional kind filter, and `max_bytes`;
- `read`: task-scoped `source_ref`, byte `offset`, and `max_bytes`.

The result includes a schema/version, task/session binding hash, fixed Journal
frontier, ordered entry IDs/positions/kinds/timestamps, source refs, content
hashes, total and returned byte counts, `next_cursor` or `next_offset`, and
`has_more`. Repeated pages at the same frontier reconstruct the full original
canonical content byte-for-byte.

The caller does not supply another task ID. Each exposed source ref is an opaque
task-scoped handle resolved through the current task's index; a raw CAS ref or a
handle from another task/session returns `NOT_VISIBLE` without opening it. An
unknown local handle returns `MISSING`. An indexed handle whose CAS object or hash
no longer verifies returns `STALE_SOURCE` with the affected ref/hash and does not
silently disappear. Query result size is enforced before the result becomes a
prompt receipt.

This is not a paper index: `LoopContextIndex` is rebuilt from actual task events,
the tool handler resolves entries through it, and content pages come from
`ContextMemoryModule.read` with the event-bound hash. Query calls remain ordinary
read operations under `LoopOperationAdapter`, so their intended/result records and
task-version bindings remain auditable.

## Concurrent input and terminal safety

Context projections, summary manifests, query snapshots, main requests, and review
requests bind `run_instance_id`, `execution_epoch`, `goal_version`,
`acceptance_version`, `handled_input_seq`, artifact ref where applicable, and a
Journal frontier. A summary/index snapshot is committed with an expected stream
version; an intervening input makes the snapshot stale. Immediately before send,
the existing provider-operation path rechecks the same binding.

A MESSAGE or CORRECTION received during compaction, query, main work, program
checking, or review therefore:

1. persists before acknowledgement;
2. advances goal and acceptance versions under the 1b control authority;
3. causes the old operation response to be retained only as old-version evidence;
4. prevents it from entering a new request or satisfying current acceptance;
5. restarts projection from the newest handled-input position.

Old acceptance records may remain historically queryable, but current projection
and completion validation exclude them by version. The existing conditional
terminal commit continues to be the sole logical terminal, so a late response
cannot create a second terminal.

Add non-terminal `TaskStatus.CONTEXT_BLOCKED` and permit it in the waiting dock.
Its durable reason records the capacity source, counting mode, component breakdown,
required source refs that could not be covered, and the concrete split/configuration
needed to resume. Entering it does not call `settle_attempt`, does not increment a
no-progress counter, and cannot propose FAILED/SUCCEEDED. New handled input can
return it to RUNNABLE through the existing control path.

## G1/G2 acceptance matrix

| Case | Falsifying setup | Required observation |
|---|---|---|
| Exact main request bound | Large system text, tool schemas, task table, recent group, summary, and retrieval | Captured final OpenAI and Anthropic bodies match the admission hash; every component plus protocol overhead is counted; output and next-tool reserves fit. |
| Exact reviewer request bound | Huge main response and program stdout/stderr | The captured reviewer wire body is bounded and contains refs/receipts rather than full values; its own admission is tested, not just helper output. |
| Large tool output | Tool returns multi-megabyte content | Complete value is readable from CAS after commit; the immediate prompt sees a bounded receipt; paged query reconstructs the original exactly. |
| Large Provider/tool-call turn | Provider returns long text and multiple tool calls | Full turn is persisted; the next request stays bounded and retains one complete, valid assistant/tool-result protocol group. |
| 100+ useful turns | Scripted distinct read/evidence turns | Every actual call is bounded; no cumulative token/turn/cost cap stops the task. |
| Multiple summaries | At least three compactions with early `REQ-EARLY`, later evidence, and newest correction `REQ-LATEST` | Final main and reviewer requests retain both current requirements and source refs; each summary's manifest covers the originals, not merely its predecessor prose. |
| Full original recovery | Goal, corrections, failure text, and Unicode tool output span many pages | History list/read pagination reconstructs exact canonical originals with hashes, sizes, and stable frontier. |
| Cross-task/session isolation | Give task B a valid handle/CAS ref observed from task A | B gets `NOT_VISIBLE`; no content or existence oracle leaks. |
| Missing/stale ref | Remove or corrupt a test CAS object after an indexed event | Query returns explicit `STALE_SOURCE`/`MISSING`; the index row remains visible and no summary claims the evidence is present. |
| Over-cap hard constraints | Required constraints alone exceed declared capacity or cannot be coverage-verified | Zero Provider sends; status is `CONTEXT_BLOCKED`; no failure terminal and no no-progress settlement. |
| Unknown tokenizer/capacity | Exact model policy absent, mismatched, or tokenizer has no safe fallback | Pre-send `CONTEXT_BLOCKED` with honest counting/capacity reason; no guessed limit or actual-token claim. |
| Correction during every phase | Barriers inject a correction during compaction, history query, main Provider wait, program check, and review | Old results persist as versioned evidence but cannot enter current acceptance; latest input is processed; one terminal at most. |
| Bounded task record | Thousands of inputs/operations/attempts | The model-facing task projection remains within its ceiling and contains bounded counts/refs; no `TaskProjection.as_dict()` or full collection is embedded. |
| Summary failure | Compressor fails after a valid checkpoint | Original CAS content and last verified ledger remain active; task continues if they fit, otherwise becomes `CONTEXT_BLOCKED`. |

Tests should exercise `LoopTaskRunner` through the Batch 2 CLI/runtime wiring and
capture the exact final request passed to the Provider client. Pure selector,
counter, or index-helper tests are necessary but not sufficient.

## Supervisor decisions requested for G1

1. **Capacity registry location and missing-entry behavior.** Recommend a new
   Loop-specific declarative policy keyed by exact profile/endpoint/model/wire, copied into
   the existing provider home, with fail-closed `CONTEXT_BLOCKED` on absence. Do
   not reinterpret the generic `context_policy.json` or provider run budgets.
2. **Unknown-tokenizer fallback.** Recommend exact tokenizer adapters when
   qualified; otherwise a clearly named UTF-8 serialized-body upper bound. If a
   provider adapter cannot guarantee that bound, block instead of applying a
   heuristic chars-per-token estimate.
3. **Next-tool reserve unit.** Recommend one configurable aggregate receipt budget
   per logical tool-call turn, so parallel calls cannot multiply unbounded prompt
   space. Exact numeric values should be qualification data, not embedded constants.
4. **History reference form.** Recommend opaque task-scoped handles backed by
   event-bound CAS refs, with list/read byte pagination. Do not expose unrestricted
   CAS reads to the model.
5. **Hard-constraint compaction policy.** Recommend never model-summarizing away
   user hard constraints in Batch 2. Compress only replaceable prose/evidence and
   retain a verified requirement/source ledger; unresolved coverage becomes
   `CONTEXT_BLOCKED`.
6. **Integration seam.** Recommend one exact wire renderer/admission object in the
   Provider layer, driven by a Loop projector callback in `AutonomousRuntime`, so
   main and reviewer share enforcement while non-Loop consumers are not silently
   assigned a task budget.
7. **Explicit state.** Recommend adding non-terminal `CONTEXT_BLOCKED`, rather than
   overloading `WAITING_INPUT` or `STALLED`, because R10 explicitly excludes this
   condition from failure and no-progress accounting.

Known Batch 1b limits remain unchanged: full process recovery, general UNKNOWN
effect reconciliation, general semantic progress classification, and experience
publication stay for later batches. Visual acceptance remains NOT_RUN.

End-of-gate marker: `B2-G0-READY`
