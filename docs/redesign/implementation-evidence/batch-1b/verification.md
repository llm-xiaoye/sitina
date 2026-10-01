# Batch 1b verification

Batch 1b is complete within its declared development scope. The guarded formal CLI now runs short code-rework, readonly, and no-change tasks on the Batch 1a durable skeleton; corrections, pause, and cancel input cannot be crossed by stale evidence or terminal proposals. This is not a production cutover or a claim that Batch 2–7 work is complete.

## Outcome

- Formal entry: `bin/sitina-r4-dev loop-task`.
- Physical development root: `/Users/moss/SitinaHub-r4-b0-1a` on branch `codex/sitina-r4-b0-1a`, base HEAD `27edb59f2ff592fb793a717c6a71ffd8d3d9610a`.
- Unique persistent authority: `/Users/moss/SitinaHub-r4-b0-1a/runtime/r4-loop-dev/state`.
- Interpreter: `/Users/moss/SitinaHub-r4-b0-1a/.venv-r4/bin/python` (Python 3.12.14).
- Provider: live DeepSeek, bounded transport retry, no fallback. There is no total task turn or cost cap.
- Shared completion contract: the runtime constructs `AcceptanceCase` and `CaseObservation` and directly calls `LoopAcceptanceEvaluator(mode="daily")`; successful formal tasks persist `CASE_PASS` in the acceptance and terminal result.
- No merge, push, production write, or cutover occurred. `/Users/moss/SitinaHub` was used only as the target of the declared read-only credential symlink; its database was not opened or queried.

The machine-readable summary is [batch-report.json](batch-report.json). Exact command arrays, task identities, artifact references, hashes, and Journal positions are in [formal-cli-evidence.json](formal-cli-evidence.json). Tests and independent evidence references are in [isolation-and-unit-verification.json](isolation-and-unit-verification.json).

## Formal CLI evidence

All accepted cases used the same manifest-declared state authority root.

| Case | Result | Direct evidence |
|---|---|---|
| Readonly facts | `SUCCEEDED`, cycle 1, zero diff | `canonical-readonly-facts-001` read `facts.txt`, calculated `17 + 29 = 46`, returned the source filename, and retained file hash `3b559f…7848`. |
| Code rework | `SUCCEEDED`, cycle 1 | `canonical-code-rework-001` used fixed method `4ceb41…0ab3`; preflight was `FAIL`, `target.py` changed from hash `a210d9…bf5b` to `255688…629`, the same method then passed, strict independent review passed, and the shared evaluator returned `CASE_PASS`. |
| Initially correct code | `SUCCEEDED`, cycle 1, zero diff | `canonical-code-correct-001` retained `answer.py` hash `5db028…b3fc`; preflight and final invocation of fixed method `1f1a47…77d` both passed, strict independent review passed, and the shared evaluator returned `CASE_PASS`. |
| Correction during old review | `SUCCEEDED`, cycle 2, goal version 2 | `canonical-correction-002` began with an `OLD` goal and a neutral fixed check accepting either well-formed `OLD` or `NEW`. At Journal positions 225–227, the correction was received/handled and the old reviewer Provider result was persisted `PARTIAL`. Cycle 2 changed the file to `NEW`, ran the same check, obtained a review explicitly bound to the latest persisted correction, and committed one success terminal. |
| Pause | `PAUSED`, no terminal | `canonical-pause-002` received and handled PAUSE at positions 155–156. The Provider result remained traceable but could not advance the task. `value.txt` retained hash `b8c97d…f187`. |
| Cancel after a completed write | `CANCELLED`, exit 130, one terminal | After cancellation artifact capture and the repeated-CANCEL fix, `canonical-cancel-005` persisted the known file edit as `SUCCEEDED` at position 296, received/handled CANCEL at 298–299, persisted the in-flight Provider result `PARTIAL` at 300, captured the current cancellation artifact at 301, and terminated at 302. The output names the completed write, the retained `value.txt` change, and `success_commit_cancelled=true`; no write intent follows CANCEL. The later UNKNOWN non-looping branch is covered by the final targeted regression, not attributed to this live run. |

Completed effects are not rolled back by cancellation. Cancellation instead prevents a success submission and makes the retained current artifact explicit. A settled `UNKNOWN` effect is different: the task returns `recovery_blocked`, keeps responsibility, and does not attempt terminalization.

Superseded runs are preserved rather than rewritten. In particular, old per-task `state/real-*` roots became invalid after the unique-authority fix; `canonical-correction-001` had a confounded check; `canonical-pause-001` completed before input connected; and `canonical-cancel-003` exposed the reviewer-cancellation exception. None is counted as final evidence.

## Race, authority, and exit verification

The runtime carries one immutable binding through goal read → main model → program check → artifact update → independent review → acceptance → terminal commit. A correction in any handoff invalidates that stage; an artifact update is the only intended step that advances the binding and its returned projection becomes the next stage's binding. Tests cover corrections after the goal read, before the check adapter, during the check, during review, after the review verdict, and in the acceptance commit gap.

The state manifest declares one authority root. An alternate `--state-root` for the same workspace is rejected before directory creation, authority acquisition, Backend initialization, or business dispatch, both while the canonical owner is live and after it exits with UNKNOWN responsibility in its durable state.

R11 progress support in this batch is deliberately narrow. A fixed check may write exact `SITINA_LOOP_CHECK_PROGRESS_V1` data containing stable `satisfied` and `remaining` requirement IDs. Only a true set reduction over the same requirement universe resets the consecutive no-progress count. A real six-cycle test produced `[false, true, false, false, false, false]`: the second attempt made verifiable progress, then four unrelated writes led to `STALLED`. Rewording, renamed IDs, and unrelated edits do not reset the count. General semantic progress review and complex attempt ownership are not implemented.

Cancellation races are bounded. A repeated CANCEL in the terminal commit gap causes a fresh binding check and still creates exactly one terminal event. An unresolved effect is explicitly excluded from that retry path and produces one durable `cancel-unknown-operation-effect` settlement plus `recovery_blocked`, without repeatedly calling `propose_terminal`.

## Verification commands

The final scoped regression command is recorded in [isolation-and-unit-verification.json](isolation-and-unit-verification.json) and passes 105 tests. It covers the frozen Loop evaluator/Batch 1a behavior, Batch 1b boundary/launcher/runtime, extension integration, and Provider tool protocol. `git diff --check`, JSON parsing for every Batch 1b evidence file, and targeted module compilation also pass.

The supervisor independently reproduced the earlier counterexamples and then verified their fixes. Its final read-only audit authenticated 302 Journal events without changing the Journal segment hash, matched all six representative CAS artifact snapshots to the actual files, verified 72 operation results had earlier intents and valid CAS, checked terminal uniqueness, and found no write intent after PAUSE/CANCEL. The fixed independent evidence is referenced by absolute path and hash in [isolation-and-unit-verification.json](isolation-and-unit-verification.json).

The frozen Batch 0/1a evidence file remains byte-identical at SHA-256 `ec44b858136742c267ffbb2c6915442e69ed9572afcc626f32311f56d59db024`.

## Scope not claimed

Batch 1b does not implement or verify Batch 2 long-context/history, Batch 3 background recovery and UNKNOWN reconciliation, Batch 4 Skill publication and ordinary-session use, Batch 5 publication interruption matrices, Batch 6 complete experience disposition, or Batch 7 long-task/visual/full-release acceptance. Program checks currently support only the pinned Python interpreter; other executors return `NOT_RUN` and `WAITING_INPUT`. Computer use and visual/TCC validation remain deferred by the current specification.
