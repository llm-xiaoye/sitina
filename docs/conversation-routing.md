# Conversation Routing

Sitina terminal chat has three visible session modes. `AUTO` is the startup
default, `FAST` is a forced one-Agent path, and `MULTI` is a forced reviewed
multi-Agent path. The mode remains active until another mode command or exit;
`/new` does not reset it.

## AUTO

The first routing stage is local and deterministic. It uses the versioned
`config/conversation_router.json` policy and consumes no Provider request.
Greetings, definitions, short translations, rewrites, simple CLI help, and
single-goal explanations normally resolve to FAST. Comparisons, architecture
or migration design, complete implementation planning, code or security
review, cross-verification, uncertain diagnosis, high-risk medical/legal/
financial content, and conflicting constraints resolve to MULTI.

If AUTO initially selects FAST, the Agent returns structured confidence and an
optional `needs_multi` signal. `needs_multi=true` or `confidence=low` creates a
Journal escalation fact and starts MULTI. The FAST answer is not displayed or
admitted as a reviewed Proposal; MULTI receives only its safe hash/confidence/
reason summary.

## FAST

`/fast` forces FAST even for a complex request. A registered Agent must pass
the `proposal`, `synthesis`, and `read-only` capability filters; the current
registry selects `agent-forge` through the normal Scheduler. The per-run
Provider ceiling is one request. The normal success evidence therefore records
one logical call, one physical send, zero Proposal competition, zero Reviewer
calls, zero retry/fallback, and zero external mutation. A low-confidence forced
FAST answer is displayed with an explicit reminder that it was not independently
reviewed and can be retried after `/multi`.

## MULTI

`/multi` forces the existing `TrueMultiAgentProductionRuntime`. Ordinary chat
is constrained to read-only Proposal and Review: goal analysis, two independent
candidate answers, independent review, selection, and a successful terminal
decision. Extra collaboration protocols are not enabled merely because the
session is in MULTI.

## State and recovery

`/mode` shows the current session mode and the previous actual route with its
reasons. `/retry` is available only after the last turn failed or was cancelled;
a successful turn clears it. `/new` clears successful history and retry state
while preserving the mode. Context is process-local and bounded only by the
token-aware limits in
`config/context_policy.json`; no separate character constant is authoritative.

Provider failures never trigger a hidden retry or Provider switch. The UI
reports authentication, Keychain, network, quota/rate-limit, schema, and
terminal failures without printing credentials. Ctrl+C cancels the current
turn, does not add history, and does not resend automatically.

## Authority and safety

FAST and MULTI both use Production Journal/CAS authority, encrypted CAS input
and output snapshots, bounded DeepSeek egress, Provider Effect/Result admission,
Secret scan, physical-send and token/cost accounting, and terminal evidence.
Runtime activation binds all conversation source files and the router config by
hash. Chat never uses Claude Code, Legacy SQLite, conversation JSON/log files,
shell/Git mutation, remote MCP, publication, Memory acceptance, or other
external business effects.

## Suggestion preview

`sitina suggest <task description>` runs this same local `ConversationRouter`
with its versioned complexity, domain, risk, budget, SLA, and history policy,
then previews the actual workflow/team policy. It does not use the optional
model classifier: `side_effects.provider_calls`, `network_calls`, and
`state_writes` remain zero. The reported route and decision path must therefore
match a direct router decision for the same description, context, overrides,
budget, and SLA.

The command also reports task type, proposal-round/worktree decisions,
team/topology, confidence, assumptions, risks, and override parameters. Its
token/time intervals are explicitly versioned estimates. Provider response
usage is authoritative only after a real call and is never synthesized from
these ranges. Budget or SLA constraints are returned as a diagnostic
`constraint_blocked` result rather than weakened safety policy.
