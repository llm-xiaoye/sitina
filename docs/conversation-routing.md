# Conversation Routing

Sitina's terminal interface has one public routing mode: AUTO. Running
`sitina` in a terminal opens the same controller as `sitina loop`. There is
no public command-line option or slash command that can force an execution
strategy.

## Automatic decision

The first routing stage is local and deterministic. It uses the versioned
`config/conversation_router.json` policy and consumes no Provider request.
Greetings, definitions, short translations, rewrites, simple CLI help, and
single-goal explanations normally select the single main Agent. Comparisons,
architecture or migration design, implementation planning, code or security
review, cross-verification, uncertain diagnosis, high-risk content, and
conflicting constraints select a main Agent plus independent review.

These are internal strategies, not session modes. Every message is submitted
to the same current `LoopHost` and executed by
`LoopTaskRunner.run_existing`. Both strategies therefore share the same
LoopBackend, Journal/CAS, authority lease, task projection, workspace boundary,
terminal decision, and recovery chain.

## Public controls

`/mode` is read-only: it displays AUTO, the most recent automatic strategy,
and the router's reasons. `/help` lists available commands. `/exit` and
`/quit` leave normally.

`/fast`, `/multi`, and `/auto` are rejected and do not change routing.
The retired `sitina chat` command remains an early side-effect-free refusal;
it does not inspect policy, state, workspace, credentials, or Provider
configuration and is never used as fallback.

## Authority and safety

The public interactive path is read-only in this release step. The single
Agent strategy uses the Runner's existing main `AutonomousRuntime`; it is
never launched beside the Loop as a second state system. The reviewed strategy
adds the Runner's existing independent read-only reviewer to that same task.
Neither route grants write authority.

An installed launch explicitly binds the physical source root, selected
interpreter, configuration root, unique state root, and managed workspace.
A marked development checkout retains its stricter marker and pinned
interpreter checks. Neither boundary can be bypassed by pretending an install
is a development checkout.

## State and recovery

Task state and terminal results are durable Loop state. Provider failures do
not trigger a hidden runtime switch, fallback to Legacy chat, or automatic
resend. A paused, blocked, stalled, failed, or cancelled task remains visible
through the existing Loop status and recovery surfaces.

## Suggestion preview

`sitina suggest <task description>` previews the same automatic routing
policy without Provider, network, tool, or state-writer calls. It accepts
budget, SLA, context, risk, task-type, and topology inputs, but it has no
`--mode` or `--prior-mode` option and cannot force the public route.
Reported token and time intervals are estimates rather than actual Provider
usage.
