# Tool, permission, and security boundaries

Phase 06 treats every external, file, network, command, tool, memory, and model-originated value as untrusted. Authorization is enforced in code before invocation; prompt text cannot grant capabilities.

## MCP and tool authorization

- `ToolAccessPolicy` evaluates principal inheritance, server, tool, action, resource, canonical argument names, and risk. No matching rule means deny.
- Explicit deny rules override wildcard allows. Path traversal, resource-root escape, conflicting aliases, unknown risk, and inheritance cycles fail closed.
- Extension MCP registrations produce exact server/tool rules from the installed manifest and granted permission. Non-read MCP calls also require the existing per-call approval callback.
- Role capabilities are exact sets from `config/agent_capabilities.yaml`; forbidden actions override otherwise valid capabilities.

## Execution, retry, and audit

- One timeout contract carries connection, read, total, and cleanup-grace deadlines. Total timeout propagates cancellation to the adapter and waits for deterministic cleanup.
- Retry uses Failure Taxonomy 1.0 and the phase-05 scheduler. A retryable tool failure still requires an idempotent operation or an idempotency key; otherwise it becomes manual recovery.
- Tool audit records only the normalized tool name, redacted argument summary/hash, permission decision, attempt, duration, result reference, and redacted error envelope. Raw arguments and raw result bodies are excluded from the tool audit event.
- Risk decisions combine versioned static action weights with capability presence, untrusted context, external target, and impact scope. Unknown actions score critical and deny.

## Approval, prompt, secret, and side-effect controls

- Pending approval facts bind wait ID, run, Effect, binding hash, and expiry. Approval is consumed once; timeout automatically denies and removes waiting state.
- System/developer content may carry trusted instructions, but prompt text never grants a capability; executable policy and an exact approval remain authoritative. User content is intent; tool and memory content are data-only. Tool result envelopes explicitly cannot grant permissions or override instructions.
- The structured secret detector normalizes Unicode, URL-decodes, inspects base64 and split fragments, checks known credential prefixes and high-entropy formats, and reports only safe locations/types across log and export scans.
- Effect Gateway, approval, worktree/application guards, and compensation remain the mutation path. Offline replay/evaluation exposes no live permit, lease, network, subprocess, or external Effect capability.
