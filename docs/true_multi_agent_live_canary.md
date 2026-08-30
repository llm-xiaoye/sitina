# MULTI live capability runbook

Sitina defaults to `MOCK_ONLY` in `config/sitina.yaml`. A normal process, a
new session, or a restart cannot physically send a Provider request from that
configuration. `config/true_multi_agent_policy.json` keeps external mutation
and handoff bypass disabled by default.

An operator may request a DeepSeek canary only for the current conversation
session with the explicit `--live` capability, for example:

```text
sitina chat --live --workspace /absolute/path/to/selected/workspace
```

Then use `/multi` and state the requested code change explicitly. The runtime
binds that capability to the session ID, run ID, `deepseek-live-canary`
purpose, a 15-minute expiry, the approved DeepSeek model/host, and a signed
activation manifest. The capability is not persisted as a reusable
permission. A batch `sitina run --provider-mode live` without a current
conversation session is rejected before physical send. The broker is a
same-user CLI parent/child trust boundary; it is not advertised as protection
against arbitrary code already running as the same OS user. That stronger
claim would require an installed OS trust root, which Code Mode does not add.

The ordinary live canary follows the configured bounded retry/fallback policy
and records the actual provider/model used. The separately labelled
`deepseek-token-test` activation sets `deepseek_token_test_no_fallback` in the
signed activation mapping; even an available fallback profile is then denied.
Provider physical attempts, retry/fallback count, actual provider/model, token
usage, tool calls, activation binding, and failure/recovery evidence are
recorded in the Journal/CAS audit chain. The CLI-owned host, rather than a
worker or injected client, performs the live HTTP request and settles its
transport receipt. A canary must not be used as evidence for deployment or
production mutation.

Production deployment remains a separate, explicitly coordinated operation;
the source workspace must first be independently reviewed and accepted.
