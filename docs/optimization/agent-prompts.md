# Agent prompt contracts

Sitina renders every role prompt from two inputs: the role text in `prompts/agents/` and the versioned machine contract in `config/agent_prompt_contracts.json`. The rendered contract is hash-bound between stable sentinels. A missing prompt, schema mismatch, role mismatch, policy-rubric divergence, or invalid responsibility matrix prevents the role from starting in mock and live modes.

The shared contract is the authority for factual claims, trust/source boundaries, token-budget behavior, proposal diversity, the PR-05 evaluation rubric and bounded schema repair. Role entries bind the exact output schema, topology, read/write boundary, completion condition, escalation route and raw output fields. Prompts refer to these contracts instead of defining parallel state or rubric vocabularies.

Responsibility ownership is intentionally singular: Critic discovers adversarial problems, evaluator is a scoring function, Reviewer owns the acceptance gate, and Arbiter resolves conflicts. Evaluator-capable agents can execute the shared scoring function without inheriting its ownership or Reviewer's gate authority.

Schema repair is limited to one live retry. The first invalid response and the repair attempt are separately observable, both physical calls remain in usage/accounting evidence, and the repair is admitted only while output and run token budget remain. A repeated schema failure terminates as `agent_schema_invalid`; it never loops or falls back to mock.
