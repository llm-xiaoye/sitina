# Sitina B+ Effect Gateway operations

## Scope and authority

Phase 4 implements the Effect/Attempt/Observation safety boundary only in
marked disposable homes and shadow mode. The checked-in adapter set is
`MOCK_ONLY`; it grants no live Provider, MCP, Tool, message, publication,
payment, deletion, or remote-mutation capability. Legacy remains the only
Production writer. Phase 4 evidence must never be interpreted as cutover,
Production Journal genesis, or permission to retrieve a real credential.

Every external trust-domain operation, including a read, disclosure,
reconciliation query, or compensation, has an immutable `effect_id` and exact
`EffectRequest` hash. A semantic request change gets a new Effect identity and
explicit `supersedes_effect_id`. A retry gets a new `effect_attempt_id`; an
Attempt may authorize at most one application-layer body transmission.

## State ownership

The Effect stream alone owns outcome, settlement, basis, execution cardinality,
open transmission exposure, and duplicate/loss risk. The Observation stream
holds authenticated external evidence and never owns the Effect outcome. The
closed legal outcome/settlement/basis matrix is implemented verbatim from the
formal specification; an unlisted combination produces a stable
`EFFECT_STATE_INVARIANT_REJECTED_V1` fact.

Important distinctions:

- `InvocationStarted` proves only that the local transport boundary was
  entered. It does not prove remote receipt.
- `MAY_HAVE_BEEN_SENT` is a local Attempt disposition, not remote success.
- `DURABLY_RECEIVED` proves encrypted spool custody only.
- `JOURNAL_ADMITTED` proves a durable canonical intake/rejection frame. It is
  still business truth only when its terminal disposition is
  `ADMITTED_BUSINESS`.
- `OUTCOME_UNKNOWN + SETTLED + POLICY_DISPOSITION` settles responsibility while
  preserving physical uncertainty. It is not confirmed success or failure.

## Dispatch boundary

The Gateway performs this order for a new transmission:

1. consume the exact Run/Closing Permit through the durable create-or-tombstone
   saga;
2. win the Effect stream `NO_STREAM` create CAS and confirm it at the source;
3. claim a single active Attempt under the current Task Fence;
4. freeze request, signed Adapter Manifest, exact approval, and opaque
   credential handle in `Prepared`;
5. activate every reservation in the Budget Bundle;
6. precheck the operational circuit breaker;
7. at the last moment, revalidate Task and Dispatch Fences, Budget Bundle, and
   final breaker CAS authorization;
8. append `InvocationStarted`;
9. redeem the short-lived host/operation-scoped credential inside the transport
   capability and perform at most one body send.

SDK retries, body-replaying redirects, and replaying failover are disabled by
the signed Adapter Manifest. A second possible body send always requires a new
Attempt, fence, and budget authorization.

## Crash and lost-ACK handling

| Last durable local fact | Recovery disposition | Allowed next action |
| --- | --- | --- |
| Claimed or Prepared, no `InvocationStarted` | `ABORTED_BEFORE_SEND` | A new Attempt may be considered under current policy. |
| `InvocationStarted`, no authoritative no-send proof | `MAY_HAVE_BEEN_SENT` | Enter reconciliation; never blind retry. |
| Remote success observed with another exposure open | `SUCCEEDED + RECONCILING` | Resolve the remaining exposure. |
| Contradictory admitted evidence | `OUTCOME_CONTRADICTED` | Preserve both observations and reconcile/arbitrate. |
| Policy-settled Unknown | Unknown remains physical truth | Transfer monitoring before Run terminal. |

Recovery Level A uses the same remote idempotency key for status query or retry
only while the declared retention window remains valid. The mock Level A test
proves exactly-once *logical settlement* and one mock remote execution in that
contract. It does not claim universal physical exactly-once behavior. Level B
queries first and creates a new Attempt only after authoritative proof of
non-execution. Level C mutation never blindly retries after the transmission
boundary; it goes to manual action.

## Observation intake

An Observation must bind source identity, signature, timestamp window,
nonce/replay key, schema, Adapter Manifest, Effect, Effect Attempt, exact request
hash, and a unique remote identity. Missing `external_request_id` is accepted
only through a Manifest-approved provider response, idempotency, or signed
session identity. If that mapping is not unique, the evidence is `ADVISORY` and
cannot advance outcome or release exposure.

Raw intake is encrypted before a Durable Ingress Spool candidate is published.
Spool metadata contains the raw evidence hash and bindings, not plaintext.
Restart uses the same stable Intake Command ID. Draining decrypts only inside
the intake path, re-encrypts the raw evidence in the Journal ingress evidence
store, commits the canonical frame, and then writes the custody-to-admission
mapping. Ordinary traffic has no access to Observation, Receipt, or Closing
reserves. If neither Journal nor spool can take custody, outbound dispatch stops
and the caller receives `UNRECEIVED_RETRYABLE`, never an acceptance receipt.

## Result quarantine and secrets

External results enter an encrypted CAS quarantine that has no normal
`ObjectRef` capability. The pipeline applies bounded size and decompression,
JSON schema, classification, secret scan, prompt-injection detection, trust
assignment, and redaction in that order. Secret-positive material loses its
ephemeral quarantine key, is deleted, and receives a durable destruction
attestation. Only validated/redacted bytes are encrypted and published through
normal CAS with a LocalCAS-issued receipt. External text is always data and
cannot become a system instruction.

The Effect writer, verifier, and evidence sealer see only an opaque credential
handle and audit fingerprint. Raw credentials are absent from Journal facts,
CAS metadata, Projection rows, receipts, logs, and reports. The Phase 4 macOS
provider is shadow/test-only and refuses a Production profile.

## Closing and operations

Closing permits are purpose, linked-effect scope, and depth bounded. They allow
only reconciliation, compensation, disclosure, containment, or monitoring work
for already-admitted exposure; they cannot expand ordinary business work.
Policy-settled Unknown may unblock a Run only after the durable successor stream
accepts the monitoring obligation and the source acknowledges that acceptance.
Late actions then use successor authority.

The side-effect audit reports logical Effects, Attempts, fences, permits,
approvals, transmissions, observations, outcome basis, Unknown exposure,
reconciliation, compensation, budget debt, quarantine, and destruction gaps.
Any unexplained in-flight Effect, unresolved exposure, orphan Observation,
authorization gap, or secret-destruction gap fails acceptance.

Operational response to an Unknown:

1. freeze new transmission for that Effect and retain receipt/observation
   ingress;
2. inspect the Attempt boundary and signed Adapter Manifest;
3. query with a new Query Effect when the recovery level permits;
4. apply only authenticated admitted observations under Effect-stream CAS;
5. preserve contradictions and unresolved exposures;
6. if remote truth cannot be established, record the frozen policy disposition,
   risks, authority, obligations, and monitoring successor;
7. never alter the original Attempt or Effect history; compensation is a new
   linked Effect.

## Activation matrix

Phase 4 stops at `MOCK_ONLY`. `EXTERNAL_READ`, `REVERSIBLE_MUTATION`, and
`HIGH_RISK_OR_IRREVERSIBLE` remain unauthorized. Later activation must be based
on a post-cutover manifest, preserve the pre-upgrade capability ceiling, qualify
the real Adapter and SecretProvider, and pass the same Effect/Observation gates.
Disabling new transmission must never disable receipt, observation,
reconciliation, required compensation, containment, or monitoring intake.
