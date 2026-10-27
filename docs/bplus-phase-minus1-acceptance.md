# Sitina B+ Phase -1 Acceptance Contract

Phase -1 is a foundation and isolation gate. It does not authorize a B+ Journal,
data migration, Production freeze, writer handoff, or Cutover.

The gate passes only when all of the following are true:

1. `EXECUTION_MANIFEST_V1` validates against the immutable Bootstrap Foundation
   Record and binds the pinned Python profile, dependency lock, plan-suite hash,
   Standing Owner Authorization hash, exact task range, roots, and stop point.
2. Source audit remains `CONTENT_MANIFEST_V1`, contains only source/docs/tests/
   non-secret configuration/schema material, and links to the initial manifest.
3. `unit_fast`, `integration_isolated`, and `crash_fault` pass from disposable
   homes with zero network attempts, zero Production mutable-path attempts, zero
   warnings, and unchanged V1 plus full mutable-root Production sentinels.
4. The child filesystem guard is reported accurately as
   `APPLICATION_ENFORCED_PYTHON_AUDIT_HOOK_V1`; it is not described as an OS
   sandbox. Tests execute with a disposable cwd and HOME.
5. The Legacy behavior baseline reproduces exactly on the final Phase -1 source
   binding. Its business semantics match the initial baseline; the source-only
   binding change caused by isolation remediation is classified explicitly.
6. The generated complete plan passes `build_complete_plan.py --check`.
7. The Legacy sink inventory parses all runtime source and has `unknown_count=0`.
8. The 2026-07-14 test-isolation incident is preserved, root-caused, recovered,
   and regression-tested. No Legacy record or existing Artifact was changed.

Authoritative machine evidence is written to
`~/Desktop/sitina/output/sitina-bplus-phase-minus1-acceptance.json`.
That report must bind the exact suite results, content manifest, baselines,
sink inventory, sentinel reports, incident record, and source-file hashes.

Passing this gate permits deriving a separate Phase 0 manifest under the
Standing Owner Authorization. It does not by itself change Production Authority.
