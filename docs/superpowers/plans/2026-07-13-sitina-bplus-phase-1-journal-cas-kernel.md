# Sitina B+ Phase 1 Journal/CAS/Projection Kernel Implementation Plan

> **For Codex execution:** Requires PASSED Phase -1/0 reports and a current Execution Manifest. Only physically separate `shadow` or `controlled_fixture` roots are writable；Production Journal Genesis/Cutover is forbidden。

**Goal:** 实现可在 Shadow/Controlled Namespace 运行的单机 Canonical Journal、Encrypted CAS、Command Outcome、Projection Kernel 和 Lost ACK Recovery，不改变 Production Legacy Authority。

**Architecture:** 单 Writer、单 Active Segment、单 Stream Transaction；单机 Position Profile 为 Gap-free Committed Prefix。CAS Object 完成 No-replace Publication 和 Fresh Verification 后才允许 Frame 引用。SQLite 只作为可删除重建的 Catalog/Projection；Command Outcome 可以从 Canonical Frame 查询。

**Tech Stack:** Approved Python 3.12 Profile、strict Canonical JSON、binary frame、`fcntl.flock`、macOS `renamex_np(RENAME_EXCL)` Native Adapter 或经能力探测验证的 `linkat` fallback、SQLite WAL、`cryptography` AES-256-GCM Object/Envelope Wrapping and Ed25519 Profiles、分层 `unittest`、Crash-injection subprocess tests。

## Global Constraints

- Production Authority 仍是 Legacy；Phase 1 Journal Namespace 必须标记 `shadow` 或 `controlled_fixture`。
- 不导入真实业务数据，不执行 Provider/Tool/MCP。
- 初始 Position Profile：`LOCAL_CONTIGUOUS_COMMITTED_PREFIX_V1`。
- 一个 Command 只修改一个 Logical Stream。
- ACK 只在 Frame 和所有 CAS Ref Durability Barrier 后返回。
- `write/fsync` 不确定后 Poison Writer，必须 Recovery。
- SQLite Cache Miss 只能返回 UNKNOWN。
- Canonical/Frame/Crypto/Identifier/Clock Profile 和 Golden Vectors 未冻结前，不得写入第一个持久 B+ Byte。
- Audit、Security Intake、Dead Letter、Projection Failure 和 Operational Control 事实必须进入 Journal-backed Stream。

---

### Task 0: Normative serialization, frame, identifier, hash and crypto profiles

**Files:**
- Create: `docs/bplus-profiles/canonical-json-v1.md`
- Create: `docs/bplus-profiles/local-frame-v1.md`
- Create: `docs/bplus-profiles/identifier-hash-v1.md`
- Create: `docs/bplus-profiles/crypto-v1.md`
- Create: `docs/bplus-profiles/journal-auth-v1.md`
- Create: `docs/bplus-profiles/macos-durability-v1.md`
- Create: `tests/vectors/bplus_v1_vectors.json`
- Test: `tests/test_bplus_profiles.py`

**Interfaces:**
- Produces immutable Profile IDs and cross-implementation Golden Vectors.

- [ ] Define UTF-8/NFC、Object Key sorting、Array order、Set-like field rules、integer bounds、float rejection、RFC3339 UTC、duplicate-key and unknown-field rejection.
- [ ] Define big-endian Frame fields, length-prefixed UTF-8 IDs, bounded 128-bit UUID encoding only for explicitly typed UUID fields, Hash preimages and self-hash exclusions.
- [ ] Fix SHA-256 domain-separated hashes and tenant HMAC-SHA-256 plaintext commitments.
- [ ] Fix per-object random 256-bit DEK、AES-256-GCM Object encryption、96-bit CSPRNG Object Nonce、immutable AAD Core Header and Ed25519 Evidence signatures.
- [ ] Wrap each DEK with KEK using a separate AES-256-GCM Envelope Nonce and AAD binding Core Header Hash、Object Identity、Key ID、Purpose and Wrap Profile；Rewrap creates a new immutable authenticated Envelope Version/ID and audited Alias without changing CAS Object bytes.
- [ ] Fix Journal Event Auth as HMAC-SHA-256 with a separate Journal Auth Key、exact Core/Event/Transaction preimages、Segment-boundary rotation and historical-key retention.
- [ ] Define default `MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1` and separately qualified `MACOS_APFS_FULLFSYNC_POWERLOSS_QUALIFIED_V1`; the default makes no power-loss RPO=0 claim.
- [ ] Produce valid/invalid Golden Vectors；Profile change requires new Major/Profile ID, never reinterpret committed bytes.
- [ ] Commit profiles before Task 1.

---

### Task 1: Canonical command, event, receipt, and outcome types

**Files:**
- Create: `core/sitina/journal/__init__.py`
- Create: `core/sitina/journal/model.py`
- Create: `core/sitina/commands/__init__.py`
- Create: `core/sitina/commands/model.py`
- Test: `tests/test_journal_model.py`

**Interfaces:**
- Produces:
  - `CommandEnvelope.canonical_request_bytes() -> bytes`
  - `EventEnvelope.canonical_bytes_for_hash() -> bytes`
  - `AppendReceipt`
  - `CommandStatus = COMMITTED|REJECTED|CONFLICT|RETRYABLE_NOT_ACCEPTED|UNKNOWN`
  - `FrontierRef(journal_id, epoch, shard, position, commitment)`.

- [ ] **Step 1: Write failing canonicalization tests**

```python
def test_command_hash_ignores_transport_received_at():
    left = command(received_at="2026-07-13T00:00:01Z")
    right = command(received_at="2026-07-13T00:00:02Z")
    assert left.command_request_hash == right.command_request_hash


def test_command_hash_changes_with_payload():
    assert command(payload={"x": 1}).command_request_hash != command(payload={"x": 2}).command_request_hash
```

- [ ] **Step 2: Run focused tests**

Expected: missing module.

- [ ] **Step 3: Implement frozen dataclasses and enums**

Implement the frozen Task 0 Canonical Profile exactly；do not reuse permissive Legacy `stable_json` as the canonical codec. Domain-separate command/event/transaction hashes. Define explicit JSON schema-to-dataclass conversion and reject duplicate keys、unknown fields and unknown major versions.

- [ ] **Step 4: Add type round-trip and invalid-field tests**

Assert stored bytes round-trip exactly；`event_core_bytes` excludes Event Hash/Auth Tag、Event Hash is unkeyed/domain-separated、Auth Tag binds Journal/Epoch/Event Hash、Transaction Hash covers final stored bytes。Test wrong/missing/rotated Key、broken Key Transition and historical Key loss fail closed.

- [ ] **Step 5: Run tests and commit**

---

### Task 2: Frame codec and parser limits

**Files:**
- Create: `core/sitina/journal/codec.py`
- Test: `tests/test_journal_codec.py`

**Interfaces:**
- Produces: `encode_frame(transaction) -> bytes`, `scan_frames(fileobj, limits) -> FrameScanResult`.
- Consumes: `CommandEnvelope`, `EventEnvelope`.

- [ ] **Step 1: Write failing frame tests**

Test one/multiple Events, CRC corruption, transaction-hash corruption, truncated Header/Body/Footer, unknown major version and oversized length rejected before allocation.

- [ ] **Step 2: Define V1 binary layout**

```text
magic(8) major(u16) minor(u16) header_len(u32) frame_len(u64)
transaction_id_len(u16) transaction_id(bytes)
command_id_len(u16) command_id(bytes) request_hash(32)
stream_id_len(u16) stream_id(bytes)
object_reference_count(u32) object_reference_manifest_hash(32)
event_count(u32) first_position(u64) last_position(u64)
first_stream_version(u64) last_stream_version(u64)
event_lengths[u32] + canonical_event_bytes
crc32(u32) transaction_hash(32) footer_magic(8)
```

For local V1 assert position span equals Event count; this assertion belongs to Position Profile, not generic codec.

All integer fields use the frozen byte order；all length/count fields are checked against Capacity Profile before allocation。Frame Hash covers the exact canonical Header/Body/CRC fields declared in the Profile and excludes only its own stored field。

- [ ] **Step 3: Implement bounded scanner**

Return complete Frame end offsets and first invalid/incomplete byte. Never allocate from unchecked length.

- [ ] **Step 4: Fuzz deterministic invalid inputs**

Use seeded random byte mutations; parser must fail closed without unbounded memory.

- [ ] **Step 5: Run tests and commit**

---

### Task 3: Fixed-inode Writer Lock

**Files:**
- Create: `core/sitina/journal/locks.py`
- Test: `tests/test_journal_lock.py`

**Interfaces:**
- Produces: `WriterLock.acquire(path, journal_id, epoch)`, context manager, `poison(reason)`.

- [ ] **Step 1: Write subprocess contention tests**

First process holds lock; second fails without deleting/replacing file. Test symlink rejection, inode replacement detection、fork/exec descriptor inheritance、duplicate FD close、filesystem capability mismatch and descriptor-close poisoning.

- [ ] **Step 2: Implement no-follow regular-file validation**

Use `os.open(..., O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW, 0o600)`, `fstat`, `lstat`, device/inode comparison, `fcntl.flock(LOCK_EX|LOCK_NB)`.

- [ ] **Step 3: Persist writer generation diagnostic**

Under held kernel lock, atomically update control metadata and directory-sync. It never substitutes for `flock`.

- [ ] **Step 4: Run tests and commit**

---

### Task 4: Local segment writer, group durability, and rollover

**Files:**
- Create: `core/sitina/journal/local.py`
- Create: `core/sitina/journal/recovery.py`
- Test: `tests/test_local_journal.py`
- Test: `tests/test_journal_crash_matrix.py`

**Interfaces:**
- Produces:
  - `LocalJournal.open(home, profile)`
  - `append(command, expected_stream_version, events, object_reference_proofs) -> AppendReceipt`
  - `query_command(command_id, request_hash) -> CommandResult`
  - `lookup_existing_object_root_proof(object_ref, verified_frontier) -> ExistingDurableObjectRootProof`
  - `iter_events(after_position)`.

- [ ] **Step 1: Write failing append tests**

Assert single Stream、continuous Stream Version、local committed Position continuity、idempotent retry、conflict on same Command/different Hash、exact Event-ref/Object-proof equality and no ACK before Frame plus all referenced CAS durability succeeds. Missing/forged/expired Proof or unverified Final Object fails before Frame write.

- [ ] **Step 2: Implement single-thread Writer queue**

Freeze `group_end_offset` before durability barrier；ACK only covered Frames。Writer derives Object Refs from Canonical Event Bytes、validates `PublishedObjectReceipt|ExistingDurableObjectRootProof`、acquires GC Epoch Reference Leases and binds `object_reference_manifest_hash` in Frame。Release Lease only after Referencing Frame Durable. On write/sync error set poisoned flag and reject all further appends until reopen.

- [ ] **Step 3: Implement segment hash/footer and rebuildable index**

Segment hash excludes/zeroes its own field; `.sidx` binds segment hash but stays outside canonical chain. Use no-replace publication and directory sync. Existing durable-object root proof lookup must resolve a verified Committed Frame and exact object-reference manifest at/before the requested Frontier；a CAS catalog row or object existence alone cannot issue this proof.

- [ ] **Step 4: Implement recovery adoption**

Scan longest physically contiguous valid Frame prefix. Truncate only incomplete active tail. Adopt complete unacknowledged Frames, sync repaired/adopted prefix, rebuild Stream Heads/Command Bindings, then serve.

Recovery tests must distinguish short write、EINTR、ENOSPC、EIO、unknown write result、unknown `fsync` result、directory-sync failure and media corruption. Any unknown durability result poisons the Writer；only a fresh locked Recovery can adopt and re-sync a valid complete prefix。

- [ ] **Step 5: Implement rollover crash matrix**

Inject crash after each state: group sync, footer write/sync, rename, directory sync, new-active create/sync/publish, index build. Recovery yields all old Segments sealed and at most one Active.

- [ ] **Step 6: Run tests and commit**

---

### Task 5: Key Provider and encrypted CAS identity

**Files:**
- Create: `core/sitina/cas/__init__.py`
- Create: `core/sitina/cas/model.py`
- Create: `core/sitina/cas/crypto.py`
- Create: `core/sitina/security/key_provider.py`
- Create: `core/sitina/security/macos_keychain.py`
- Test: `tests/test_key_profiles.py`
- Test: `tests/test_cas_crypto.py`

**Interfaces:**
- Produces:
  - `KeyProvider.wrap_dek/unwrap_dek/sign/verify`
  - `JournalAuthProvider.authenticate/verify/rotate`
  - `ObjectEnvelope`
  - `encrypt_object(plaintext, profile) -> EncryptedObject`.

- [ ] **Step 1: Write purpose-isolation tests**

Test that runtime writer can request only current Journal Auth Capability and cannot request Evidence/Authority Signing Key；test/dev/prod namespaces cannot resolve one another；Key IDs bind purpose/provider/environment/version/profile。Journal、Authority Control and Evidence/Archive signatures never share a Key Purpose.

- [ ] **Step 2: Implement provider interface and in-memory test provider**

Production macOS adapter stores opaque references in Keychain; tests use deterministic in-memory keys. Never commit key bytes.

- [ ] **Step 3: Implement the frozen Crypto V1 profile**

Use the Phase -1 locked `cryptography` dependency and Task 0 AES-256-GCM Object/Envelope + Ed25519 Profile. A new random DEK per Object prevents Object Nonce reuse across Objects；immutable Core Header is Object AAD；rewrappable DEK Envelope uses its own Nonce and context-bound AAD. Separate DEK, KEK, Commitment and Signing Key purposes.

- [ ] **Step 4: Test rewrap and destruction semantics**

Rewrap preserves Semantic ID/Ciphertext; crypto-erasure makes decrypt fail and yields an Attestation fixture.

- [ ] **Step 5: Run tests and commit**

---

### Task 6: Local CAS no-replace publication

**Files:**
- Create: `core/sitina/cas/local.py`
- Create: `core/sitina/cas/native.py`
- Test: `tests/test_local_cas.py`

**Interfaces:**
- Produces: `LocalCAS.publish_verified(body, metadata) -> PublishedObjectReceipt` and `open_verified(ref)`. It never issues `ExistingDurableObjectRootProof`.

- [ ] **Step 1: Write publication tests**

Test staging sync、Fresh Verify、no-replace concurrency、exact-existing idempotency、collision incident、directory durability、Receipt identity/profile/expiry and missing/auth-failed object。Receipt cannot be constructed by callers and does not itself become a business/GC Root. Test CAS existence/catalog cannot manufacture an existing-root proof；only Task 4 Journal lookup can bind a Committed Frame root.

- [ ] **Step 2: Implement macOS no-replace adapter**

Bind `renamex_np(RENAME_EXCL)` with `ctypes` or use tested same-filesystem `linkat` strategy. Plain overwriting rename is forbidden.

- [ ] **Step 3: Implement ciphertext-digest path and authenticated header**

Do not expose plaintext hash. Reject symlink/path traversal.

- [ ] **Step 4: Run race tests and commit**

---

### Task 7: CAS reference-admission, fixed GC frontier and GC fence

**Files:**
- Create: `core/sitina/cas/gc.py`
- Test: `tests/test_cas_gc_fence.py`

**Interfaces:**
- Produces: `ReferenceLease`, `GCMarkFrontier`, `GCCycle`, `GCController.mark/quarantine/sweep`, `with_reference_lease(ref)`.

- [ ] **Step 1: Write append-vs-GC race tests**

Prove a durable in-flight reference lease blocks quarantine until Frame Durable; once GC transitions to QUARANTINING, new admission fails.

- [ ] **Step 2: Implement Journal-backed GC control records for shadow namespace**

Do not store sole fence state in SQLite. Freeze Signed Journal Frontier、GC Epoch、Catalog Set/Versions、Hold Snapshot and Policy Hash。Scan all fixture Journal/CAS/Package/Supplement/Archive/Migration/Rebuild catalogs at that Frontier；fail closed if required coverage is unavailable.

- [ ] **Step 3: Test post-frontier reference protection**

New Reference Admission enters a successor/Post-frontier Root under GC Epoch Lease and cannot be swept by the current Candidate Set. Sweep-time recheck rejects any Committed/In-flight/Post-frontier/Read/Backup/Hold/Restore reference.

- [ ] **Step 4: Test restart reconciliation**

GC cannot resume until Journal and lease reconciliation completes.

- [ ] **Step 5: Commit**

---

### Task 8: Projection schema and atomic runner

**Files:**
- Create: `core/sitina/projections/__init__.py`
- Create: `core/sitina/projections/schema.py`
- Create: `core/sitina/projections/runner.py`
- Create: `core/sitina/projections/rebuild.py`
- Test: `tests/test_projection_kernel.py`

**Interfaces:**
- Produces: `ProjectionRunner.apply_batch()`, `ProjectionGeneration.build/switch`, Event Catalog, Stream Head and Command Outcome projections.

- [ ] **Step 1: Write rollback tests**

A handler failure after row mutation must roll back rows and offset. Gapped-position arithmetic is not used. For local V1, a committed gap fails integrity checks.

- [ ] **Step 2: Implement schema**

Use WAL, `synchronous=NORMAL`, FK on, trusted schema off, one write coordinator. Store Event location Metadata, not payload copies.

- [ ] **Step 3: Implement atomic apply+offset**

No universal processed-events table. Use natural uniqueness and last applied Stream Version.

- [ ] **Step 4: Implement disposable rebuild**

Build a Shadow DB to fixed Frontier, compute semantic checksums, switch Reader Generation atomically.

- [ ] **Step 5: Run tests and commit**

---

### Task 8A: Journal-backed operational authority primitives

**Files:**
- Create: `core/sitina/journal/operational.py`
- Create: `core/sitina/journal/security_intake.py`
- Create: `core/sitina/journal/dead_letters.py`
- Create: `core/sitina/journal/schema_registry.py`
- Create: `core/sitina/commands/authorization.py`
- Test: `tests/test_operational_authority.py`

**Interfaces:**
- Produces typed Streams/handlers for Audit、Security Intake、Operational Control、Dead Letter、Projection Failure、Schema Registry and Capability/Authorization decisions.

- [ ] Test SQLite/log-only rows never become authoritative operational facts.
- [ ] Test unsafe/oversized/unparseable intake stores bounded redacted metadata or Quarantine Attestation, never raw secret/business payload.
- [ ] Test Blocking Dead Letter and Required Projection Failure enter Terminal Eligibility inputs.
- [ ] Test schema versions/upcaster chain hashes are immutable and unknown Major fails closed.
- [ ] Test authorization decision binds actor、capability、policy、target、request hash、expiry and audit reference.
- [ ] Ensure deterministic rejection can be queried through canonical Command Outcome.
- [ ] Commit before Phase 2.

---

### Task 9: Strong/Eventual/Stale read API

**Files:**
- Create: `core/sitina/projections/consistency.py`
- Test: `tests/test_projection_consistency.py`

**Interfaces:**
- Produces: `ReadOptions`, `ReadMetadata`, `wait_for_frontier()`.

- [ ] **Step 1: Test fixed-target waits**

Strong wait reaches Caller target and does not chase moving Head. Failed/Blocked/Incompatible Projector fails closed.

- [ ] **Step 2: Implement condition notification plus polling fallback**

No SQLite busy loop. Calculate `lag_events` from Event Catalog count.

- [ ] **Step 3: Test Multi-journal type even though Phase 1 uses one component**

Keep Vector-compatible API; single Position is a convenience wrapper.

- [ ] **Step 4: Commit**

---

### Task 10: Command Gateway and Lost ACK query

**Files:**
- Create: `core/sitina/commands/gateway.py`
- Create: `core/sitina/commands/outcomes.py`
- Test: `tests/test_command_outcomes.py`

**Interfaces:**
- Produces: `CommandGateway.submit()`, `query(command_id, request_hash) -> CommandResult`.

- [ ] **Step 1: Write all five result-state tests**

Cover COMMITTED, REJECTED, CONFLICT, RETRYABLE_NOT_ACCEPTED and UNKNOWN.

- [ ] **Step 2: Implement canonical lookup hierarchy**

In-memory verified index → segment indexes → canonical scan. SQLite miss returns UNKNOWN. Cold coverage unavailable fails closed.

- [ ] **Step 3: Test Lost ACK**

Kill after Frame durable and before response; reopen, resubmit same ID/hash, return identical AppendReceipt; different hash returns CONFLICT.

- [ ] **Step 4: Commit**

---

### Task 11: Capacity safety profile and emergency reserve

**Files:**
- Create: `core/sitina/runtime/capacity.py`
- Create: `config/capacity_profile.shadow.json`
- Test: `tests/test_capacity_gates.py`

**Interfaces:**
- Produces: hard parser limits, Admission Classes, Disk Gate, emergency quota.

- [ ] **Step 1: Test safety bounds**

Reject oversized envelope/Event/Frame before allocation; reserve cannot be consumed by Ordinary traffic.

- [ ] **Step 2: Implement NOT_YET_QUALIFIED profile**

Include explicit empty measured SLO fields; never expose defaults as supported capacity.

- [ ] **Step 3: Test disk gate combines percent, bytes, inode, rollover and staging headroom**

Most restrictive condition wins.

- [ ] **Step 4: Commit**

---

### Task 12: Kernel acceptance and benchmark harness

**Files:**
- Create: `tests/test_phase1_kernel_acceptance.py`
- Create: `benchmarks/journal_benchmark.py`
- Create: `docs/journal-kernel-operations.md`

**Interfaces:**
- Produces: fixture-only acceptance report and unqualified benchmark output.

- [ ] **Step 1: Run crash matrix**

Every append/CAS/rollover/offset/Object-proof/Reference-lease boundary under the default Process/OS Crash Profile. Full-fsync Power-loss Profile remains `NOT_YET_QUALIFIED` until hardware-specific qualification succeeds.

- [ ] **Step 2: Run delete/rebuild and zero-external tests**

Patch all external adapters to raise if called.

- [ ] **Step 3: Run benchmark matrix**

Record hardware/filesystem/profile and leave status `NOT_YET_QUALIFIED` until review approves thresholds.

- [ ] **Step 4: Run the applicable Phase -1 isolated suites**

Use Phase -1 `unit_fast`、`integration_isolated` and Phase 1 `crash_fault`; assert Production sentinels unchanged.

- [ ] **Step 5: Commit and stop**

Phase 1 exit does not authorize Production Cutover or Legacy data import.
