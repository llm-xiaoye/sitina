# Sitina macOS local durability profile

Default profile ID: `MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1`.

The default profile requires regular-file `fsync`, directory `fsync` after
publication/rename, fixed-inode `flock`, a single active segment, no-replace
publication, and recovery scan/re-sync before adoption. It qualifies process and
OS crash behavior only. It makes no power-loss RPO=0 claim.

Optional profile ID: `MACOS_APFS_FULLFSYNC_POWERLOSS_QUALIFIED_V1`. It additionally
requires successful `F_FULLFSYNC` at every declared barrier and a hardware,
filesystem, OS-build, mount-option, cache, and fault-injection qualification
record. Its status is `NOT_YET_QUALIFIED` in Phase 1.

After an unknown `write` or sync result, the writer is poisoned. No further ACK
or append is allowed. A fresh process must take the same fixed-inode lock, scan
the longest physically contiguous valid prefix, truncate only an incomplete
active tail, re-sync any adopted complete frame, rebuild indexes, and only then
serve. Media corruption is never truncated as an incomplete tail.

