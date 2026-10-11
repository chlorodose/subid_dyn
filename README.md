# subid_dyn

A Linux libsubid plugin and PAM account module that allocate subordinate UID and
GID ranges on demand. Both use `/var/db/subid/allocated` as their authoritative
allocation database. Requires Linux-PAM and a shadow/libsubid installation with
plugin support.

## Build and check

Install a Rust toolchain with edition 2024 support, a C linker, and the Linux-PAM
development package (`pam-devel` for the RPM build). Then run:

```sh
cargo build --release --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

The output is `target/release/libsubid_dyn.so`. The RPM spec installs it in the
system library directory and adds `security/pam_ensure_subid.so` as a symlink.
Tests use temporary databases; they do not change `/etc` or `/var/db/subid`.

## Configure

Install the shared library into your distribution's library directory. Configure
libsubid in `/etc/nsswitch.conf`:

```text
subid: dyn
```

Add the following account entry to the appropriate PAM service stack after its
account eligibility checks, with the module installed in the PAM module directory:

```text
account optional pam_ensure_subid.so
```

The PAM module always returns `PAM_IGNORE`: it provisions ranges without deciding
whether a user may log in. Lookup or allocation failures are logged through
`pam_syslog`. With this optional configuration, failure does not block login.
NSS query/allocation operations return an error when provisioning fails.

Only privileged callers can create new allocations. Unprivileged clients can
query existing allocations. A first query from an unprivileged client can fail
until PAM or another privileged caller has provisioned the user.

## Allocation policy

`/etc/login.defs` supplies `SUB_UID_MIN`, `SUB_UID_MAX`, `SUB_UID_COUNT`, and the
corresponding `SUB_GID_*` values. Defaults are min `100000`, max `600100000`, and
count `65536`. Max is inclusive. Invalid values and read errors are reported;
defaults apply only to missing settings or a missing file.

- UIDs below `1000` are not automatically provisioned.
- A count of `0` disables new allocation of that ID type. Existing grants remain
  valid, including manually provisioned system users.
- Ranges must contain positive IDs and end below Linux's reserved `(uid_t)-1`.
- UID and GID spaces are allocated independently; failure in one does not roll
  back a successful allocation in the other.
- Existing grants are retained when configured limits change. New grants stay
  within the current limits. Allocation never reclaims old grants automatically.

## Database and permissions

Every non-comment record is a newline-terminated line:

```text
owner_uid:start:count:u
owner_uid:start:count:g
```

`owner_uid` is the user's numeric UID, including for GID grants. Each ID type must
have nonoverlapping ranges. Blank lines and `#` comments are allowed. Empty,
overflowing, malformed or overlapping ranges are rejected.

The database directory and every ancestor must be `root:root` and must not be
writable by group or other users. Directory symlinks are rejected. Newly created
directories use `0755`, and the database uses `0644`. The database must be a regular,
singly linked `root:root` file without group/other write permission or special
mode bits. Unsafe existing paths are rejected rather than automatically repaired.

Readers take a shared `flock`; writers take an exclusive lock before selecting
and appending a range. Access uses directory-relative opens with `O_NOFOLLOW` and
file-descriptor validation. File and directory sync failures propagate before
success is reported. Queries also confirm persistence before returning grants.
Use a local filesystem supporting `flock` and file/directory `fsync`.

## Migration and recovery

The plugin does not merge `/etc/subuid`, `/etc/subgid`, or another provider's
allocations. Before switching `subid: files` (or another provider) to `subid: dyn`,
stop affected workloads and import **all existing grants** into this database,
resolving usernames to their numeric UIDs and preserving starts and counts.
Check for overlaps, append a newline to each record, and set the permissions
above before enabling the plugin. Preserve a backup of the old grants.

On corruption or an unterminated final record, reads and allocations fail closed.
No record is automatically dropped: even an incomplete record may correspond to
IDs already in use. Stop all consumers and writers, back up the database, and
reconstruct the complete grants from trustworthy backups and workload ownership
information before restoring service. Do not simply delete the tail or reset the
database; doing so can delegate IDs still in use to a different user.

All external writers must use the same exclusive lock. Do not replace, unlink,
truncate, or rotate the database while consumers are active: locks belong to the
open inode. Treat UID reuse as a manual ownership/migration operation; a new
account with a recycled UID otherwise inherits that UID's stored grants.

## C interface

The library exports the four standard `shadow_subid_*` plugin callbacks and an
additional `shadow_subid_allocate` callback. Arrays use C allocation and must be
released with `shadow_subid_free`. Invalid ID-type values and null arguments
return errors; valid outputs are reset before processing. Allocation failure is
an error, not an empty successful result.

Rust callers must uphold each exported unsafe function's documented pointer and
lifetime requirements. Rust panics are caught at the NSS/PAM boundaries; invalid
non-null pointers and process-level allocation aborts cannot be recovered there.
