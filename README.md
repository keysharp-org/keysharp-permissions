# keysharp-permissions

`keysharp-permissions` is a source-only C library for Linux services that grant
persistent permissions to executable identities. It centralizes the shared
scope values, identity algorithm, v1 store, prompt locking, and polkit runner.

The library builds as a private static target. It installs no library, package,
daemon, CLI, policy, or state file.

## Add it to a service

Pin the repository as a submodule or another immutable source dependency, then
add it from the service's CMake project:

```cmake
set(KEYSHARP_PERMISSIONS_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/keysharp-permissions"
    CACHE PATH "keysharp-permissions source directory")

add_subdirectory(
    "${KEYSHARP_PERMISSIONS_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/keysharp-permissions"
    EXCLUDE_FROM_ALL)

target_link_libraries(my-authority PRIVATE
    KeysharpPermissions::permissions)
```

Include the API as:

```c
#include <keysharp_permissions/permissions.h>
```

Each authority sets `ksp_store_config.write_scopes` to only the scopes it
administers. `read_scopes` may additionally include a foreign scope needed for
a combined authorization check. Listing and every mutation remain confined to
`write_scopes`.

## Scopes

The v1 store contains exactly these scopes:

| Value | Name |
| ---: | --- |
| `0x01` | `input-monitoring` |
| `0x02` | `input-control` |
| `0x04` | `window-monitoring` |
| `0x08` | `window-control` |
| `0x10` | `screen-capture` |
| `0x20` | `audio-capture` |
| `0x40` | `camera-capture` |
| `0x80` | `clipboard-monitoring` |

These values describe durable permissions. A service's wire operations remain
part of that service's own protocol.

## Executable identity

The final application identity is lowercase hexadecimal SHA-256 over these
exact bytes:

```text
ASCII("org.keysharp.app-identity-v1") || 00 || ASCII(kind) || 00 || identity
```

There is no byte after `identity`.

- `kind` is `path` when the opened executable and every path ancestor are
  UID-0-owned and not group- or other-writable. `identity` is the exact absolute
  byte string from `/proc/<pid>/exe`.
- Otherwise, `kind` is `sha256`. Hash the bytes from the already-open executable,
  encode that digest as 64 lowercase ASCII hex bytes, and use those bytes as
  `identity`.

Identification verifies the process UID and `/proc/<pid>/stat` start time before
and after hashing. `ksp_identity_revalidate` repeats the complete check after an
interactive authorization.

`ksp_identity_revalidate_cached` checks the process and the executable inode,
size, timestamps, and resolved path without rehashing unchanged bytes. It falls
back to complete revalidation when the fingerprint changes. Capture and the
interactive grant path still compute the complete identity; cached checks let
long-lived connections detect executable changes without file-sized work on
every operation. Executable identity does not authenticate loaded libraries,
managed assemblies, scripts, or changes to a process's address space.

## Store contract

The default persistent directory is `/var/lib/keysharp-permissions/v1`, owned by
root and mode `0700`. One root-owned, mode-`0600` file represents one scope:

```text
grant-<canonical-decimal-uid>-<64-lowercase-hex-hash>-<8-lowercase-hex-scope>.grant
```

The complete file grammar is:

```text
keysharp-permission-v1
<uid>\t<hash>\t<scope>\t<canonical-decimal-unix-time>\t<display-path>
```

Both lines end in one newline. The filename and record must agree. Parsers
reject aliases, uppercase hex, non-canonical numbers, symlinks, extra bytes,
control characters, unexpected ownership, and unexpected modes. Marker writes
use a mode-`0600` temporary file, `fsync`, atomic rename, and directory `fsync`.

Authorities coordinate through the persistent `.lock`. Revocation removes only
requested bits within `write_scopes`; all other scope markers remain intact.
Each accepted revoke is bracketed by two updates to the root-owned generation
file `/run/keysharp-permissions/revoke-<uid>.generation`. Bracketing an absent
marker also fences an authorization prompt already in progress.

`ksp_store_grant_if_generation` is the only grant mutation API. It writes only
when the generation observed before prompting still matches. Listing is sorted
by UID and hash and is bounded by `ksp_store_config.max_records`.

## Prompting

`ksp_prompt_lock_acquire` serializes prompts for one `(uid, identity)` across
independent authorities. Waiting is cancellable and never holds the store lock.

`ksp_polkit_authorize` invokes an absolute `pkcheck` path with `posix_spawn`, a
fixed environment, an argv vector, a bounded timeout, and no shell. The caller
supplies its action ID, detail keys, and allowed scope mask. A successful result
is returned only after executable identity revalidation.

## Build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## License

MIT. See [LICENSE](LICENSE). Contributor provenance is recorded in
[PROVENANCE.md](PROVENANCE.md).
