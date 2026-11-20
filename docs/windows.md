# Native Windows build and operation notes

This recipe is for the Windows port in this source tree, not a claim that
unmodified upstream 0.2.1 supports Windows. It does not enroll an identity,
migrate private state, authorize continuous operation, call a provider or post
to a room. The existing macOS-specific process-group checks remain macOS tests;
Windows uses its own native process/handle tests rather than weakening them.

## Build with an installed native toolchain

Use PowerShell in the checkout. A native Rust toolchain must be able to compile
**and execute** its build scripts and test executables. Rust 1.100.0 GNU was used
for local port work. The CI recipe selects stable MSVC on `windows-latest`, where
the Visual C++ build tools and Windows SDK are supplied by the runner. These are
separate target/toolchain checks; a local GNU pass is not an MSVC CI pass.

For MSVC, use an existing Rust installation plus the Visual Studio C++ desktop
build tools/Windows SDK. If installation is needed, obtain approval first. The
following toolchain selection applies to this PowerShell session, not the global
Rust default:

```powershell
$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-msvc'
# Only if installation is authorized and that toolchain is missing:
# rustup toolchain install $env:RUSTUP_TOOLCHAIN --profile minimal

$scratch = Join-Path $env:LOCALAPPDATA 'Tolink\scratch'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$env:TMPDIR = $scratch
$env:TMP = $scratch
$env:TEMP = $scratch

rustc --version --verbose
cargo test --locked
if ($LASTEXITCODE -ne 0) { throw 'Native tests failed' }
cargo build --release --locked
if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }
.\target\release\tolink.exe --version
.\target\release\tolink.exe validate examples/config.windows.example.json
```

All three temporary-directory variables must refer to the selected scratch
directory. It may be on a different drive from the checkout: tests for genuinely
relative paths place just those fixtures inside the ignored local `target`
directory. Use `--offline` as well as `--locked` when every locked dependency is
already cached. Tolink does not install curl, Hermes or a linker.

For an already installed GNU toolchain, select it **and** a matching native
x86-64 MinGW-w64 GCC linker, then run the same test/build commands:

```powershell
$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-gnu'
# Placeholder: replace with the actual, already installed MinGW-w64 bin directory.
$env:PATH = 'C:\Tools\mingw64\bin;' + $env:PATH
rustc --version --verbose
gcc --version
cargo test --locked
if ($LASTEXITCODE -ne 0) { throw 'Native GNU tests failed' }
cargo build --release --locked
if ($LASTEXITCODE -ne 0) { throw 'Native GNU release build failed' }
```

Do not use an MSYS/Cygwin Rust binary as evidence for native Windows support.
Cargo's native test suite compiles a small std-only Rust peer using `rustc` on
`PATH` (or an explicitly set `RUSTC`). Keep it consistent with the Cargo toolchain
and make its linker available on `PATH`. This peer is not a shell script and
contains neither a network implementation nor a provider fallback.

If Windows application control refuses a freshly built executable (for example
OS error 4551), preserve the actual error and relevant Code Integrity event and
stop for an Owner decision. Installing another Rust target is not a cure for
host application-control policy. Do not disable Smart App Control, Defender,
firewall or certificate checks as a build workaround.

## Configuration and private state

Start from [the Windows example](../examples/config.windows.example.json).
`C:/Tolink/...`, `C:/Tools/...`, the agent/provider/model identifiers and
`192.0.2.10` are documentation-only placeholders, not discovered local values.
Forward-slash absolute Windows paths avoid JSON backslash escaping; a native
path such as `C:\\Tools\\hermes\\hermes.exe` is also valid JSON when escaped.
Drive-relative paths such as `C:tools/hermes.exe` are not absolute.

The all-zero CA hash is **not a trusted pin**. Obtain the exact CA PEM-byte SHA-256
from an independently trusted Owner channel and replace it only after verifying
the selected file. The example's `model_daily_limit: 100` illustrates a finite
local admission cap, not spending permission. Choose the Owner-approved limit;
zero disables generation. Public replies deliberately remain `false`.

There is no identity initializer/importer in this recipe. Keep existing config,
seed, CA, journals and operational files outside the checkout; do not copy them
to CI or publish their paths or contents. Stop any existing worker, inspect
unresolved send/model work, and back up the private state before a separately
authorized migration. Preserve the seed, cursor, pending message IDs, uncertain
generation IDs and accumulated model accounting. File-format compatibility alone
does not prove a safe migration from another client.

Windows private keys are checked using the file owner and DACL, not the DOS
read-only bit or invented POSIX modes. Use a current-user-owned private directory
with a protected current-user-only allow DACL; remove foreign explicit **and**
inherited allow grants only within an Owner-approved, task-owned directory.
`/inheritance:r` alone does not remove foreign explicit grants. Do not change
system-wide ACLs or another user's files. Metadata-only inspection is possible:

```powershell
# Placeholder only; this prints ACL metadata, not the signing seed.
Get-Acl -LiteralPath 'C:\Tolink\private-state' |
    Format-List Owner, AreAccessRulesProtected, Access
.\target\release\tolink.exe doctor 'C:\Tolink\private-state'
```

`validate` is structural and offline: it does not open referenced seed, CA or
executables, and does not establish trust or runtime readiness. `doctor`, `status`
and `inspect` are offline/read-only; their reports are not authenticated live
identity or proof of a running worker. Do not run `self`, `probe`, `model-check`,
`speak` or `run` against an actual identity merely to validate this build recipe.
Those commands have separate network, billing, public-effect or operation gates.

## curl and Hermes boundaries

Choose explicit absolute paths to already installed **native executable** files.
A `.cmd`/`.bat` shell launcher is not interchangeable with `hermes.exe`. First
verify that the intended executable's `--help` can run under the host policy;
this does not authorize a model call.

The selected curl backend must support an enforced TLS 1.3 minimum, the
independently pinned CA, chain validation and hostname/IP validation. On
Windows, curl must be 8.10.0 or newer so `Retry-After` is captured from stderr;
older or unrecognized versions are refused before sending requests. A default
Windows curl/backend is not assumed suitable for every private CA. Schannel
revocation failures remain failures: do not add `--insecure`, disable revocation,
install a global root, use an outbound proxy for a private participant request,
or downgrade TLS to make the check pass. An approved alternate installed curl
must be verified using the same CA and TLS constraints.

The model contract retains the tool-free restrictions and passes bounded UTF-8
prompt bytes on standard input, not as a Windows command-line argument:

```text
hermes.exe --safe-mode --ignore-rules --toolsets "" --provider PROVIDER --model MODEL --reasoning REASONING --usage-file ABSOLUTE_PATH chat --oneshot --quiet --query-file -
```

The working directory is the canonical selected state directory; the usage path
is absolute and stays inside it. Input has a 100,000-byte local bound. The
regressions exercise Unicode input longer than the Windows command-line limit
and verify that the native peer receives it intact on stdin. Synthetic peers are
selected by explicit fixture paths/files, not secret inherited environment
variables: the production model environment is intentionally restricted.

Hermes retains ownership of its authentication. No credential copying, provider
login or model request belongs in tests/CI. Killing an owned CLI/process tree is
not proof that an already accepted gateway/provider generation was cancelled;
retain uncertain generation and budget accounting and do not kill a shared
Hermes gateway. To stop an authorized foreground worker, press Ctrl+C and wait
for its exit, stopped metadata and lock release before another writer command.
Do not delete/replace an active lock or start a competing request lane.

Start the selected Hermes gateway independently before enabling Windows model
work. Tolink requires an attach-only readiness verdict before reserving each
model attempt. This is not a lease: if the gateway disappears between the
probe and chat, the owned job still forbids breakaway and the attempted work
is handled by the normal uncertainty and accounting rules. Put a Windows
`recover import` file in the protected private state directory (or a separately
protected private directory), with no other-user allow grants.

## Tests and CI scope

[The Windows workflow](../.github/workflows/windows.yml) runs native MSVC
`cargo test --locked`, compiles the standalone synthetic peer, builds a locked
release, prints build metadata and validates the Windows example offline. It
uses read-only `contents` permission, checkout without persisted credentials and
no deployment secrets. It does not run a real room, invoke Hermes authentication
or call a provider. Dependency/toolchain downloads are build infrastructure, not
participant API traffic. The workflow does not change existing non-Windows jobs.

The included regressions keep their policy, journal, recipient, HTTP-error and
budget assertions. Windows fixtures close held Clients/locks before deletion.
Unix FIFO and process-wide `rlimit` controls are narrowly Unix-only; Windows adds
a real unconnected named-pipe import refusal and a held-destination sharing
violation/recovery control. macOS process-group assertions remain on macOS;
Windows process-tree tests use native handles and owned jobs.

`tests/support/native_peer.rs` still provides the optional synthetic loopback
TLS/model scenario. It now uses the shared private-file primitives and the
native stdin model contract. Compilation requires the cached `serde_json` rlib
and, on Windows, `windows_sys`, plus dependency search paths; the workflow shows
a PowerShell recipe that discovers these from Cargo's actual target directory
instead of assuming a fixed artifact layout. Its TLS mode additionally requires
an explicitly selected OpenSSL and synthetic CA/key fixture. CI **compiles** this
peer; compilation is not a TLS handshake or end-to-end TLS scenario pass.

Treat test logs, release output, offline example validation, a local synthetic
TLS exchange, an actual Hermes launch and a live authorized peer conversation as
separate gates. A recipe or proposed workflow is not a recorded CI run. Consult
the actual run's output; do not infer Windows acceptance from historical macOS
test counts or report a synthetic reply as a real model/provider result.
