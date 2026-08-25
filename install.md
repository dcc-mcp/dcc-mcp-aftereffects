# Install dcc-mcp-aftereffects

This runbook installs, verifies, upgrades, and removes the DCC-MCP adapter for
Adobe After Effects. Agents should read the
[raw file](https://raw.githubusercontent.com/dcc-mcp/dcc-mcp-aftereffects/main/install.md)
before changing an installation.

The Core catalog `instructions_url` and pinned install block are tracked outside
this repository. Until that catalog change lands, use this adapter-owned entry
point and do not claim catalog installation is complete.

## Requirements

- **After Effects:** 2024 / 24.0 or newer on Windows or macOS.
  Preflight verifies Adobe product metadata and the platform code signature;
  a renamed executable or copied unsigned bundle is rejected.
- **Python:** 3.9 or newer for the adapter sidecar; this is not After Effects'
  embedded ExtendScript runtime.
- **dcc-mcp-core:** 0.20.14 or newer in the selected Python environment.
- **adobepy:** Python SDK 0.6.2 plus the matching audited `adobepy` CLI binary.
- **Authentication:** one non-empty `ADOBEPY_TOKEN` shared by the broker and
  CEP bridge.
- **Permissions:** write access to the current user's CEP extension and
  DCC-MCP state directories.

The PyPI `adobepy` wheel contains the Python SDK, not the Rust CLI. On Windows,
use the official `adobepy-v0.6.2` release asset
`adobepy-0.6.2-windows-x64.zip`. The adapter pins its published archive SHA-256
`9ef9abb5e034359f12e9ce248b0030e38d34c76df343eb2713f18036068719a7`
and the extracted `bin/adobepy.exe` SHA-256
`c02f28f07705b69a4f97f9f6639f0f80d1f5292115446801fbd92423336301aa`.
Set `ADOBEPY_CLI` to that executable. An optional `ADOBEPY_CLI_SHA256` must equal
the pinned executable digest; it cannot introduce a new trust root. The
package-owned digest map binds the selected versioned asset, bounded manifest,
and CLI bytes to fixed SHA-256, byte size, and layout. Remediation verifies each
bound value and fails closed after download before installing mismatched bytes.
An adjacent manifest alone is not trust. No macOS CLI release is currently
allowlisted, so install and upgrade there fail closed with exit `20`; the adapter
never copies an unverified bridge.

Keep the token in the process environment. The adapter passes it to the
supported CLI through `ADOBEPY_TOKEN`; it never places the token in command
arguments, reports, logs, receipts, or PR text.

## Supported versions

Current adapter release: **0.7.0** <!-- x-release-please-version -->

| Adapter | dcc-mcp-core | After Effects | Python | Platform |
|---|---|---|---|---|
| Current release | >=0.20.14,<1 | >=24.0 | >=3.9 | Windows 10/11 x64 |
| Current release | >=0.20.14,<1 | >=24.0 | >=3.9 | macOS discovery only; no allowlisted CLI release yet |
| Current release | >=0.20.14,<1 | unavailable | >=3.9 | Linux package development only; no host install |

Default host and profile paths are:

- Windows host: `C:\Program Files\Adobe\Adobe After Effects 2024\Support Files\AfterFX.exe`
- Windows CEP root: `%APPDATA%\Adobe\CEP\extensions`
- macOS host: `/Applications/Adobe After Effects 2024/Adobe After Effects 2024.app`
- macOS CEP root: `~/Library/Application Support/Adobe/CEP/extensions`

The adapter owns only the `dcc-mcp-aftereffects` child under that CEP root and
its receipt. Unsupported hosts, interpreters, and profiles fail preflight
before any directory is changed.

## Agent quick path

Set the secret and supported CLI in the operator environment without printing
the secret. Then inspect the non-mutating plan:

```text
dcc-mcp-aftereffects install --dcc-path "<absolute After Effects path>" --python "<adapter python>" --json --dry-run
```

Review the host, interpreter, extension path, receipt path, current state
(`fresh`, `installed`, or `partial`), ordered steps, and every `next_steps`
entry. Execute only after the plan is correct:

```text
dcc-mcp-aftereffects install --dcc-path "<absolute After Effects path>" --python "<adapter python>" --json --yes
dcc-mcp-aftereffects status --dcc-path "<absolute After Effects path>" --python "<adapter python>" --json
dcc-mcp-aftereffects verify --dcc-path "<absolute After Effects path>" --python "<adapter python>" --json
```

All lifecycle verbs accept the uniform flags `--json`, `--yes`, `--dry-run`,
`--dcc-path`, and `--python`. Stable exits are:

| Exit | Meaning |
|---:|---|
| 0 | plan or operation completed successfully |
| 10 | host, profile, interpreter, version, authentication, or receipt preflight failed |
| 20 | a supported external adobepy CLI is unavailable |
| 30 | staged install, receipt commit, rollback, or uninstall failed |
| 40 | import or typed verify-to-usable probe failed |
| 50 | After Effects must release/reload a locked or newly installed CEP extension |

## Manual path

1. Install the adapter wheel in the Python environment that will run the
   sidecar: `python -m pip install --upgrade dcc-mcp-aftereffects`.
2. Obtain the official adobepy CLI for the intended platform from an approved,
   versioned release and verify its published checksum. Do not scrape a
   mutable “latest” page.
3. Verify the archive checksum above, extract it without changing its bundle
   layout, and set `ADOBEPY_CLI` to `bin/adobepy.exe`. Set `ADOBEPY_TOKEN` to the
   broker token and optionally set the loopback-only `ADOBEPY_BROKER_URL` /
   bounded `ADOBEPY_TARGET`.
4. Run the JSON dry-run from **Agent quick path** with the exact host and
   Python paths.
5. Execute with `--yes`. The adapter asks the official adobepy CLI to assemble
   the CEP extension in a sibling staging directory, validates its typed JSON
   result, atomically swaps the adapter-owned directory, and writes a receipt.
6. If exit `50` returns ordered `next_steps[].command` values, save work, launch
   the exact signed After Effects product, then run the exact context-preserving
   `verify` command. The installer never drives the UI, kills the host, or uses a
   broad scripting fallback.
7. Run the verification sequence below. If the official runtime cannot expose
   exact PID/start/executable/profile/CEP-module identity, verification fails
   closed instead of treating a broker socket or manual UI claim as readiness.

An existing target without a matching receipt is `partial`; install and upgrade
preserve it and fail closed instead of guessing ownership. Upgrade keeps the old
directory until the new staged payload, receipt, and live verification all pass.
A commit or verification failure restores the exact prior directory and receipt.
No delete-then-copy update is used.

## Verify

```text
dcc-mcp-aftereffects verify --dcc-path "<absolute After Effects path>" --python "<adapter python>" --json
dcc-mcp-cli wait-ready --dcc-type aftereffects --require host_execution_bridge --require main_thread_executor
dcc-mcp-cli search --query "After Effects project ping" --dcc-type aftereffects
```

Verification validates the complete typed file/directory/link receipt closure,
distribution-owned `adobe`, Core, and adapter modules, the canonical Core schema,
and the complete CEP capability contract. It then binds the typed RPC to the
selected signed AfterFX product, PID/start identity, instance/profile, broker,
target, and receipted CEP module origin. Only then is `verify.directly_usable`
true. A broker socket alone is not readiness.

Bootstrap/startup failures are captured as a bounded, redacted JSON diagnostic
under the adapter state directory. It records stage, error type, timestamp, and
message but never the token.

## Upgrade

Upgrade the Python wheel first, inspect the host change, then execute:

```text
python -m pip install --upgrade dcc-mcp-aftereffects
dcc-mcp-aftereffects upgrade --dcc-path "<absolute After Effects path>" --python "<adapter python>" --json --dry-run
dcc-mcp-aftereffects upgrade --dcc-path "<absolute After Effects path>" --python "<adapter python>" --json --yes
dcc-mcp-aftereffects verify --dcc-path "<absolute After Effects path>" --python "<adapter python>" --json
```

Upgrade requires the existing adapter receipt. It stages before swapping and
retains the previous extension and receipt until live verification succeeds.
Stage, commit, receipt, or live verify failure restores the exact prior install.
Exit `50` means After Effects owns a file lock or must reload the newly installed
extension; follow only the ordered returned commands.

## Uninstall

Inspect the receipt-driven plan, then remove only the adapter-owned extension:

```text
dcc-mcp-aftereffects uninstall --dcc-path "<absolute After Effects path>" --python "<adapter python>" --json --dry-run
dcc-mcp-aftereffects uninstall --dcc-path "<absolute After Effects path>" --python "<adapter python>" --json --yes
python -m pip uninstall dcc-mcp-aftereffects
```

Uninstall consumes the receipt and refuses to delete an unreceipted or
mismatched directory. It keeps a validated recovery snapshot through receipt
removal and restores the install on failure. Repeating uninstall after success
is a schema-valid no-op. After Effects projects, Adobe preferences, other CEP
extensions, the broker, and adobepy remain operator-owned.

## Troubleshooting

| Result | Diagnosis | Action |
|---|---|---|
| Exit 10, `host` | host not found or wrong `--dcc-path` | Pass the exact `AfterFX.exe` or `.app` from the table. |
| Exit 10, `python` / `core` | wrong sidecar interpreter or old Core | Install the wheel/Core in that interpreter and pass it with `--python`. |
| Exit 10, `authentication` | `ADOBEPY_TOKEN` is missing | Set it in the installer/broker environment without echoing it. |
| Exit 10, `receipt` | partial or mismatched install | Run `status`, inspect ownership, and preserve unreceipted content; do not retry a destructive repair. |
| Exit 20, `acquire` | supported adobepy CLI not found | Download the exact Windows asset above, verify its published archive checksum, extract it, and set `ADOBEPY_CLI`. |
| Exit 30, `install` / `rollback` | staging, commit, or rollback failed | Preserve the redacted report and retry only after fixing permissions/disk space. |
| Exit 40, `import` | target environment cannot import both packages | Repair that exact Python environment. |
| Exit 40, `readiness` | CEP bridge is not loaded or typed RPC failed | Start the intended project, follow Adobe's CEP development workflow if required, and rerun verify. |
| Exit 50 | host reload or real file lock | Save work, close/restart only the reported After Effects instance, then repeat. |

For shared runtime diagnosis, keep the redacted failure report and run
`dcc-mcp-cli doctor` and `dcc-mcp-cli list`.
