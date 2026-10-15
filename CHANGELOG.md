## Licensing

- Added the Apache License 2.0 text and SPDX identifiers for project-authored implementation and test code. Confirm you have the rights to license all included material before publishing.

# Changelog

## Independent prototype completion pass

- Raised the configurable default maximum file size from 100 MiB to 8192 MiB (8 GiB).
- Replaced the 30-second socket timeout with a configurable 300-second inactivity timeout.
- Added a size-aware readiness handshake before file-body streaming.
- Added sender hashing/sending progress, transfer time and average-throughput reporting.
- Tightened JSON framing, filename normalization, digest validation, temporary-file cleanup, and no-overwrite publication.
- Displayed received messages safely in the receiver terminal while avoiding payloads in application logs.
- Removed unused path-selection code and corrected the opt-in large-transfer test timeout diagnostic.
- Added an actionable diagnostic when atomic hard-link publication is unsupported by the destination filesystem.
- Expanded unit tests and added an opt-in 101 MiB TCP end-to-end smoke test.
- Updated the README and architecture documentation to describe the protocol and security limits.

The real 6 GB transfer between the user's own devices has not been tested in this environment.

### Continuous-integration strengthening (2026-10-14)

- Run the opt-in 101 MiB TCP streaming smoke test in GitHub Actions in addition to the protocol unit tests, so the end-to-end file-body path is exercised on each supported Python version.

### Additional filename edge-case audit (2026-10-14)

- Enforced Windows-compatible UTF-16 filename length limits and added tests for supplementary Unicode characters and superscript device names.

### Cross-platform filename hardening (2026-10-14)

- Enforced both Windows UTF-16-unit and POSIX UTF-8-byte component limits to support Unicode filenames on Windows and Raspberry Pi/Linux filesystems.
- Ensured numeric collision suffixes preserve those limits rather than growing an already long filename past the filesystem cap.
- Added deterministic mixed-Unicode property tests for sanitization and collision suffixes.

### Final cross-platform verification (2026-10-14)

- Limited sanitized filenames by both UTF-16 code units and UTF-8 bytes so long multi-byte names remain portable across Windows and Raspberry Pi/Linux filesystems.
- Added collision-suffix tests and a deterministic stress corpus for mixed Unicode filenames.
- Re-ran opt-in 101 MiB, 1 GiB, and 6 GiB TCP loopback transfers with byte-count and SHA-256 verification on the updated source.

- Normalized trailing dots/spaces and blocked Windows device-name aliases with spaces before extensions.
- Kept reserved-name prefixing within the same length limits for names with very long extensions.

- Probe hard-link capability before the readiness acknowledgement so an unsupported destination filesystem is rejected before large payload bytes are sent.

### Malformed-Unicode envelope hardening (2026-10-14)

- Sanitize unpaired UTF-16 surrogate code points in peer-supplied filenames instead of raising `UnicodeEncodeError`.
- Serialize JSON headers with ASCII escapes so unusual POSIX source filenames can still be represented safely in the transfer protocol.
- Add round-trip and end-to-end regression coverage for JSON-escaped lone surrogates.

### GitHub Actions runtime compatibility (2026-10-14)

- Upgraded checkout/setup actions to current Node 24-compatible major releases because GitHub removed Node 20 from Actions runners on September 23, 2026.
- Added regression coverage for JSON envelope serialization of escaped unpaired surrogates and safe receiver-side filename sanitization.

### Fifteen-pass release audit (2026-10-14)

- ASCII-escape message text, filenames, and CLI acknowledgements in console output so legacy Windows code pages cannot raise encoding errors for Unicode content.
- Treat an atomically published destination as successfully received even if removing the temporary hard link fails transiently; warn and retry cleanup in the receiver's `finally` block.
- Add regression tests for console encoding and cleanup-failure semantics.
- Verify the individual and combined bundles use identical workflow versions; add Python 3.14 to the CI matrix and update the trifilar test workflow to Node.js 24.


### Sender acknowledgement validation follow-up (2026-10-14)

- Require a message acknowledgement to confirm `kind: message`, not just a generic `status: ok`.
- Require readiness and final acknowledgement byte counts to be exact JSON integers, rejecting booleans and mismatched types.
- Require a non-empty destination filename and matching SHA-256 in successful file acknowledgements.
- Escape terminal control characters in peer-provided error messages.
- Add regression tests for malformed message/file acknowledgements and terminal-control injection.
- Re-run 101 MiB, 1 GiB and 6 GiB end-to-end TCP tests after the protocol changes; all passed with matching hashes.


### Malformed request validation and Windows CI (2026-10-14)

- Reject missing, empty, or non-string filename fields before acknowledging readiness.
- Add regression coverage ensuring malformed filenames create neither output nor temporary files.
- Add a Windows-hosted CI job to exercise protocol tests on the receiver platform in addition to the Ubuntu/Python-version matrix; its hosted result remains pending until push.


### Strict message decoding and console logging (2026-10-14)

- Reject malformed UTF-8 message bodies instead of silently replacing invalid bytes and reporting successful delivery.
- Escape dynamic path and exception strings in logs so Unicode filenames/output paths do not trigger encoding errors on legacy Windows consoles.
- Add regression tests for malformed UTF-8 bodies and ASCII-safe console representations.


### Strict UTF-8 message handling and console-safe logging (2026-10-14)

- Reject malformed UTF-8 message payloads instead of replacing invalid bytes and acknowledging delivery.
- ASCII-escape output-directory paths and exception messages in logs for legacy Windows console compatibility.
- Add regression tests for invalid UTF-8 messages and dynamic console output.


### Strict UTF-8 message handling, console safety, and ignore rules (2026-10-14)

- Reject malformed UTF-8 message bodies instead of silently replacing invalid bytes and acknowledging delivery.
- ASCII-escape output-directory paths and exception messages in logs for legacy Windows console compatibility.
- Ignore local coverage artifacts in both repositories so they are not accidentally committed after audit tooling runs.
- Add regression tests for invalid UTF-8 messages and ASCII-safe console representations.


### Strict JSON-envelope validation (2026-10-14)

- Reject duplicate keys and non-standard `NaN`/`Infinity` numeric constants when parsing protocol frames; the encoder also refuses non-standard JSON numbers.
- Normalize malformed/nested-frame parser exceptions to clear protocol errors.
- Add regression tests for duplicate keys, non-standard constants, and encoder-side non-finite numbers.


### Filename edge-case follow-up (2026-10-14)

- Trim trailing spaces/dots again after truncation, because cutting at a component-length boundary can expose an internal trailing space that Windows will not handle consistently.
- Treat `CLOCK$` as a reserved Windows filename for compatibility with common Windows file dialogs in addition to documented DOS device aliases.
- Add regression checks for truncation-boundary whitespace and the `CLOCK$` alias.

### Filename truncation boundary and reserved alias audit (2026-10-14)

- Trim Windows-illegal trailing spaces/dots after truncation as well as before it.
- Sanitize the `CLOCK$` compatibility alias in addition to the documented DOS device names.
- Revalidated 100,000 randomized mixed-Unicode input names and 600,000 collision-suffix variants against Windows UTF-16 and POSIX UTF-8 component limits.

### Large-transfer test efficiency (2026-10-14)

- Removed redundant full-file checksum rereads from the opt-in large-transfer test. The sender already hashes the source, validates the receiver's final SHA-256 acknowledgement against that digest, and the test confirms the published file exists with the expected size and acknowledgement fields.
- Re-ran the 6 GiB synthetic loopback transfer with the optimized test; it completed and passed instead of timing out during duplicate checksum scans.

