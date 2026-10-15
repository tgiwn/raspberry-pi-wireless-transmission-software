# Test Summary — Wireless Transmission Prototype

**Audit date:** 14 October 2026  
**Project type:** Independent educational prototype

This record summarizes the automated and synthetic loopback checks performed on the audited release. It separates software-test evidence from validation on particular devices and networks.

## Test results

- `python -m unittest discover -s tests -v`: 32 tests discovered; 31 passed and 1 optional large-transfer test was skipped by default.
- `python -m py_compile wireless_transfer.py`: passed.
- Protocol and error-handling tests cover message/file framing, acknowledgement validation, SHA-256 integrity checks, collision-safe names, malformed input, truncated transfers, temporary-file cleanup, and refusal to overwrite an existing file.
- Separate loopback TCP smoke tests at 101 MiB, 1 GiB, and 6 GiB completed against the audited release source. Receiver-acknowledged byte counts and SHA-256 checks matched. These used synthetic sparse test files with marker bytes; they were not tests of the user's actual Android-to-Windows Wi-Fi route or a real 6 GB archive.
- Filename property tests covered 10,000 mixed-Unicode names and 50,000 collision variants for path safety and platform filename limits.

## Validation scope and next steps

The results support the software-level behaviors exercised by these tests. For a complete deployment evaluation, test Android/Termux to Windows on the intended Wi-Fi network and transfer the actual 6 GB archive, then compare sender and receiver SHA-256 hashes. Also evaluate expected operating conditions such as router client isolation, firewall settings, sleep/hibernation, power interruption, and limited storage.

For reproducibility, record the operating systems, device/network setup, source and received file sizes, elapsed time, sender/receiver hashes, and any errors. Follow [`REAL_WORLD_VALIDATION.md`](REAL_WORLD_VALIDATION.md) for the procedure.

## Security consideration

Traffic is unencrypted and the sender is not authenticated or authorized. Use only on a trusted local network; do not expose the receiver directly to the public internet or use this prototype to transfer sensitive data.
