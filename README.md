# Raspberry Pi Wireless Transmission Software — Independent Prototype

This repository is a newly written, independent educational prototype inspired by a software registration title. It is **not the original registered source code**, it has been verified against the original program.

## What it does

- Sends UTF-8 text messages and files over TCP on a trusted local network.
- Streams file content in 64 KiB chunks instead of loading the whole file into memory.
- Uses a size-aware readiness handshake before sending file content, so the sender learns when the receiver rejects a file.
- Computes SHA-256 on the sender and verifies the digest on the receiver before publishing the file.
- Writes to a unique temporary file, then publishes the completed file atomically without overwriting an existing destination. The receiving filesystem must support hard links (for example, normal NTFS/ext4 volumes); unsupported filesystems fail with a diagnostic before the sender streams the file.
- Uses a collision suffix such as `report_1.pdf` when a name already exists; sanitized filenames respect Windows UTF-16 component limits, literal POSIX UTF-8 byte limits, and UTF-8 length after canonical Unicode decomposition on normalization-aware filesystems such as macOS, including added collision suffixes.
- Reports hashing and send progress, transfer duration, and average throughput. Incoming text is displayed in the receiver terminal as JSON-escaped text; message contents are not written to application logs.
- Supports configurable file-size and socket-inactivity limits.
- Validates acknowledgement fields strictly (including message kind and exact integer byte counts), rejects duplicate JSON keys and non-standard `NaN`/`Infinity` constants, rejects missing/empty/non-string incoming filenames and malformed UTF-8 message bodies, and escapes peer-supplied errors and dynamic console values for legacy terminal compatibility.
- Includes protocol/unit tests and GitHub Actions coverage on Ubuntu (Python 3.10–3.14) and Windows (Python 3.13). The Windows-hosted job must be confirmed after the repository is pushed.

## Requirements

- Python 3.10 or newer
- No third-party Python packages
- Raspberry Pi OS, Windows, macOS, Linux, or Android with a Python environment such as Termux (device/network restrictions may apply)

## Quick start

### On the receiving device

```bash
python3 wireless_transfer.py receive --host 0.0.0.0 --port 5001 --output-dir received --max-file-size-mib 8192 --idle-timeout 300
```

On Windows, the executable may be named `py` rather than `python3`:

```powershell
py .\wireless_transfer.py receive --host 0.0.0.0 --port 5001 --output-dir "$env:USERPROFILE\Downloads\received" --max-file-size-mib 8192 --idle-timeout 300
```

Find the receiver's LAN IP address (for example, `hostname -I` on Raspberry Pi OS or `ipconfig` on Windows). The sending device must be able to reach that IP and port. Guest Wi-Fi and campus/public networks may block device-to-device connections.

### Send a message

```bash
python3 wireless_transfer.py send --host 192.168.1.50 --port 5001 --message "Hello from my laptop"
```

### Send a file

```bash
python3 wireless_transfer.py send --host 192.168.1.50 --port 5001 --file ./example.pdf --max-file-size-mib 8192 --idle-timeout 300
```

Use the actual receiver IP in place of `192.168.1.50`. The sender and receiver must both allow a file at least as large as the file being transferred. The configured limit is in **MiB**; the default is 8192 MiB (8 GiB). To restrict transfers to 100 MiB, set `--max-file-size-mib 100` on both commands.

## Large-file notes

Files are streamed, so the program's memory use does not grow with the file size. The sender reads the file once to compute its SHA-256 digest, then reads it again to send it; large files therefore require additional disk I/O and time. `--idle-timeout` limits how long a socket operation can go without activity; the default is 300 seconds. It is not a total transfer-duration limit. Keep the receiver application running, avoid sleep/hibernation, and ensure adequate free disk space on the receiver. The receiver checks the declared file size plus a 64 MiB reserve and probes that hard-link publication works before replying that it is ready; this makes a low-space failure visible before the sender streams the entire file. This check cannot prevent another process from consuming disk space during a transfer.

A 6 GB transfer has not been confirmed on every operating system or Wi-Fi network. This version removes the previous hard-coded 100 MiB restriction and the 30-second timeout, but the real network test still needs to be run on the intended devices. Follow [`docs/REAL_WORLD_VALIDATION.md`](docs/REAL_WORLD_VALIDATION.md) to check protocol version, network reachability, destination free space, staged sizes, and end-to-end SHA-256 integrity.

## Security limitations

This prototype is only for a trusted local network. It does **not** encrypt traffic or authenticate or authorize peers. Anyone who can reach the listening port may attempt to send messages/files within the configured size limit. Do not expose it to the public internet or use it for sensitive data. A production system should add authenticated TLS, peer authorization, access controls, rate limits, and a deliberate storage quota. Raising the file-size limit increases the potential storage-denial-of-service risk.

## Tests

```bash
python -m unittest discover -s tests -v
python -m py_compile wireless_transfer.py
```

The tests cover message framing, strict UTF-8 message decoding, filename sanitization and malformed filename fields, no-overwrite behavior, size and free-space preflight rejection, integrity checks, truncated transfers, empty files, and acceptance of file sizes above 100 MiB by the default limit. The normal suite avoids sending a large payload each run. For an end-to-end local TCP smoke test, run `RUN_LARGE_TRANSFER_TEST=1 python -m unittest tests.test_large_transfer -v` (101 MiB by default). To test 1 GiB locally, use `TRANSFER_TEST_MIB=1024 RUN_LARGE_TRANSFER_TEST=1 python -m unittest tests.test_large_transfer -v`. These tests use loopback TCP and do not replace the real-device checklist.

## Copyright and provenance

This independent recreation/prototype is not the registered software's original source code. The supplied certificate title is 基于树莓派的无线传输软件 V1.0 (registration number stated on the supplied certificate: 2026SR0573929). The certificate names 天津职业技术师范大学（中国职业培训指导教师进修中心） as the copyright holder. This repository does not imply ownership of the registered work or permission to redistribute its original source/assets. Confirm authorization before public release and describe this code accurately in applications.



## License

The independently written code and documentation in this repository are licensed under the [Apache License, Version 2.0](LICENSE), subject to the publisher having the rights to grant that license. The license does not apply to third-party material or grant rights to any separately registered software, institutional names, or logos. See [COPYRIGHT.md](COPYRIGHT.md) for provenance and scope.
