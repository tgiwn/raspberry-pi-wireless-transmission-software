#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TCP message/file transfer prototype for a trusted local network.

This project is an independent educational prototype. It does not encrypt traffic
or authenticate peers; do not expose it directly to the public internet.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import socket
import struct
import shutil
import sys
import secrets
import tempfile
import time
import unicodedata
from functools import lru_cache
from pathlib import Path, PurePosixPath

CHUNK_SIZE = 64 * 1024
MAX_HEADER_SIZE = 16 * 1024
MAX_MESSAGE_SIZE = 1024 * 1024
MIB = 1024 * 1024
DEFAULT_MAX_FILE_SIZE = 8 * 1024 * 1024 * 1024  # 8 GiB
DEFAULT_IDLE_TIMEOUT = 300.0  # seconds without socket activity
MIN_FREE_SPACE_RESERVE = 64 * MIB  # leave a small reserve after a successful transfer
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOG = logging.getLogger("wireless-transfer")


class TransferError(RuntimeError):
    """A transfer was rejected or did not complete successfully."""


def _console_safe(value: object) -> str:
    """Represent dynamic values as ASCII so legacy Windows consoles cannot fail."""
    return ascii(str(value))[1:-1]


def recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly size bytes or raise if the peer closes early."""
    if size < 0:
        raise ValueError("Byte count cannot be negative")
    parts: list[bytes] = []
    remaining = size
    while remaining:
        data = sock.recv(min(CHUNK_SIZE, remaining))
        if not data:
            raise ConnectionError("Connection closed before the expected data arrived")
        parts.append(data)
        remaining -= len(data)
    return b"".join(parts)


def send_json_frame(sock: socket.socket, payload: dict) -> None:
    # Escaping non-ASCII in the JSON envelope also handles escaped lone surrogates
    # originating from POSIX filenames decoded with Python's surrogateescape.
    # Actual message content travels as UTF-8 body bytes, not in this envelope.
    raw = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if not raw or len(raw) > MAX_HEADER_SIZE:
        raise ValueError("JSON frame is empty or exceeds the header-size limit")
    sock.sendall(struct.pack("!I", len(raw)))
    sock.sendall(raw)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate JSON keys instead of silently accepting the last value."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    """Reject non-standard NaN/Infinity constants, which JSON does not permit."""
    raise ValueError(f"Non-standard JSON numeric constant: {value}")


def recv_json_frame(sock: socket.socket) -> dict:
    header_size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if header_size <= 0 or header_size > MAX_HEADER_SIZE:
        raise ValueError("Invalid JSON frame size")
    try:
        result = json.loads(
            recv_exact(sock, header_size).decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("Invalid JSON frame") from exc
    if not isinstance(result, dict):
        raise ValueError("JSON frame must contain an object")
    return result


def _parse_size(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


MAX_FILENAME_UTF16_UNITS = 240
MAX_FILENAME_UTF8_BYTES = 240  # Stay below common 255-byte POSIX NAME_MAX limits.


def _nfd_utf8_bytes(value: str) -> int:
    """Return bytes after canonical decomposition, as used by macOS filesystems."""
    return len(unicodedata.normalize("NFD", value).encode("utf-8"))


@lru_cache(maxsize=8192)
def _nfd_char_utf8_bytes(char: str) -> int:
    """Cached per-code-point byte length avoids repeated normalization work."""
    return len(unicodedata.normalize("NFD", char).encode("utf-8"))


def _truncate_filename(value: str, max_units: int, max_bytes: int) -> str:
    """Truncate safely for Windows, POSIX NAME_MAX, and macOS normalization."""
    result: list[str] = []
    used_units = 0
    used_bytes = 0
    used_nfd_bytes = 0
    for char in value:
        char_units = 2 if ord(char) > 0xFFFF else 1
        char_bytes = len(char.encode("utf-8"))
        # macOS filesystems commonly compare/store names in decomposed form. A
        # precomposed name may grow after filesystem normalization, so cap both
        # its literal UTF-8 length and its NFD UTF-8 length before publication.
        char_nfd_bytes = _nfd_char_utf8_bytes(char)
        if (used_units + char_units > max_units
                or used_bytes + char_bytes > max_bytes
                or used_nfd_bytes + char_nfd_bytes > max_bytes):
            break
        result.append(char)
        used_units += char_units
        used_bytes += char_bytes
        used_nfd_bytes += char_nfd_bytes
    return "".join(result)


def _name_lengths(value: str) -> tuple[int, int]:
    return len(value.encode("utf-16-le")) // 2, len(value.encode("utf-8"))


def _safe_filename(value: object) -> str:
    # Treat both Windows and POSIX separators as path separators regardless of OS.
    raw = str(value or "received.bin")
    # JSON can legally contain escaped lone UTF-16 surrogates even though those
    # code points are not valid Unicode scalar values and cannot be UTF-8 encoded.
    # Replace them before byte-length checks so a malformed peer filename is
    # rejected/sanitized rather than raising UnicodeEncodeError mid-handshake.
    raw = "".join("_" if 0xD800 <= ord(char) <= 0xDFFF else char for char in raw)
    raw = raw.replace("\\", "/")
    name = PurePosixPath(raw).name
    if name in ("", ".", ".."):
        name = "received.bin"
    # Windows device/control characters are invalid in filenames; normalize them.
    name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name).strip().rstrip(" .")
    if name in ("", ".", ".."):
        name = "received.bin"

    # Preserve a modest extension where possible. Limit both UTF-16 units (Windows)
    # and UTF-8 bytes (common POSIX filesystems such as those used on Raspberry Pi).
    suffix = Path(name).suffix
    suffix_units, suffix_bytes = _name_lengths(suffix)
    if suffix and suffix_units < 40 and suffix_bytes < 80:
        stem = name[:-len(suffix)]
        suffix_nfd_bytes = _nfd_utf8_bytes(suffix)
        # Keep room for the literal suffix and for its possible decomposed form.
        stem_byte_budget = min(
            MAX_FILENAME_UTF8_BYTES - suffix_bytes,
            MAX_FILENAME_UTF8_BYTES - suffix_nfd_bytes,
        )
        name = _truncate_filename(
            stem,
            MAX_FILENAME_UTF16_UNITS - suffix_units,
            stem_byte_budget,
        ) + suffix
    else:
        name = _truncate_filename(name, MAX_FILENAME_UTF16_UNITS, MAX_FILENAME_UTF8_BYTES)
    # Truncation can turn an internal space/dot into a trailing character, which
    # is invalid on Windows even though the original unsliced name was acceptable.
    name = name.rstrip(" .") or "received.bin"

    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"}
    reserved.update(f"COM{i}" for i in range(1, 10))
    reserved.update(f"LPT{i}" for i in range(1, 10))
    reserved.update(("COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"))
    # Windows treats device names with extensions, and names followed by spaces/dots
    # before an extension, as reserved as well (for example, "CON .txt").
    device_base = name.split(".", 1)[0].rstrip(" .").upper()
    if device_base in reserved:
        # Prefixing a nearly max-length device alias must still obey both limits.
        name = _truncate_filename(
            f"_{name}", MAX_FILENAME_UTF16_UNITS, MAX_FILENAME_UTF8_BYTES
        )
    return name


def hash_file(path: Path, show_progress: bool = False) -> str:
    total = path.stat().st_size
    digest = hashlib.sha256()
    read_total = 0
    next_percent = 10
    with path.open("rb") as stream:
        while block := stream.read(CHUNK_SIZE):
            digest.update(block)
            read_total += len(block)
            if show_progress and total:
                percent = min(100, int(read_total * 100 / total))
                if percent >= next_percent:
                    sys.stderr.write(f"\rHashing {ascii(path.name)}: {percent:3d}%")
                    sys.stderr.flush()
                    next_percent = (percent // 10 + 1) * 10
    if show_progress and total:
        sys.stderr.write("\rHashing complete.                 \n")
    return digest.hexdigest()



def _collision_candidate(name: str, index: int) -> str:
    """Add a numeric collision suffix while preserving both filename limits."""
    marker = f"_{index}"
    marker_units, marker_bytes = _name_lengths(marker)
    suffix = Path(name).suffix
    suffix_units, suffix_bytes = _name_lengths(suffix)
    marker_nfd_bytes = _nfd_utf8_bytes(marker)
    if suffix and suffix_units < 40 and suffix_bytes < 80:
        stem = name[:-len(suffix)]
        suffix_nfd_bytes = _nfd_utf8_bytes(suffix)
        stem_byte_budget = min(
            MAX_FILENAME_UTF8_BYTES - suffix_bytes - marker_bytes,
            MAX_FILENAME_UTF8_BYTES - suffix_nfd_bytes - marker_nfd_bytes,
        )
        candidate = _truncate_filename(
            stem,
            MAX_FILENAME_UTF16_UNITS - suffix_units - marker_units,
            stem_byte_budget,
        ) + marker + suffix
    else:
        candidate_byte_budget = min(
            MAX_FILENAME_UTF8_BYTES - marker_bytes,
            MAX_FILENAME_UTF8_BYTES - marker_nfd_bytes,
        )
        candidate = _truncate_filename(
            name,
            MAX_FILENAME_UTF16_UNITS - marker_units,
            candidate_byte_budget,
        ) + marker
    # _safe_filename() only adds a prefix for reserved device names; here the marker
    # makes a reserved stem non-reserved in the usual collision case, then validate.
    return _safe_filename(candidate)


def _check_hardlink_support(temp_path: Path, output_dir: Path) -> None:
    """Fail before streaming if the destination directory cannot create hard links."""
    for _ in range(5):
        probe = output_dir / f".link-check-{secrets.token_hex(8)}"
        try:
            os.link(temp_path, probe)
        except FileExistsError:
            continue
        except OSError as exc:
            raise OSError(
                "The destination filesystem or permissions do not support the hard-link "
                "operation required for atomic no-overwrite publication. Choose a supported "
                "destination (for example, an NTFS or ext4 volume) before sending the file. "
                f"Underlying error: {exc}"
            ) from exc
        else:
            try:
                probe.unlink()
            except OSError as exc:
                try:
                    probe.unlink(missing_ok=True)
                except OSError:
                    pass
                raise OSError(
                    "The destination can create a hard link but could not remove the temporary "
                    f"capability-check link: {exc}"
                ) from exc
            return
    raise OSError("Could not find an unused filename for the hard-link capability check")


def _publish_without_overwrite(temp_path: Path, output_dir: Path, name: str) -> tuple[Path, bool]:
    """Publish a verified temp file atomically without replacing an existing file."""
    index = 0
    while True:
        candidate_name = name if index == 0 else _collision_candidate(name, index)
        candidate = output_dir / candidate_name
        try:
            # A hard link is atomic and fails rather than replacing an existing path.
            os.link(temp_path, candidate)
        except FileExistsError:
            index += 1
            continue
        except OSError as exc:
            raise OSError(
                "Could not atomically publish the verified file. Check destination permissions "
                "and ensure the destination filesystem supports hard links. "
                f"Underlying error: {exc}"
            ) from exc
        try:
            temp_path.unlink(missing_ok=True)
        except OSError as exc:
            # The destination is already atomically published. Treat the transfer as
            # successful; the caller's finally block will retry temporary-file cleanup.
            LOG.warning(
                "Published %s but could not remove temporary hard link %s: %s",
                ascii(candidate.name), ascii(temp_path.name), _console_safe(exc),
            )
            return candidate, False
        return candidate, True


def _send_error(sock: socket.socket, message: str) -> None:
    try:
        send_json_frame(sock, {"status": "error", "error": message[:1000]})
    except OSError:
        pass


def handle_client(
    conn: socket.socket,
    output_dir: Path,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
) -> None:
    """Handle one connection. The caller owns and closes conn."""
    conn.settimeout(idle_timeout)
    temp_path: Path | None = None
    try:
        request = recv_json_frame(conn)
        kind = request.get("kind")
        if kind == "message":
            size = _parse_size(request.get("size"), "Message size")
            if size > MAX_MESSAGE_SIZE:
                raise ValueError(f"Message exceeds {MAX_MESSAGE_SIZE} byte limit")
            message = recv_exact(conn, size).decode("utf-8", errors="strict")
            # Show the message to the receiving user, but keep payloads out of app logs.
            # JSON escaping prevents newline/control-character terminal injection.
            print(f"Received message ({size} UTF-8 bytes): {json.dumps(message, ensure_ascii=True)}", flush=True)
            LOG.info("Message received (%d UTF-8 bytes)", size)
            send_json_frame(conn, {"status": "ok", "kind": "message"})
            return

        if kind != "file":
            raise ValueError("Unsupported packet type")
        size = _parse_size(request.get("size"), "File size")
        if size > max_file_size:
            raise ValueError(f"File exceeds receiver limit of {max_file_size} bytes")
        requested_filename = request.get("filename")
        if not isinstance(requested_filename, str) or requested_filename == "":
            raise ValueError("Filename must be a non-empty string")
        filename = _safe_filename(requested_filename)
        expected_hash = request.get("sha256", "")
        if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
            raise ValueError("A valid SHA-256 digest is required for file transfers")

        output_dir.mkdir(parents=True, exist_ok=True)
        if not output_dir.is_dir():
            raise OSError(f"Output path is not a directory: {output_dir}")
        # Reject files that cannot fit before asking the sender to transmit the body.
        # The reserve reduces the risk of filling the destination volume completely.
        free_bytes = shutil.disk_usage(output_dir).free
        required_bytes = size + MIN_FREE_SPACE_RESERVE
        if free_bytes < required_bytes:
            raise OSError(
                "Insufficient free space on receiver: "
                f"need {required_bytes} bytes including a {MIN_FREE_SPACE_RESERVE}-byte reserve, "
                f"have {free_bytes} bytes"
            )
        # Create a unique temporary file in the target directory before accepting the body.
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".incoming-", suffix=".part", dir=output_dir, delete=False
        ) as temp_stream:
            temp_path = Path(temp_stream.name)

        # Verify that atomic no-overwrite publication will work before acknowledging
        # readiness; otherwise the sender could waste a large transfer before failure.
        _check_hardlink_support(temp_path, output_dir)

        # Readiness handshake avoids sending gigabytes to a receiver that has rejected
        # the request (for example, because its configured size limit is lower).
        send_json_frame(conn, {"status": "ready", "size": size})

        digest = hashlib.sha256()
        remaining = size
        with temp_path.open("wb") as stream:
            while remaining:
                block = conn.recv(min(CHUNK_SIZE, remaining))
                if not block:
                    raise ConnectionError("Connection closed during file transfer")
                stream.write(block)
                digest.update(block)
                remaining -= len(block)
            stream.flush()
            os.fsync(stream.fileno())

        actual_hash = digest.hexdigest()
        if actual_hash.lower() != expected_hash.lower():
            raise ValueError("SHA-256 mismatch; received file failed integrity verification")

        destination, temp_removed = _publish_without_overwrite(temp_path, output_dir, filename)
        if temp_removed:
            temp_path = None
        LOG.info("Saved %s (%d bytes; SHA-256 %s)", ascii(destination.name), size, actual_hash)
        send_json_frame(conn, {"status": "ok", "filename": destination.name,
                               "size": size, "sha256": actual_hash})
    except Exception as exc:
        _send_error(conn, str(exc))
        raise
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                LOG.warning("Could not remove incomplete temporary file %s", ascii(str(temp_path)))


def receive(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir).expanduser().resolve()
    max_file_size = args.max_file_size_mib * MIB
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(5)
        LOG.info("Listening on %s:%d; output directory: %s", args.host, args.port, ascii(str(output_dir)))
        LOG.info("Maximum file size: %d MiB; idle timeout: %g s",
                 args.max_file_size_mib, args.idle_timeout)
        while True:
            conn, address = server.accept()
            LOG.info("Connection from %s:%d", *address)
            try:
                with conn:
                    handle_client(conn, output_dir, max_file_size, args.idle_timeout)
            except Exception as exc:
                LOG.warning("Transfer failed from %s: %s", address[0], _console_safe(exc))


def _prepare_file(path: Path, max_file_size: int) -> tuple[int, str]:
    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {path}")
    before = path.stat()
    size = before.st_size
    if size > max_file_size:
        raise ValueError(f"File is {size} bytes, exceeding the configured {max_file_size} byte limit")
    LOG.info("Computing SHA-256 for %s (%d bytes)", ascii(path.name), size)
    digest = hash_file(path, show_progress=size >= 10 * MIB)
    after = path.stat()
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise TransferError("Source file changed while its SHA-256 digest was being computed")
    return size, digest


def _check_ack(ack: dict, expected_status: str) -> None:
    if ack.get("status") != expected_status:
        error = ack.get("error")
        # The receiver is not authenticated, so treat any returned error string as
        # untrusted terminal text. ascii() escapes control characters such as ESC.
        if isinstance(error, str):
            safe_error = ascii(error)[1:-1]
        else:
            safe_error = "Unexpected receiver response: " + ascii(ack)
        raise TransferError(safe_error)


def _require_int_field(payload: dict, key: str, expected: int, context: str) -> None:
    value = payload.get(key)
    # bool is a subclass of int in Python, so use exact type equality. A malformed
    # peer must not be allowed to claim that True is the byte count 1.
    if type(value) is not int or value != expected:
        raise TransferError(f"{context} did not contain the expected integer {key}")


def send(args: argparse.Namespace) -> None:
    max_file_size = args.max_file_size_mib * MIB
    path: Path | None = None
    size: int | None = None
    digest: str | None = None
    if args.message is not None:
        message = args.message.encode("utf-8")
        if len(message) > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message exceeds {MAX_MESSAGE_SIZE} byte limit")
    else:
        path = Path(args.file).expanduser().resolve()
        size, digest = _prepare_file(path, max_file_size)

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(args.idle_timeout)
        if args.message is not None:
            send_json_frame(sock, {"kind": "message", "size": len(message)})
            sock.sendall(message)
            response = recv_json_frame(sock)
            _check_ack(response, "ok")
            if response.get("kind") != "message":
                raise TransferError("Receiver acknowledgement did not confirm a message")
            print(json.dumps(response, ensure_ascii=True))
            return

        assert path is not None and size is not None and digest is not None
        send_json_frame(sock, {"kind": "file", "filename": path.name,
                               "size": size, "sha256": digest})
        ready = recv_json_frame(sock)
        _check_ack(ready, "ready")
        _require_int_field(ready, "size", size, "Receiver readiness response")

        sent = 0
        next_percent = 1
        start = time.monotonic()
        with path.open("rb") as stream:
            remaining = size
            while remaining:
                block = stream.read(min(CHUNK_SIZE, remaining))
                if not block:
                    raise TransferError("Source file became shorter during transfer")
                sock.sendall(block)
                sent += len(block)
                remaining -= len(block)
                if size:
                    percent = int(sent * 100 / size)
                    if percent >= next_percent:
                        sys.stderr.write(f"\rSending {ascii(path.name)}: {percent:3d}%")
                        sys.stderr.flush()
                        next_percent = percent + 1
        if size:
            sys.stderr.write("\n")
        response = recv_json_frame(sock)
        _check_ack(response, "ok")
        _require_int_field(response, "size", size, "Receiver acknowledgement")
        if response.get("sha256") != digest:
            raise TransferError("Receiver acknowledgement did not match the sent file SHA-256")
        if not isinstance(response.get("filename"), str) or not response["filename"]:
            raise TransferError("Receiver acknowledgement did not include a valid destination filename")
        elapsed = max(time.monotonic() - start, 1e-9)
        response["transfer_seconds"] = round(elapsed, 3)
        response["average_mib_per_second"] = round(size / MIB / elapsed, 3)
        print(json.dumps(response, ensure_ascii=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TCP message/file transfer prototype for a trusted LAN")
    sub = parser.add_subparsers(dest="command", required=True)

    receiver = sub.add_parser("receive", help="listen for messages and files")
    receiver.add_argument("--host", default="0.0.0.0", help="interface to listen on")
    receiver.add_argument("--port", type=int, default=5001)
    receiver.add_argument("--output-dir", default="received")
    receiver.add_argument("--max-file-size-mib", type=int, default=DEFAULT_MAX_FILE_SIZE // MIB,
                          help="maximum accepted file size in MiB (default: 8192 = 8 GiB)")
    receiver.add_argument("--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT,
                          help="socket inactivity timeout in seconds (default: 300)")
    receiver.set_defaults(func=receive)

    sender = sub.add_parser("send", help="send a message or file")
    sender.add_argument("--host", required=True, help="receiver IP address")
    sender.add_argument("--port", type=int, default=5001)
    sender.add_argument("--max-file-size-mib", type=int, default=DEFAULT_MAX_FILE_SIZE // MIB,
                        help="maximum outgoing file size in MiB (default: 8192 = 8 GiB)")
    sender.add_argument("--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT,
                        help="socket inactivity timeout in seconds (default: 300)")
    group = sender.add_mutually_exclusive_group(required=True)
    group.add_argument("--message")
    group.add_argument("--file")
    sender.set_defaults(func=send)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.max_file_size_mib < 1:
        parser.error("--max-file-size-mib must be at least 1")
    if not 0 < args.idle_timeout <= 86400:
        parser.error("--idle-timeout must be greater than 0 and at most 86400 seconds")
    try:
        args.func(args)
    except (OSError, ValueError, ConnectionError, json.JSONDecodeError, TransferError) as exc:
        LOG.error("%s", _console_safe(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
