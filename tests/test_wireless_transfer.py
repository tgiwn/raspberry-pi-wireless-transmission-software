# SPDX-License-Identifier: Apache-2.0
import contextlib
import hashlib
import io
import json
import socket
import struct
import sys
import tempfile
import unicodedata
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wireless_transfer as wt


class SocketPairHarness:
    def __init__(self, output_dir, max_file_size=wt.DEFAULT_MAX_FILE_SIZE):
        self.output_dir = Path(output_dir)
        self.server_sock, self.client_sock = socket.socketpair()
        self.errors = []

        def serve():
            try:
                wt.handle_client(self.server_sock, self.output_dir, max_file_size=max_file_size,
                                 idle_timeout=5)
            except Exception as exc:
                self.errors.append(exc)
            finally:
                self.server_sock.close()

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def send_header(self, header):
        wt.send_json_frame(self.client_sock, header)

    def receive_frame(self):
        return wt.recv_json_frame(self.client_sock)

    def close(self):
        self.client_sock.close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise AssertionError("Receiver thread did not finish")


class FakeTcpReceiverHarness:
    """One-shot TCP peer for testing sender-side protocol validation."""
    def __init__(self, handler):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.host, self.port = self.listener.getsockname()
        self.errors = []

        def serve():
            try:
                conn, _ = self.listener.accept()
                with conn:
                    handler(conn)
            except Exception as exc:
                self.errors.append(exc)
            finally:
                self.listener.close()

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def close(self):
        self.listener.close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise AssertionError("Fake receiver thread did not finish")


class ProtocolTests(unittest.TestCase):
    def test_recv_exact(self):
        a, b = socket.socketpair()
        try:
            a.sendall(b"abcdef")
            self.assertEqual(wt.recv_exact(b, 6), b"abcdef")
            self.assertEqual(wt.recv_exact(b, 0), b"")
            with self.assertRaises(ValueError):
                wt.recv_exact(b, -1)
        finally:
            a.close()
            b.close()

    def test_json_frame_round_trip(self):
        a, b = socket.socketpair()
        try:
            payload = {"status": "ok", "text": "你好", "unpaired_surrogate": "\ud800"}
            wt.send_json_frame(a, payload)
            self.assertEqual(wt.recv_json_frame(b), payload)
        finally:
            a.close()
            b.close()

    def test_reject_duplicate_keys_and_nonstandard_json_numbers(self):
        malformed = (
            b'{"kind":"message","size":0,"size":1}',
            b'{"kind":"message","size":NaN}',
            b'{"kind":"message","size":Infinity}',
            b'{"kind":"message","size":-Infinity}',
        )
        for raw in malformed:
            with self.subTest(raw=raw):
                a, b = socket.socketpair()
                try:
                    a.sendall(struct.pack("!I", len(raw)) + raw)
                    with self.assertRaisesRegex(ValueError, "Invalid JSON frame"):
                        wt.recv_json_frame(b)
                finally:
                    a.close()
                    b.close()

    def test_json_frame_encoder_rejects_nan(self):
        a, b = socket.socketpair()
        try:
            with self.assertRaises(ValueError):
                wt.send_json_frame(a, {"number": float("nan")})
        finally:
            a.close()
            b.close()

    def test_reject_oversized_frame(self):
        a, b = socket.socketpair()
        try:
            a.sendall(struct.pack("!I", wt.MAX_HEADER_SIZE + 1))
            with self.assertRaisesRegex(ValueError, "Invalid JSON frame size"):
                wt.recv_json_frame(b)
        finally:
            a.close()
            b.close()

    def test_message_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                payload = "hello from test".encode("utf-8")
                pair.send_header({"kind": "message", "size": len(payload)})
                pair.client_sock.sendall(payload)
                self.assertEqual(pair.receive_frame(), {"status": "ok", "kind": "message"})
            finally:
                pair.close()
            self.assertEqual(pair.errors, [])

    def test_invalid_utf8_message_is_rejected_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                payload = b"valid-prefix\xff-invalid-utf8"
                pair.send_header({"kind": "message", "size": len(payload)})
                pair.client_sock.sendall(payload)
                response = pair.receive_frame()
                self.assertEqual(response.get("status"), "error")
                self.assertNotEqual(response, {"status": "ok", "kind": "message"})
            finally:
                pair.close()
            self.assertEqual(len(pair.errors), 1)
            self.assertIsInstance(pair.errors[0], UnicodeDecodeError)

    def test_message_payload_is_not_written_to_logs(self):
        secret = "private-text-that-must-not-appear-in-logs"
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                payload = secret.encode("utf-8")
                console = io.StringIO()
                with contextlib.redirect_stdout(console):
                    with self.assertLogs("wireless-transfer", level="INFO") as captured:
                        pair.send_header({"kind": "message", "size": len(payload)})
                        pair.client_sock.sendall(payload)
                        self.assertEqual(pair.receive_frame(), {"status": "ok", "kind": "message"})
                self.assertNotIn(secret, "\n".join(captured.output))
                self.assertTrue(any("Message received" in line for line in captured.output))
                self.assertIn(secret, console.getvalue())
            finally:
                pair.close()
            self.assertEqual(pair.errors, [])

    def test_unicode_message_is_ascii_escaped_for_legacy_consoles(self):
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                payload = "你好 — test".encode("utf-8")
                console = io.StringIO()
                with contextlib.redirect_stdout(console):
                    pair.send_header({"kind": "message", "size": len(payload)})
                    pair.client_sock.sendall(payload)
                    self.assertEqual(pair.receive_frame(), {"status": "ok", "kind": "message"})
                self.assertIn(r"\u4f60\u597d", console.getvalue())
                self.assertNotIn("你好", console.getvalue())
            finally:
                pair.close()
            self.assertEqual(pair.errors, [])

    def test_publish_cleanup_failure_is_still_reported_as_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            temp_path = output_dir / ".incoming-test.part"
            temp_path.write_bytes(b"verified")
            real_unlink = Path.unlink
            fail_once = {"value": True}

            def unlink_once(path, *args, **kwargs):
                if path == temp_path and fail_once["value"]:
                    fail_once["value"] = False
                    raise PermissionError("transient lock")
                return real_unlink(path, *args, **kwargs)

            with patch.object(Path, "unlink", unlink_once):
                published, temp_removed = wt._publish_without_overwrite(temp_path, output_dir, "sample.bin")
            self.assertEqual(published.read_bytes(), b"verified")
            self.assertFalse(temp_removed)
            self.assertTrue(temp_path.exists())
            # The caller's finally block can retry deletion; publication already succeeded.
            temp_path.unlink()
            self.assertFalse(temp_path.exists())

    def test_filename_truncation_respects_windows_and_posix_limits(self):
        safe = wt._safe_filename(("😀" * 240) + ".txt")
        self.assertTrue(safe.endswith(".txt"))
        self.assertLessEqual(len(safe.encode("utf-16-le")) // 2, wt.MAX_FILENAME_UTF16_UNITS)
        self.assertLessEqual(len(safe.encode("utf-8")), wt.MAX_FILENAME_UTF8_BYTES)
        self.assertEqual(wt._safe_filename("COM¹.txt"), "_COM¹.txt")
        self.assertEqual(wt._safe_filename("CLOCK$"), "_CLOCK$")
        self.assertEqual(wt._safe_filename("CON .txt"), "_CON .txt")
        self.assertEqual(wt._safe_filename("foo ."), "foo")
        # Truncation itself can make an internal space/dot become the final character.
        self.assertFalse(wt._safe_filename("a" * 239 + " tail").endswith((" ", ".")))
        self.assertFalse(wt._safe_filename("a" * 200 + "x" * 40 + " " + "y" * 20).endswith((" ", ".")))
        # JSON-escaped lone surrogates decode to Python strings that cannot be UTF-8
        # encoded. Sanitization must remain total for untrusted peer-provided names.
        self.assertEqual(wt._safe_filename("\ud800.txt"), "_.txt")
        self.assertEqual(wt._safe_filename("name\udfff.bin"), "name_.bin")

    def test_filename_limit_accounts_for_macos_unicode_decomposition(self):
        # macOS commonly normalizes filenames to NFD. A long precomposed name can
        # satisfy a literal UTF-8-byte cap yet exceed NAME_MAX after decomposition.
        raw = ("é" * 120) + ".txt"
        safe = wt._safe_filename(raw)
        self.assertTrue(safe.endswith(".txt"))
        self.assertLessEqual(len(safe.encode("utf-16-le")) // 2, wt.MAX_FILENAME_UTF16_UNITS)
        self.assertLessEqual(len(safe.encode("utf-8")), wt.MAX_FILENAME_UTF8_BYTES)
        self.assertLessEqual(len(unicodedata.normalize("NFD", safe).encode("utf-8")), wt.MAX_FILENAME_UTF8_BYTES)
        for index in (1, 10, 1000):
            candidate = wt._collision_candidate(safe, index)
            self.assertLessEqual(len(candidate.encode("utf-8")), wt.MAX_FILENAME_UTF8_BYTES)
            self.assertLessEqual(len(unicodedata.normalize("NFD", candidate).encode("utf-8")), wt.MAX_FILENAME_UTF8_BYTES)

    def test_missing_empty_and_non_string_filename_fields_are_rejected_before_ready(self):
        missing = object()
        malformed_values = (missing, None, 123, True, [], {}, "")
        for filename in malformed_values:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                pair = SocketPairHarness(tmp)
                try:
                    header = {
                        "kind": "file", "size": 0,
                        "sha256": hashlib.sha256(b"").hexdigest(),
                    }
                    if filename is not missing:
                        header["filename"] = filename
                    pair.send_header(header)
                    response = pair.receive_frame()
                    self.assertEqual(response["status"], "error")
                    self.assertIn("Filename must be a non-empty string", response["error"])
                finally:
                    pair.close()
                self.assertEqual(len(pair.errors), 1)
                self.assertFalse(list(Path(tmp).iterdir()))

    def test_json_escaped_lone_surrogate_filename_is_sanitized_and_received(self):
        content = b"safe payload"
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                # Use ensure_ascii=True to simulate a peer sending a JSON escape for
                # a lone UTF-16 surrogate, which Python json.loads decodes to a surrogate.
                frame = json.dumps({
                    "kind": "file", "filename": "\ud800.txt", "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
                pair.client_sock.sendall(struct.pack("!I", len(frame)) + frame)
                self.assertEqual(pair.receive_frame(), {"status": "ready", "size": len(content)})
                pair.client_sock.sendall(content)
                response = pair.receive_frame()
                self.assertEqual(response["status"], "ok")
                self.assertEqual(response["filename"], "_.txt")
            finally:
                pair.close()
            self.assertEqual((Path(tmp) / "_.txt").read_bytes(), content)
            self.assertEqual(pair.errors, [])

    def test_collision_suffix_stays_within_filename_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            name = wt._safe_filename(("😀" * 240) + ".bin")
            (output_dir / name).write_bytes(b"existing")
            temp_path = output_dir / ".incoming-test.part"
            temp_path.write_bytes(b"new content")
            published, temp_removed = wt._publish_without_overwrite(temp_path, output_dir, name)
            units = len(published.name.encode("utf-16-le")) // 2
            bytes_len = len(published.name.encode("utf-8"))
            self.assertLessEqual(units, wt.MAX_FILENAME_UTF16_UNITS)
            self.assertLessEqual(bytes_len, wt.MAX_FILENAME_UTF8_BYTES)
            self.assertNotEqual(published.name, name)
            self.assertTrue(temp_removed)
            self.assertEqual((output_dir / name).read_bytes(), b"existing")
            self.assertEqual(published.read_bytes(), b"new content")

    def test_filename_properties_for_mixed_unicode_and_collision_indexes(self):
        samples = [
            "😀" * 240 + ".dat",
            "汉字" * 180 + ".csv",
            "é" * 180 + ".txt",
            "a" * 400,
            "COM¹.txt",
            "CON." + ("a" * 236),
            r"C:\unsafe\name:with|bad?.rar",
            "...",
            "   ",
        ]
        for raw in samples:
            safe = wt._safe_filename(raw)
            self.assertTrue(safe)
            self.assertLessEqual(len(safe.encode("utf-16-le")) // 2, wt.MAX_FILENAME_UTF16_UNITS)
            self.assertLessEqual(len(safe.encode("utf-8")), wt.MAX_FILENAME_UTF8_BYTES)
            for index in (1, 9, 10, 1000):
                candidate = wt._collision_candidate(safe, index)
                self.assertNotEqual(candidate, safe)
                self.assertLessEqual(len(candidate.encode("utf-16-le")) // 2, wt.MAX_FILENAME_UTF16_UNITS)
                self.assertLessEqual(len(candidate.encode("utf-8")), wt.MAX_FILENAME_UTF8_BYTES)

    def test_hard_link_capability_failure_is_rejected_before_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                with patch("wireless_transfer.os.link", side_effect=OSError("Operation not permitted")):
                    pair.send_header({"kind": "file", "filename": "large.bin", "size": 101 * wt.MIB,
                                      "sha256": "0" * 64})
                    response = pair.receive_frame()
                self.assertEqual(response["status"], "error")
                self.assertIn("do not support the hard-link operation", response["error"])
            finally:
                pair.close()
            self.assertFalse((Path(tmp) / "large.bin").exists())
            self.assertEqual(list(Path(tmp).glob(".incoming-*.part")), [])
            self.assertEqual(list(Path(tmp).glob(".link-check-*")), [])

    def test_hard_link_publication_failure_has_actionable_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp_path = Path(tmp) / ".incoming-test.part"
            temp_path.write_bytes(b"verified")
            with patch("wireless_transfer.os.link", side_effect=OSError("Operation not permitted")):
                with self.assertRaisesRegex(OSError, "filesystem supports hard links"):
                    wt._publish_without_overwrite(temp_path, Path(tmp), "sample.bin")
            self.assertTrue(temp_path.exists())  # The caller owns temporary-file cleanup.

    def test_file_transfer_sanitizes_name_checks_hash_and_returns_ack(self):
        content = b"independent prototype test payload\n" * 2000
        expected_hash = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                pair.send_header({"kind": "file", "filename": r"..\subdir\sample.txt",
                                  "size": len(content), "sha256": expected_hash})
                self.assertEqual(pair.receive_frame(), {"status": "ready", "size": len(content)})
                for offset in range(0, len(content), 777):
                    pair.client_sock.sendall(content[offset:offset + 777])
                ack = pair.receive_frame()
                self.assertEqual(ack["status"], "ok")
                self.assertEqual(ack["filename"], "sample.txt")
                self.assertEqual(ack["size"], len(content))
                self.assertEqual(ack["sha256"], expected_hash)
            finally:
                pair.close()
            saved = Path(tmp) / "sample.txt"
            self.assertEqual(saved.read_bytes(), content)
            self.assertEqual(pair.errors, [])
            self.assertEqual(list(Path(tmp).glob("*.part")), [])

    def test_existing_file_is_not_overwritten(self):
        content = b"new content"
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "same.txt").write_bytes(b"keep me")
            pair = SocketPairHarness(tmp)
            try:
                pair.send_header({"kind": "file", "filename": "same.txt",
                                  "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
                self.assertEqual(pair.receive_frame()["status"], "ready")
                pair.client_sock.sendall(content)
                ack = pair.receive_frame()
                self.assertEqual(ack["filename"], "same_1.txt")
            finally:
                pair.close()
            self.assertEqual((Path(tmp) / "same.txt").read_bytes(), b"keep me")
            self.assertEqual((Path(tmp) / "same_1.txt").read_bytes(), content)

    def test_files_larger_than_100_mib_are_permitted_by_default_limit(self):
        self.assertGreater(wt.DEFAULT_MAX_FILE_SIZE, 100 * wt.MIB)
        self.assertEqual(wt.DEFAULT_MAX_FILE_SIZE, 8192 * wt.MIB)
        # Confirm the receiver's preflight accepts a size above 100 MiB without
        # transferring a 100 MiB test payload on every ordinary test run.
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                declared_size = 101 * wt.MIB
                pair.send_header({"kind": "file", "filename": "large.bin",
                                  "size": declared_size, "sha256": "0" * 64})
                self.assertEqual(pair.receive_frame(), {"status": "ready", "size": declared_size})
                pair.client_sock.shutdown(socket.SHUT_WR)
            finally:
                pair.close()
            self.assertTrue(any("closed during file transfer" in str(e) for e in pair.errors))
            self.assertFalse((Path(tmp) / "large.bin").exists())
            self.assertEqual(list(Path(tmp).glob("*.part")), [])

    def test_insufficient_receiver_disk_space_is_rejected_before_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                with patch("wireless_transfer.shutil.disk_usage", return_value=SimpleNamespace(free=10)):
                    pair.send_header({"kind": "file", "filename": "too-large-for-volume.bin", "size": 1,
                                      "sha256": hashlib.sha256(b"x").hexdigest()})
                    response = pair.receive_frame()
                self.assertEqual(response["status"], "error")
                self.assertIn("Insufficient free space", response["error"])
            finally:
                pair.close()
            self.assertFalse((Path(tmp) / "too-large-for-volume.bin").exists())
            self.assertEqual(list(Path(tmp).glob(".incoming-*.part")), [])

    def test_file_over_configured_limit_is_rejected_before_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp, max_file_size=10)
            try:
                pair.send_header({"kind": "file", "filename": "too-big.bin", "size": 11,
                                  "sha256": "0" * 64})
                response = pair.receive_frame()
                self.assertEqual(response["status"], "error")
                self.assertIn("receiver limit", response["error"])
            finally:
                pair.close()
            self.assertFalse((Path(tmp) / "too-big.bin").exists())

    def test_hash_mismatch_does_not_publish_partial_file(self):
        content = b"wrong digest"
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                pair.send_header({"kind": "file", "filename": "bad.bin", "size": len(content),
                                  "sha256": "0" * 64})
                self.assertEqual(pair.receive_frame()["status"], "ready")
                pair.client_sock.sendall(content)
                response = pair.receive_frame()
                self.assertEqual(response["status"], "error")
                self.assertIn("SHA-256 mismatch", response["error"])
            finally:
                pair.close()
            self.assertFalse((Path(tmp) / "bad.bin").exists())
            self.assertEqual(list(Path(tmp).glob("*.part")), [])

    def test_truncated_file_is_not_published_and_temp_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                pair.send_header({"kind": "file", "filename": "truncated.bin", "size": 100,
                                  "sha256": hashlib.sha256(b"x" * 100).hexdigest()})
                self.assertEqual(pair.receive_frame()["status"], "ready")
                pair.client_sock.sendall(b"short")
                pair.client_sock.shutdown(socket.SHUT_WR)
            finally:
                pair.close()
            self.assertFalse((Path(tmp) / "truncated.bin").exists())
            self.assertEqual(list(Path(tmp).glob("*.part")), [])
            self.assertTrue(any("closed during file transfer" in str(e) for e in pair.errors))

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            pair = SocketPairHarness(tmp)
            try:
                pair.send_header({"kind": "file", "filename": "empty.bin", "size": 0,
                                  "sha256": hashlib.sha256(b"").hexdigest()})
                self.assertEqual(pair.receive_frame(), {"status": "ready", "size": 0})
                ack = pair.receive_frame()
                self.assertEqual(ack["status"], "ok")
                self.assertEqual((Path(tmp) / "empty.bin").read_bytes(), b"")
            finally:
                pair.close()
            self.assertEqual(pair.errors, [])

    def test_sender_rejects_message_ack_without_message_kind(self):
        def handler(conn):
            request = wt.recv_json_frame(conn)
            wt.recv_exact(conn, request["size"])
            wt.send_json_frame(conn, {"status": "ok"})

        server = FakeTcpReceiverHarness(handler)
        args = SimpleNamespace(host=server.host, port=server.port, message="hello", file=None,
                               max_file_size_mib=8192, idle_timeout=5)
        try:
            with self.assertRaisesRegex(wt.TransferError, "did not confirm a message"):
                wt.send(args)
        finally:
            server.close()
        self.assertEqual(server.errors, [])

    def test_sender_rejects_boolean_size_in_ready_ack(self):
        def handler(conn):
            wt.recv_json_frame(conn)
            wt.send_json_frame(conn, {"status": "ready", "size": True})

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "one-byte.bin"
            source.write_bytes(b"x")
            server = FakeTcpReceiverHarness(handler)
            args = SimpleNamespace(host=server.host, port=server.port, message=None, file=str(source),
                                   max_file_size_mib=8192, idle_timeout=5)
            try:
                with self.assertRaisesRegex(wt.TransferError, "expected integer size"):
                    wt.send(args)
            finally:
                server.close()
            self.assertEqual(server.errors, [])

    def test_sender_rejects_boolean_size_in_final_ack(self):
        def handler(conn):
            request = wt.recv_json_frame(conn)
            wt.send_json_frame(conn, {"status": "ready", "size": request["size"]})
            wt.recv_exact(conn, request["size"])
            wt.send_json_frame(conn, {"status": "ok", "filename": "one-byte.bin",
                                      "size": True, "sha256": request["sha256"]})

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "one-byte.bin"
            source.write_bytes(b"x")
            server = FakeTcpReceiverHarness(handler)
            args = SimpleNamespace(host=server.host, port=server.port, message=None, file=str(source),
                                   max_file_size_mib=8192, idle_timeout=5)
            try:
                with self.assertRaisesRegex(wt.TransferError, "expected integer size"):
                    wt.send(args)
            finally:
                server.close()
            self.assertEqual(server.errors, [])

    def test_dynamic_console_log_values_are_ascii_safe(self):
        value = "路径/файл/😀\x1b[2J"
        rendered = wt._console_safe(value)
        self.assertTrue(rendered.isascii())
        self.assertNotIn("\x1b", rendered)
        self.assertIn(r"\u8def", rendered)
        self.assertIn(r"\U0001f600", rendered)

    def test_remote_error_control_characters_are_escaped(self):
        with self.assertRaises(wt.TransferError) as caught:
            wt._check_ack({"status": "error", "error": "bad\x1b[2Jterminal"}, "ok")
        self.assertNotIn("\x1b", str(caught.exception))
        self.assertIn(r"\x1b", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
