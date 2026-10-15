# SPDX-License-Identifier: Apache-2.0
"""Opt-in large end-to-end TCP smoke test. Defaults to 101 MiB; TRANSFER_TEST_MIB can raise it.

Run with RUN_LARGE_TRANSFER_TEST=1 python -m unittest tests.test_large_transfer -v
"""
import contextlib
import hashlib
import io
import json
import re
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wireless_transfer as wt


@unittest.skipUnless(os.environ.get("RUN_LARGE_TRANSFER_TEST") == "1",
                     "set RUN_LARGE_TRANSFER_TEST=1 to move a real TCP payload (101 MiB by default)")
class LargeTransferSmokeTest(unittest.TestCase):
    def test_large_file_over_tcp_is_received_and_verified(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            test_mib = int(os.environ.get("TRANSFER_TEST_MIB", "101"))
            if test_mib < 101:
                raise ValueError("TRANSFER_TEST_MIB must be at least 101")
            source = root_path / f"sparse-{test_mib}MiB.bin"
            destination_dir = root_path / "received"
            expected_size = test_mib * wt.MIB
            # Keep the file mostly sparse for a fast large-scale test, but place
            # unique nonzero markers at regular offsets. An all-zero sparse file
            # would be unable to reveal chunk reordering that preserves zero bytes.
            marker_stride = 1024 * 1024
            marker_offsets = list(range(0, expected_size, marker_stride))
            marker_offsets.extend([max(0, expected_size - 64), expected_size // 2])
            marker_offsets = sorted(set(offset for offset in marker_offsets if offset + 64 <= expected_size))
            markers = {}
            with source.open("wb") as stream:
                stream.truncate(expected_size)
                for offset in marker_offsets:
                    marker = hashlib.sha256(f"offset:{offset}".encode("ascii")).digest() * 2
                    markers[offset] = marker
                    stream.seek(offset)
                    stream.write(marker)

            errors = []
            ready = threading.Event()
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            host, port = listener.getsockname()

            def receiver():
                ready.set()
                try:
                    conn, _ = listener.accept()
                    with conn:
                        wt.handle_client(conn, destination_dir, max_file_size=8 * wt.MIB * 1024,
                                         idle_timeout=60)
                except Exception as exc:
                    errors.append(exc)
                finally:
                    listener.close()

            thread = threading.Thread(target=receiver, daemon=True)
            thread.start()
            self.assertTrue(ready.wait(2))
            args = SimpleNamespace(host=host, port=port, message=None, file=str(source),
                                   max_file_size_mib=8192, idle_timeout=60)
            sender_output = io.StringIO()
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(sender_output):
                wt.send(args)
            # wt.send() independently hashes the source before streaming and validates
            # that the receiver's post-write SHA-256 acknowledgement exactly matches it.
            # Re-hashing both 6 GiB files again here needlessly adds 12 GiB of disk I/O.
            response_lines = [line for line in sender_output.getvalue().splitlines() if line.strip()]
            self.assertTrue(response_lines, "sender did not print its verified acknowledgement")
            response = json.loads(response_lines[-1])
            self.assertEqual(response.get("size"), expected_size)
            self.assertEqual(response.get("filename"), source.name)
            self.assertRegex(response.get("sha256", ""), re.compile(r"^[0-9a-f]{64}$"))
            thread.join(timeout=max(120, test_mib / 10 + 60))
            self.assertFalse(thread.is_alive(), f"TCP receiver did not finish within {max(120, test_mib / 10 + 60):g} seconds")
            self.assertEqual(errors, [])
            received = destination_dir / source.name
            self.assertTrue(received.is_file())
            self.assertEqual(received.stat().st_size, expected_size)
            # Sample nonzero markers throughout the sparse file to catch gross
            # write-offset/reordering errors without rereading/checksumming 6 GiB.
            with received.open("rb") as stream:
                for offset in (0, expected_size // 2, max(0, expected_size - 64)):
                    stream.seek(offset)
                    self.assertEqual(stream.read(64), markers[offset], f"marker mismatch at offset {offset}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
