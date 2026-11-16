#!/usr/bin/env python3
"""Exercise the real ncurses options on a synthetic image, using only stdlib.

Usage: python3 tests/test_image_options_ui.py ./src/photorec [evidence-directory]
Does not start recovery or access physical devices. Requires a POSIX PTY.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time

binary = Path(sys.argv[1]).resolve()
evidence = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
transcript = bytearray()
checks = []
with tempfile.TemporaryDirectory(prefix="photorec-image-options-ui-") as temporary:
    directory = Path(temporary)
    image = directory / "synthetic.dd"
    image.write_bytes(bytes(4 * 1024 * 1024))
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 110, 0, 0))
    process = subprocess.Popen(
        [str(binary), "/log", "/cmd", str(image), "partition_none,options,inter"],
        cwd=directory, stdin=slave, stdout=slave, stderr=slave,
        env=dict(os.environ, TERM="xterm"),
    )
    os.close(slave)
    cursor = 0

    def expect(text):
        global cursor
        target = text.encode()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            position = transcript.find(target, cursor)
            if position >= 0:
                result = bytes(transcript[cursor:position + len(target)])
                cursor = position + len(target)
                return result
            if select.select([master], [], [], max(0, deadline-time.monotonic()))[0]:
                try:
                    transcript.extend(os.read(master, 65536))
                except OSError:
                    break
        raise AssertionError(f"Did not observe {text!r}: {bytes(transcript[-2000:])!r}")

    def send(text):
        os.write(master, text.encode())

    def menu():
        return expect("Return to main menu")

    def set_value(key, value, expected):
        send(key)
        expect("Value: ")
        send(value + "\n")
        screen = menu()
        assert expected.encode() in screen, screen
        checks.append(expected)

    try:
        expect("Start file recovery")
        send("o")
        screen = menu()
        for field in ("width", "height", "pixels", "bytes"):
            assert f"Image minimum {field} : 0".encode() in screen
        checks.append("all four defaults are zero")
        set_value("w", "640", "Image minimum width : 640")
        set_value("h", "480", "Image minimum height : 480")
        set_value("i", "307200", "Image minimum pixels : 307200")
        set_value("b", "10240", "Image minimum bytes : 10240")
        set_value("w", "18446744073709551615", "Image minimum width : 18446744073709551615")
        set_value("w", "640", "Image minimum width : 640")
        for invalid in ("-1", "+2", "18446744073709551616", "99999999999999999999999", "5kb"):
            send("w")
            expect("Value: ")
            send(invalid + "\n")
            expect("Invalid image minimum. The previous value has been kept.")
            send("\n")
            assert b"Image minimum width : 640" in menu()
            checks.append("invalid input preserves width: " + invalid)
        set_value("w", "", "Image minimum width : 640")
        set_value("b", "0", "Image minimum bytes : 0")
        send("q")
        expect("Modify options")
        send("o")
        screen = menu()
        for field, value in (("width", 640), ("height", 480), ("pixels", 307200), ("bytes", 0)):
            assert f"Image minimum {field} : {value}".encode() in screen
        checks.append("all settings preserved after leaving and reopening menu")
        send("q")
        expect("Modify options")
    finally:
        # PhotoRec installs signal handlers, so SIGTERM need not end its UI loop.
        # Terminate only this test's subprocess; no recovery was started.
        process.kill()
        process.wait(timeout=5)
        os.close(master)
        if evidence:
            evidence.mkdir(parents=True, exist_ok=True)
            (evidence / "options-ui-transcript.log").write_bytes(transcript)
            if (directory / "photorec.log").exists():
                (evidence / "options-ui-photorec.log").write_bytes((directory / "photorec.log").read_bytes())
result = {"binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
          "passed": len(checks), "checks": checks, "recovery_started": False,
          "limitations": "Tests actual ncurses input; session serialization covered separately by the C round-trip test."}
if evidence:
    (evidence / "options-ui-result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
