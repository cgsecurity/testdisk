#!/usr/bin/env python3
"""Synthetic raw-image integration tests; requires Python 3 and Pillow.

Build PhotoRec first, then run: python3 tests/test_image_filters.py
PHOTOREC_BINARY may select another built executable. All input/output lives in
a temporary directory; no real disks or user files are accessed.
"""

import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from PIL import Image


REPO = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("PHOTOREC_BINARY", REPO / "src/photorec")).resolve()


def picture(kind, width=32, height=24, progressive=False, late=False):
    stream = io.BytesIO()
    Image.new("RGB", (width, height), (23, 147, 211)).save(
        stream, format=kind, progressive=progressive
    )
    data = stream.getvalue()
    if late:
        # Preserve JFIF, then put SOF beyond the 64 KiB header buffer. False
        # SOF/EOI bytes inside an APP segment must not describe the parent.
        first_end = 4 + int.from_bytes(data[4:6], "big")
        payload = (b"opaque metadata\xff\xd9\xff\xc0" * 3000)[:60000]
        app = b"\xff\xe2" + (len(payload) + 2).to_bytes(2, "big") + payload
        data = data[:first_end] + app * 2 + data[first_end:]
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ImageFilters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="photorec-image-tests-")
        cls.root = Path(cls.temporary.name)
        cls.counter = 0
        cls.hook = None
        if sys.platform.startswith("linux"):
            # Observe actual fopen calls, including files deleted before exit.
            # The hook records only recovery outputs, never input or log files.
            source = cls.root / "observe_open.c"
            source.write_text(r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static void observe(const char *path, const char *mode)
{
  const char *prefix=getenv("PHOTOREC_TEST_OUTPUT_PREFIX");
  const char *log=getenv("PHOTOREC_TEST_OPEN_LOG");
  if(prefix && log && mode[0]=='w' && strncmp(path, prefix, strlen(prefix))==0
      && strstr(path, "report.xml")==NULL)
  {
    int fd=open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if(fd>=0)
    {
      if(write(fd, path, strlen(path))<0) abort();
      if(write(fd, "\n", 1)<0) abort();
      close(fd);
    }
  }
}
FILE *fopen(const char *path, const char *mode)
{
  FILE *(*original)(const char *, const char *)=dlsym(RTLD_NEXT, "fopen");
  observe(path, mode);
  return original(path, mode);
}
FILE *fopen64(const char *path, const char *mode)
{
  FILE *(*original)(const char *, const char *)=dlsym(RTLD_NEXT, "fopen64");
  observe(path, mode);
  return original(path, mode);
}
''')
            cls.hook = cls.root / "observe_open.so"
            subprocess.run(
                [os.environ.get("CC", "cc"), "-Wall", "-Wextra", "-shared",
                 "-fPIC", str(source), "-ldl", "-o", str(cls.hook)],
                check=True,
            )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def recover(self, images, options="", binary=BINARY, formats="jpg,png", log=True):
        type(self).counter += 1
        directory = self.root / str(self.counter)
        directory.mkdir()
        raw = bytearray(4096)
        for data in images:
            raw.extend(data)
            raw.extend(bytes((-len(raw)) % 4096 + 4096))
        raw.extend(bytes(2 * 1024 * 1024))
        disk = directory / "disk.img"
        disk.write_bytes(raw)
        output = directory / "out"
        opened_log = directory / "opened.txt"
        env = os.environ.copy()
        if self.hook:
            env.update(LD_PRELOAD=str(self.hook),
                       PHOTOREC_TEST_OUTPUT_PREFIX=str(output),
                       PHOTOREC_TEST_OPEN_LOG=str(opened_log))
        command = "fileopt,everything,disable,"
        command += ",".join(f"{kind},enable" for kind in formats.split(","))
        if options:
            command += ",options," + options
        command += ",search"
        args = [str(binary)] + (["/log"] if log else [])
        process = subprocess.run(
            args + ["/d", str(output), "/cmd", str(disk), command],
            cwd=directory, env=env, capture_output=True, timeout=30,
        )
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace"))
        recovered = sorted(digest(path.read_bytes()) for path in directory.glob("out.*/*")
                           if path.suffix != ".xml")
        opened = opened_log.read_text().splitlines() if opened_log.exists() else []
        return recovered, opened, process

    def test_default_and_explicit_zero(self):
        images = [picture("JPEG"), picture("PNG"), picture("JPEG", progressive=True),
                  picture("JPEG", late=True)]
        expected = sorted(map(digest, images))
        self.assertEqual(self.recover(images)[0], expected)
        self.assertEqual(self.recover(images, "image_min_width,0,image_min_height,0,"
                                      "image_min_pixels,0,image_min_bytes,0")[0], expected)

    @unittest.skipUnless(os.environ.get("PHOTOREC_BASELINE"),
                         "set PHOTOREC_BASELINE to compare an untouched upstream build")
    def test_defaults_match_upstream(self):
        images = [picture("JPEG"), picture("PNG"), picture("JPEG", progressive=True),
                  picture("JPEG", late=True), picture("BMP")]
        baseline = Path(os.environ["PHOTOREC_BASELINE"]).resolve()
        self.assertEqual(self.recover(images, formats="jpg,png,bmp")[0],
                         self.recover(images, binary=baseline, formats="jpg,png,bmp")[0])

    def test_independent_dimension_boundaries(self):
        for kind in ("JPEG", "PNG"):
            data = picture(kind)
            for name, value in (("width", 32), ("height", 24), ("pixels", 768)):
                with self.subTest(kind=kind, minimum=name):
                    option = f"image_min_{name}"
                    accepted, opened, _ = self.recover([data], f"{option},{value}")
                    self.assertEqual(accepted, [digest(data)])
                    if self.hook:
                        self.assertTrue(opened, "positive control must observe output fopen")
                    rejected, opened, _ = self.recover([data], f"{option},{value + 1}")
                    self.assertEqual(rejected, [])
                    if self.hook:
                        self.assertEqual(opened, [], "rejection must occur before fopen")

    def test_byte_boundaries(self):
        for kind, progressive in (("JPEG", False), ("JPEG", True), ("PNG", False)):
            data = picture(kind, progressive=progressive)
            with self.subTest(kind=kind, progressive=progressive):
                self.assertEqual(self.recover([data], f"image_min_bytes,{len(data)}")[0],
                                 [digest(data)])
                rejected, opened, _ = self.recover([data], f"image_min_bytes,{len(data)+1}")
                self.assertEqual(rejected, [])
                if self.hook:
                    self.assertEqual(opened, [])

    def test_late_jpeg_dimensions_and_bytes(self):
        data = picture("JPEG", width=96, height=80, late=True)
        self.assertGreater(len(data), 65536)
        self.assertEqual(self.recover([data], "image_min_width,96,image_min_height,80,"
                                      f"image_min_pixels,7680,image_min_bytes,{len(data)}")[0],
                         [digest(data)])
        for option in ("image_min_width,97", f"image_min_bytes,{len(data)+1}"):
            rejected, opened, _ = self.recover([data], option)
            self.assertEqual(rejected, [])
            if self.hook:
                self.assertEqual(opened, [])

    def test_progressive_dimensions(self):
        data = picture("JPEG", width=80, height=96, progressive=True)
        self.assertEqual(self.recover([data], "image_min_width,80,image_min_height,96")[0],
                         [digest(data)])
        self.assertEqual(self.recover([data], "image_min_height,97")[0], [])

    def test_rejected_image_followed_by_valid_and_nonimage(self):
        small = picture("PNG")
        large = picture("JPEG", width=96, height=80, late=True)
        bmp = picture("BMP", width=16, height=16)
        recovered, opened, _ = self.recover(
            [small, large, bmp], "image_min_width,90", formats="jpg,png,bmp")
        self.assertEqual(recovered, sorted(map(digest, [large, bmp])))
        if self.hook:
            self.assertFalse(any(name.endswith(".png") for name in opened))

    def test_maximum_unsigned_minima(self):
        for name in ("width", "height", "pixels", "bytes"):
            with self.subTest(minimum=name):
                rejected, opened, _ = self.recover(
                    [picture("JPEG"), picture("PNG")],
                    f"image_min_{name},18446744073709551615")
                self.assertEqual(rejected, [])
                if self.hook:
                    self.assertEqual(opened, [])

    def test_invalid_values_do_not_start_recovery(self):
        for value in ("-1", "+1", "18446744073709551616", "", "1k", "1.5"):
            with self.subTest(value=value):
                recovered, opened, process = self.recover(
                    [picture("JPEG")], f"image_min_width,{value}", log=False)
                self.assertEqual(recovered, [])
                self.assertEqual(opened, [])
                self.assertIn(b"Invalid image minimum", process.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
