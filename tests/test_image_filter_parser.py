#!/usr/bin/env python3
"""Exercise the image probes using only synthetic metadata and a temporary build.

Run from any directory after configuring the project. No source images, devices,
network access, installed PhotoRec, or persistent build outputs are used.
"""

import ctypes
import json
import os
import random
import shlex
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Limits(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64)
                for name in ['width', 'height', 'pixels', 'bytes']]


Read = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint64,
                       ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint)


def build_library(directory):
    library = Path(directory) / 'libimage_filter.so'
    command = shlex.split(os.environ.get('CC', 'cc')) + [
        '-O2', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
        '-DHAVE_CONFIG_H', '-I', str(ROOT), '-I', str(ROOT / 'src'),
        str(ROOT / 'src/image_filter.c'), '-o', str(library),
    ]
    subprocess.run(command, check=True)
    lib = ctypes.CDLL(str(library))
    lib.image_filter_probe.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(Limits), Read,
        ctypes.c_void_p, ctypes.c_uint64,
    ]
    lib.image_filter_probe.restype = ctypes.c_int
    return lib


def probe(lib, ext, blob, limits, available=None, fail=False):
    calls = []
    invalid_reads = []
    @Read
    def read(_opaque, offset, target, count):
        if offset > len(blob) or count > len(blob) - offset:
            invalid_reads.append((offset, count))
            return 0
        calls.append((offset, count))
        if fail:
            return 0
        ctypes.memmove(target, blob[offset:offset + count], count)
        return 1
    result = lib.image_filter_probe(ext.encode(), ctypes.byref(Limits(*limits)),
                                   read, None, len(blob) if available is None else available)
    assert not invalid_reads, invalid_reads
    return result, calls


def segment(marker, body):
    return bytes([255, marker]) + struct.pack('>H', len(body) + 2) + body


def sof(width=100, height=80, marker=0xc0):
    return segment(marker, bytes([8]) + struct.pack('>HH', height, width) + bytes([1, 1, 0x11, 0]))


sos = segment(0xda, bytes([1, 1, 0, 0, 63, 0]))

def jpg(width=100, height=80, marker=0xc0, prefix=b'', entropy=b'123456', extra=b''):
    return b'\xff\xd8' + prefix + sof(width, height, marker) + sos + entropy + extra + b'\xff\xd9'


def chunk(name, data):
    return struct.pack('>I', len(data)) + name + data + struct.pack('>I', zlib.crc32(name + data))


def png(width=100, height=80, ancillary=b''):
    ihdr = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr) + ancillary + chunk(b'IDAT', zlib.compress(b'\x00abc')) + chunk(b'IEND', b'')



def run_cases(lib):
    cases = []
    def case(name, ext, blob, limits, expected, **kwargs):
        actual, calls = probe(lib, ext, blob, limits, **kwargs)
        cases.append({'name': name, 'expected': expected, 'actual': actual, 'read_calls': len(calls)})
        assert actual == expected, (name, actual, expected)

    for ext, blob in [('jpg', jpg()), ('png', png())]:
        case(ext + '_exact_dimensions', ext, blob, (100, 80, 8000, 0), 1)
        case(ext + '_width_below', ext, blob, (101, 0, 0, 0), -1)
        case(ext + '_height_below', ext, blob, (0, 81, 0, 0), -1)
        case(ext + '_pixels_below', ext, blob, (0, 0, 8001, 0), -1)
        case(ext + '_exact_bytes', ext, blob, (0, 0, 0, len(blob)), 1)
        case(ext + '_below_bytes', ext, blob, (0, 0, 0, len(blob) + 1), -1)
        case(ext + '_short_read_unknown', ext, blob, (1, 1, 1, 10000), 0, fail=True)
        case(ext + '_truncated_metadata_unknown', ext, blob[:10], (1000, 1000, 0, 0), 0)

    for marker in [0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]:
        case('jpeg_sof_' + hex(marker), 'jpg', jpg(marker=marker), (100, 80, 8000, 0), 1)

    thumb = jpg(width=1, height=1)
    case('jpeg_embedded_thumbnail_ignored', 'jpg', jpg(prefix=segment(0xe1, thumb)), (50, 50, 0, 0), 1)
    case('jpeg_long_exif_skipped', 'jpg', jpg(prefix=segment(0xe1, b'x' * 65533) * 4), (100, 80, 0, 0), 1)
    case('jpeg_app_eoi_ignored', 'jpg', jpg(prefix=segment(0xe1, b'\xff\xd9')), (0, 0, 0, len(jpg(prefix=segment(0xe1, b'\xff\xd9')))), 1)
    stuffed = jpg(entropy=b'one\xff\x00\xd9two\xff\xd0three')
    case('jpeg_stuffed_eoi_restart_ignored', 'jpg', stuffed, (0, 0, 0, len(stuffed)), 1)
    dnl = jpg(height=0, extra=segment(0xdc, struct.pack('>H', 80)))
    case('jpeg_dnl_height', 'jpg', dnl, (100, 80, 8000, 0), 1)
    case('jpeg_dnl_small', 'jpg', dnl, (100, 81, 0, 0), -1)
    case('jpeg_zero_height_unknown', 'jpg', jpg(height=0), (0, 1000, 0, 0), 0)
    mpo = jpg(prefix=segment(0xe2, b'MPF\x00' + b'not-a-full-mpf-index'))
    case('jpeg_mpo_first_eoi_not_total', 'jpg', mpo, (0, 0, 0, len(mpo) + 1), 0)
    case('jpeg_incomplete_segment_unknown', 'jpg', b'\xff\xd8\xff\xe1\xff\xffabc', (0, 0, 0, 1000), 0)

    fake_end = chunk(b'IEND', b'')
    with_text = png(ancillary=chunk(b'tEXt', b'Key\x00' + fake_end))
    case('png_embedded_iend_ignored', 'png', with_text, (0, 0, 0, len(with_text)), 1)
    bad_ihdr = bytearray(png(width=1, height=1))
    bad_ihdr[29] ^= 1
    case('png_bad_ihdr_crc_unknown', 'png', bytes(bad_ihdr), (100, 100, 0, 0), 0)
    bad_iend = bytearray(png())
    bad_iend[-1] ^= 1
    case('png_bad_iend_crc_unknown', 'png', bytes(bad_iend), (0, 0, 0, len(bad_iend) + 1), 0)
    case('png_huge_truncated_chunk_unknown', 'png', png()[:33] + struct.pack('>I', 0x7fffffff) + b'tEXt', (0, 0, 0, 2**64 - 1), 0)
    case('png_uint32_product_safe', 'png', png(width=0xffffffff, height=0xffffffff), (0, 0, (0xffffffff**2), 0), 1)
    case('png_uint64_threshold_reject', 'png', png(width=0xffffffff, height=0xffffffff), (0, 0, 2**64 - 1, 0), -1)
    case('unsupported_jng_unchanged', 'jng', png(width=1, height=1), (100, 100, 0, 0), 0)

    rng = random.Random(167)
    for _ in range(1000):
        blob = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 1024)))
        ext = rng.choice(['jpg', 'png'])
        actual, _calls = probe(lib, ext, blob, (100, 100, 10000, 100000))
        assert actual in [-1, 0, 1]


    # Valid metadata followed by a long entropy stream must exhaust the read
    # budget without turning incomplete size information into a rejection.
    budget = 16 * 1024 * 1024
    long_scan = jpg(entropy=b'x' * (budget + 8192))
    actual, calls = probe(lib, 'jpg', long_scan, (0, 0, 0, len(long_scan) + 1))
    assert actual == 0, ('jpeg_read_budget_unknown', actual)
    assert sum(count for _offset, count in calls) == budget
    cases.append({'name': 'jpeg_read_budget_unknown', 'actual': actual,
                  'expected': 0, 'read_calls': len(calls)})
    return {'passed_cases': len(cases), 'random_short_inputs': 1000,
            'note': 'Metadata probe fixtures; full image recovery is tested separately.'}


def main():
    with tempfile.TemporaryDirectory(prefix='photorec-parser-') as directory:
        report = run_cases(build_library(directory))
    print(json.dumps(report))


if __name__ == '__main__':
    main()
