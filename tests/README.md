# Image minimum regression checks

These tests use generated images and temporary output directories. They do not
read physical disks, write source images, or require administrator privileges.

## Build

Follow the normal build instructions in `INSTALL`. A C compiler, Autotools,
ncurses headers and libjpeg headers were used for these checks. From a Git
checkout, generate the build system and compile before running the tests:

```sh
autoreconf --install -W all -I config
./configure
make -j4
```

If `autopoint` refuses to replace the repository's `config/config.rpath`, use
`AUTOPOINT=true autoreconf --install -W all -I config` to retain the existing
gettext files. No installation into system directories is needed.

## Run

```sh
sh tests/run_image_options.sh
python3 tests/test_image_filter_parser.py
python3 tests/test_image_options_cli.py ./src/photorec
python3 tests/test_image_options_ui.py ./src/photorec
python3 tests/test_image_filters.py
```

- The C options test checks strict unsigned parsing, CLI errors, all four limits,
  and the actual session save/load round trip. It uses the configured source
  files, with only logging functions stubbed.
- The parser test compiles the format probes into a temporary shared library and
  checks malformed metadata, marker/segment boundaries, progressive JPEG, DNL,
  MPF, PNG CRCs, large dimensions and incomplete input. It needs Python 3 and a
  C compiler with shared-library support.
- The CLI test checks all four options against invalid and missing values on an
  actual PhotoRec process. PhotoRec's native syntax-error exit status can be zero;
  the test asserts the diagnostic and that recovery did not begin.
- The menu test needs a POSIX pseudo-terminal and a curses-enabled build. It sets
  all four values, exercises invalid input and verifies values survive reopening
  the Options screen. It never starts recovery.
- The recovery test needs Python 3 and Pillow. It generates ordinary and
  progressive JPEGs, PNGs, a JPEG whose SOF is beyond 64 KiB of APP metadata, and
  an unaffected BMP. It tests equality and rejection for each minimum, mixed-file
  scanning, defaults, maximum unsigned inputs and malformed commands. On Linux,
  an `LD_PRELOAD` observer proves simple rejected images never call output
  `fopen`, including files that would otherwise have been deleted before exit.
  Output-open observation is omitted on other systems; file-content checks run.

`PHOTOREC_BINARY` can select the integration test's binary. To additionally
compare default recovered content with an untouched upstream build, run:

```sh
PHOTOREC_BASELINE=/absolute/path/to/upstream/photorec python3 tests/test_image_filters.py
```

All four zero values preserve normal recovery. A positive dimension limit rejects
only known below-minimum dimensions: unknown metadata retains normal recovery.
The format probe uses a 4 KiB cache, at most 16 MiB of reads, and at most 65536
markers/chunks. It skips APP/EXIF payloads rather than interpreting embedded
thumbnail dimensions. Preflight stays within the current source extent, caps
ext2 metadata before possible indirect blocks, and defers brute-force recovery
to the reconstructed stream. Incomplete metadata, damage or fragmentation may
require output writes before a final rejection. The byte limit is checked against
the final native recovery size, even when dimension metadata remains unknown.

The format table in `src/image_filter.c` is the extension point for additional
image formats; the option/session and recovery adapters do not need to change.
