#!/usr/bin/env python3
"""Verify malformed batch limits are diagnosed without starting recovery."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve()
results = []
with tempfile.TemporaryDirectory(prefix="photorec-invalid-image-options-") as temporary:
    directory = Path(temporary)
    image = directory / "synthetic.dd"
    image.write_bytes(bytes(1024 * 1024))
    for name in ("image_min_width", "image_min_height", "image_min_pixels", "image_min_bytes"):
        for bad in ("-1", "18446744073709551616", "", "search"):
            case = directory / str(len(results))
            case.mkdir()
            destination = case / "recovered"
            command = f"partition_none,options,{name},{bad},search"
            process = subprocess.run(
                [str(binary), "/log", "/d", str(destination), "/cmd", str(image), command],
                cwd=case, capture_output=True, text=True, timeout=10,
            )
            # /log redirects file descriptor 2 into photorec.log.
            assert "PhotoRec syntax error" in process.stdout, process
            assert not destination.exists(), list(case.iterdir())
            assert not any(case.glob("recovered*")), list(case.iterdir())
            log = (case / "photorec.log").read_text(errors="replace")
            assert "Invalid image minimum" in log
            assert "Pass 1" not in log
            results.append({"option": name, "invalid_value": bad,
                            "diagnostic": True, "output_directory_created": False,
                            "process_exit_status": process.returncode})
report = {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
          "cases_passed": len(results), "cases": results,
          "exit_status_note": "Native PhotoRec may return zero for CLI syntax errors; these checks assert diagnostic and no recovery output, not a nonzero exit."}
if len(sys.argv) > 2:
    Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
