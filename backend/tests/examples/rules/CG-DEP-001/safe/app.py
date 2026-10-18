# Example only: scanned by the tests, never run.  CG-DEP-001 (safe)
import os
import tempfile


def scratch_file():
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("data")
    return path
