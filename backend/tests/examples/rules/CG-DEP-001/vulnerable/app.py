# Example only: scanned by the tests, never run.  CG-DEP-001 (vulnerable)
import tempfile


def scratch_file():
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w") as f:
        f.write("data")
    return path
