# Example only: scanned by the tests, never run.  CG-DEP-008 (safe)
import tarfile


def unpack(archive, dest):
    with tarfile.open(archive) as tar:
        tar.extractall(dest, filter="data")
