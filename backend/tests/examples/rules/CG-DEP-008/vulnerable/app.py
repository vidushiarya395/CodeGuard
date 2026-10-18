# Example only: scanned by the tests, never run.  CG-DEP-008 (vulnerable)
import tarfile


def unpack(archive, dest):
    with tarfile.open(archive) as tar:
        tar.extractall(dest)
