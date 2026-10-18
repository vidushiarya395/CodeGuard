# Example only: scanned by the tests, never run.  CG-SET-002 (safe)
import ssl


def make_context():
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context
