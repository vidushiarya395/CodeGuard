# Example only: scanned by the tests, never run.  CG-SET-002 (vulnerable)
import ssl


def make_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context
