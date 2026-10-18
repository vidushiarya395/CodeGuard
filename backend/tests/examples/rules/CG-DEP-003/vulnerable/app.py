# Example only: scanned by the tests, never run.  CG-DEP-003 (vulnerable)
import ssl


def make_context():
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)
