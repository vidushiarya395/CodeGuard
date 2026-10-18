# Example only: scanned by the tests, never run.  CG-DEP-003 (safe)
import ssl


def make_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_default_certs()
    return context
