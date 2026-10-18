# Example only: scanned by the tests, never run.  CG-DEP-002 (safe)
import socket
import ssl


def connect(host):
    sock = socket.create_connection((host, 443))
    context = ssl.create_default_context()
    return context.wrap_socket(sock, server_hostname=host)
