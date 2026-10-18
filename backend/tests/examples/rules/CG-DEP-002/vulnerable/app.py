# Example only: scanned by the tests, never run.  CG-DEP-002 (vulnerable)
import socket
import ssl


def connect(host):
    sock = socket.create_connection((host, 443))
    return ssl.wrap_socket(sock)
