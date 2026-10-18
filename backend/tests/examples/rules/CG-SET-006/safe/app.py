# Example only: scanned by the tests, never run.  CG-SET-006 (safe)
import paramiko


def connect(host, user):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(host, username=user, timeout=10)
    return client
