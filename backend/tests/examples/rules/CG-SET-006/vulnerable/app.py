# Example only: scanned by the tests, never run.  CG-SET-006 (vulnerable)
import paramiko


def connect(host, user):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, timeout=10)
    return client
