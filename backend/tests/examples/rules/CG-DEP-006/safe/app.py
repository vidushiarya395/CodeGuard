# Example only: scanned by the tests, never run.  CG-DEP-006 (safe)
import paramiko


def run(host, user, command):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(host, username=user, timeout=10)
    _, stdout, _ = client.exec_command(command)
    return stdout.read()
