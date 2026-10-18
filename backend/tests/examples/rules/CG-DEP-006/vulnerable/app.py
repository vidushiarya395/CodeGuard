# Example only: scanned by the tests, never run.  CG-DEP-006 (vulnerable)
import telnetlib


def run(host, command):
    with telnetlib.Telnet(host, 23, timeout=10) as tn:
        tn.write(command.encode() + b"\n")
        return tn.read_all()
