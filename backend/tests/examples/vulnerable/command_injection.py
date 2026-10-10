import subprocess


def ping(host):
    # Host comes from the user and is passed to a shell.
    return subprocess.call("ping -c 1 " + host, shell=True)
