# Example only: scanned by the tests, never run.  CG-SET-001 (vulnerable)
import requests


def fetch(url):
    return requests.get(url, verify=False, timeout=10).json()
