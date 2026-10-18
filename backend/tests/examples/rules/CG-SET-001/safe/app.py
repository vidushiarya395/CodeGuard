# Example only: scanned by the tests, never run.  CG-SET-001 (safe)
import requests


def fetch(url):
    return requests.get(url, timeout=10).json()


def fetch_internal(url):
    return requests.get(url, verify="/etc/ssl/company-ca.pem", timeout=10).json()
