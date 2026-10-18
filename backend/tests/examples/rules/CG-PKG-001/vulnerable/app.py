# Example only: scanned by the tests, never run.  CG-PKG-001 (vulnerable)
# "fastjsonx" is an invented name, as an AI tool might write. It is not on PyPI.
import requests
import fastjsonx


def load(url):
    return fastjsonx.loads(requests.get(url, timeout=10).text)
