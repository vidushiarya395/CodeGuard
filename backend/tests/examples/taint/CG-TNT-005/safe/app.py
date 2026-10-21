# Example only: scanned by the tests, never run.  CG-TNT-005 (safe)
from urllib.parse import urlparse

import requests
from flask import Flask, abort, request

app = Flask(__name__)
ALLOWED_HOSTS = {"example.com", "docs.python.org"}


@app.route("/preview")
def preview():
    url = request.args["url"]
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        abort(400)
    page = requests.get(url, timeout=5)
    return page.text[:500]
