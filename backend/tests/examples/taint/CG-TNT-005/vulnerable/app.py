# Example only: scanned by the tests, never run.  CG-TNT-005 (vulnerable)
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/preview")
def preview():
    url = request.args["url"]
    page = requests.get(url, timeout=5)
    return page.text[:500]
