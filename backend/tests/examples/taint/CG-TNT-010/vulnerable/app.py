# Example only: scanned by the tests, never run.  CG-TNT-010 (vulnerable)
import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/cart")
def cart():
    raw = request.cookies.get("cart", "")
    items = pickle.loads(base64.b64decode(raw))
    return {"count": len(items)}
