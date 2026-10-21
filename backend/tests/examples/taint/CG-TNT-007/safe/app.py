# Example only: scanned by the tests, never run.  CG-TNT-007 (safe)
from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello {{ name }}!</h1>", name=name)
