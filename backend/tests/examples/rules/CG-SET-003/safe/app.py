# Example only: scanned by the tests, never run.  CG-SET-003 (safe)
import os

from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "hello"


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
