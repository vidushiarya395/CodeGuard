# Example only: scanned by the tests, never run.  CG-SEC-003 (safe)
import os

from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
