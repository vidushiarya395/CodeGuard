# Example only: scanned by the tests, never run.  CG-SEC-003 (vulnerable)
import os

from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
OPENAI_API_KEY = "YOUR_API_KEY_HERE"
