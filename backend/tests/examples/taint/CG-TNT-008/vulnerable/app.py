# Example only: scanned by the tests, never run.  CG-TNT-008 (vulnerable)
from flask import Flask, render_template, request
from markupsafe import Markup

app = Flask(__name__)


@app.route("/bio", methods=["POST"])
def bio():
    text = request.form["bio"]
    return render_template("bio.html", bio=Markup(f"<p>{text}</p>"))
