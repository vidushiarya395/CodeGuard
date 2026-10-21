# Example only: scanned by the tests, never run.  CG-TNT-002 (safe)
import ast

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args["expr"]
    return jsonify(result=ast.literal_eval(expr))
