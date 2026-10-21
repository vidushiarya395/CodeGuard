"""Small web front end: paste a product URL and see the scraped price."""

import requests
from flask import Flask, jsonify, request

from scraper import parse_price

app = Flask(__name__)


@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    if not url.startswith("http"):
        return jsonify(error="Please give an http(s) URL"), 400
    page = requests.get(url, timeout=10)
    return jsonify(url=url, price=parse_price(page.text))


@app.route("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
