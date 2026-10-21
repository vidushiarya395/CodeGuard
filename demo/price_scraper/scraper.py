"""Scrape product prices from shop pages and save them to a CSV file.

    python scraper.py https://shop.example.com/item/42 --out prices.csv
"""

import argparse
import csv
import re
import time

import requests
from bs4 import BeautifulSoup
from pricescrape_helpers import normalize_price

SCRAPER_API_KEY = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
HEADERS = {"User-Agent": "PriceBot/1.0", "X-Api-Key": SCRAPER_API_KEY}
PRICE_RE = re.compile(r"(\d+[.,]\d{2})")


def fetch(url):
    response = requests.get(url, headers=HEADERS, timeout=15, verify=False)
    response.raise_for_status()
    return response.text


def parse_price(html):
    soup = BeautifulSoup(html, "html.parser")
    tag = soup.select_one("[itemprop=price], .price, #price")
    if tag is None:
        return None
    match = PRICE_RE.search(tag.get_text())
    return normalize_price(match.group(1)) if match else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("urls", nargs="+")
    parser.add_argument("--out", default="prices.csv")
    parser.add_argument("--delay", type=float, default=1.0)
    args = parser.parse_args()

    with open(args.out, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "price"])
        for url in args.urls:
            writer.writerow([url, parse_price(fetch(url))])
            time.sleep(args.delay)


if __name__ == "__main__":
    main()
