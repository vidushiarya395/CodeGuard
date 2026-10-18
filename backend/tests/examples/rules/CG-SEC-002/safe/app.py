# Example only: scanned by the tests, never run.  CG-SEC-002 (safe)
# Secret-like names that hold no secret must not be reported either.
import os

import psycopg2

DB_PASSWORD = os.environ["DB_PASSWORD"]
PASSWORD_FIELD = "password"
API_TOKEN_ENV = "API_TOKEN"
eos_token = "</s>"


def connect():
    return psycopg2.connect(host="db", user="app", password=DB_PASSWORD)
