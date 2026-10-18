# Example only: scanned by the tests, never run.  CG-SEC-002 (vulnerable)
import psycopg2

DB_PASSWORD = "Tr0ub4dor-prod-42"


def connect():
    return psycopg2.connect(host="db", user="app", password=DB_PASSWORD)
