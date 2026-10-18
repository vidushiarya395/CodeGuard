# Example only: scanned by the tests, never run.  CG-SET-004 (safe): a Django settings file.
import os

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
ALLOWED_HOSTS = ["example.com"]
