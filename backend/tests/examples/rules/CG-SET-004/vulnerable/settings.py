# Example only: scanned by the tests, never run.  CG-SET-004 (vulnerable): a Django settings file.
import os

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = True
ALLOWED_HOSTS = ["example.com"]
