# Example only: scanned by the tests, never run.  CG-PKG-001 (safe)
# Standard library, real packages (cv2 is published as opencv-python, yaml as PyYAML)
# and a relative import of the project's own code.
import json
import os

import cv2
import requests
import yaml

from .models import User


def load(url):
    return json.loads(requests.get(url, timeout=10).text), cv2, yaml, os, User
