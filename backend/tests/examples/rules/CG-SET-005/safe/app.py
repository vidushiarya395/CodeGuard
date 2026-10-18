# Example only: scanned by the tests, never run.  CG-SET-005 (safe)
import os

import jwt


def current_user(token):
    claims = jwt.decode(token, os.environ["JWT_KEY"], algorithms=["HS256"])
    return claims["sub"]
