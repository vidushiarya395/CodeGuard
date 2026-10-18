# Example only: scanned by the tests, never run.  CG-SET-005 (vulnerable)
import jwt


def current_user(token):
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["sub"]
