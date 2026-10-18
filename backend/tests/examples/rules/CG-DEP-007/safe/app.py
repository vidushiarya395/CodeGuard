# Example only: scanned by the tests, never run.  CG-DEP-007 (safe)
import ast


def parse_list(text):
    return ast.literal_eval(text)
