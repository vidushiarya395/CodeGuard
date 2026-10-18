# Example only: scanned by the tests, never run.  CG-DEP-005 (safe)
import html


def name_field(name):
    return '<input value="' + html.escape(name) + '">'
