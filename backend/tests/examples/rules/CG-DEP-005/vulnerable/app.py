# Example only: scanned by the tests, never run.  CG-DEP-005 (vulnerable)
import cgi


def name_field(name):
    return '<input value="' + cgi.escape(name) + '">'
