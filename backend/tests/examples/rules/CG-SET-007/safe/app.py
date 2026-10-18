# Example only: scanned by the tests, never run.  CG-SET-007 (safe)
from jinja2 import Environment, FileSystemLoader, select_autoescape

env = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape())


def render(name):
    return env.get_template("hello.html").render(name=name)
