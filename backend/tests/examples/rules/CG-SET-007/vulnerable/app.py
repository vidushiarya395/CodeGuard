# Example only: scanned by the tests, never run.  CG-SET-007 (vulnerable)
from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader("templates"), autoescape=False)


def render(name):
    return env.get_template("hello.html").render(name=name)
