# Example only: scanned by the tests, never run.  CG-DEP-004 (vulnerable)
import yaml


def read_config(text):
    return yaml.load(text)
