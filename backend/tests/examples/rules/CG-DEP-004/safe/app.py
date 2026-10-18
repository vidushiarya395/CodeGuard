# Example only: scanned by the tests, never run.  CG-DEP-004 (safe)
import yaml


def read_config(text):
    first = yaml.safe_load(text)
    second = yaml.load(text, Loader=yaml.SafeLoader)
    return first, second
