import yaml


def load_settings(path):
    # CVE-2020-14343: yaml.load on untrusted input -> code execution
    with open(path) as f:
        return yaml.load(f)
