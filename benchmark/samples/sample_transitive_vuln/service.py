"""
Service module for transitive vulnerability sample.
Vulnerable sink located here.
"""
import yaml


def parse_untrusted_data(data: str):
    # Vulnerable sink yaml.load called here
    return yaml.load(data, Loader=yaml.Loader)
