"""
Benchmark Sample 5: Dead Code Vulnerability
Defines an unused helper function that calls yaml.load,
which is never called by any entry point or active code path.
Expected: is_reachable = False, confidence = 0.0
"""
import yaml


def dead_utility_func(untrusted_payload: str):
    # This helper calls yaml.load, but is completely unreferenced dead code
    return yaml.load(untrusted_payload, Loader=yaml.Loader)


def active_endpoint():
    return "Service is operational"


if __name__ == "__main__":
    active_endpoint()
