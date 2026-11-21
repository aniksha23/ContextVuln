"""
Benchmark Sample 3: Aliased Vulnerability
Imports vulnerable function using aliased import (from yaml import load as unsafe_loader).
Expected: is_reachable = True, confidence = 1.0
"""
from yaml import load as unsafe_loader, Loader


def run_alias_test():
    payload = "session: active"
    return unsafe_loader(payload, Loader=Loader)


if __name__ == "__main__":
    run_alias_test()
    # Direct invocation via alias in main block
    unsafe_loader("direct: test", Loader=Loader)
