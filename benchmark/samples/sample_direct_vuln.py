"""
Benchmark Sample 1: Direct Vulnerability
Entry point directly calls a vulnerable symbol (yaml.load).
Expected: is_reachable = True, confidence = 1.0
"""
import yaml


def direct_entrypoint(payload: str):
    # Direct invocation of vulnerable yaml.load
    return yaml.load(payload, Loader=yaml.Loader)


if __name__ == "__main__":
    sample_payload = "name: ContextVuln"
    yaml.load(sample_payload, Loader=yaml.Loader)
