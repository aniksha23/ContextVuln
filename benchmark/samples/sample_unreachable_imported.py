"""
Benchmark Sample 4: Unreachable Imported Dependency
Imports urllib3 and uses safe methods (PoolManager, request),
never invoking vulnerable target symbol (e.g. urllib3.util.retry.Retry).
Expected: is_reachable = False, confidence = 0.0
"""
import urllib3


def fetch_resource(url: str):
    http = urllib3.PoolManager()
    response = http.request("GET", url)
    return response.status


if __name__ == "__main__":
    fetch_resource("https://example.com/health")
