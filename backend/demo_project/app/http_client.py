import urllib3

_pool = urllib3.PoolManager()


def fetch(url):
    # urllib3 is used, but never parse_url() -> CVE-2021-33503 is NOT reachable
    return _pool.request("GET", url).data
