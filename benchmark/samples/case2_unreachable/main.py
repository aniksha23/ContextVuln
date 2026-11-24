import urllib3
http = urllib3.PoolManager()
http.request("GET", "https://example.com")
