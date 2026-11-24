import requests
s = requests.Session()
s.get("https://example.com", verify=False)
