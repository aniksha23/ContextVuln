import requests
s = requests.Session()
s.rebuild_auth(None, None)
