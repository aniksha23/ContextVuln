from urllib3.response import HTTPResponse
def consume(resp: HTTPResponse):
    for chunk in resp.stream(1024):
        pass
