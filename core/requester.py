import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def requester(url, scheme, headers, origin):
    if origin == "null":
        headers["Origin"] = origin
    else:
        headers["Origin"] = scheme + "://" + origin

    try:
        response = requests.get(url, headers=headers, verify=False, timeout=20)
    except Exception:
        return
    response = response.headers
    for key, value in response.items():
        if key.lower() == "access-control-allow-origin":
            return response
