import requests


def fetch_pages(
    api_session: requests.Session,
    uri: str,
    api_key: str,
):
    params = {
        "auth": api_key,
        "page": 1,
    }
    response = api_session.get(uri, params=params, timeout=30)
    response.raise_for_status()
    return response.json()
