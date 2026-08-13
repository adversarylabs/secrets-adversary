from urllib.parse import urlsplit

import requests


def fetch_page(session, uri, page):
    response = session.get(uri, params={"page": page}, timeout=30)
    response.raise_for_status()
    return response.json()


def fetch_with_header(session, uri, api_key):
    response = session.get(
        uri,
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def fetch_with_auth(session, uri, username, password):
    response = session.get(uri, auth=(username, password), timeout=30)
    response.raise_for_status()
    return response.json()


def fetch_without_status_raise(session, uri, api_key):
    return session.get(uri, params={"api_key": api_key}, timeout=30)


def fetch_with_sanitized_error(session: requests.Session, uri, access_token):
    response = session.get(uri, params={"access_token": access_token}, timeout=30)
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        status = exc.response.status_code
        path = urlsplit(exc.response.url).path
        raise RuntimeError(f"request failed: {status} {path}") from None
    return response.json()


def fetch_with_unrelated_client(client, uri, api_key):
    response = client.get(uri, params={"api_key": api_key})
    response.raise_for_status()
    return response.data


def fetch_with_intentionally_contained_error(session: requests.Session, uri, api_key):
    response = session.get(uri, params={"api_key": api_key}, timeout=30)
    try:
        response.raise_for_status()
    except requests.HTTPError:
        return None
    return response.json()


def documentation_only():
    """Example that must not be interpreted as executable code.

    response = requests.get(uri, params={"api_key": api_key})
    response.raise_for_status()
    """
    example = "response = requests.get(uri, params={'api_key': api_key}); response.raise_for_status()"
    # response = requests.get(uri, params={"api_key": api_key})
    # response.raise_for_status()
    return example
