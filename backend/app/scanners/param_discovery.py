"""
scanners/param_discovery.py

Day 10 — SQLi target discovery.

Crawls a target's homepage (depth 1, same-origin only) to find
candidate injectable parameters: URLs with query strings, and
GET-method forms with input fields. Deliberately bounded — this
feeds sqlmap_scanner.py, and each discovered parameter costs a
real sqlmap invocation (5-30+ seconds), so scope stays tight.

This module only discovers and returns candidate URLs; it never
sends injection payloads itself. That stays entirely inside
sqlmap_scanner.py, keeping "look for testable surface" and
"actually inject" as separate, independently auditable steps.
"""

import logging
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger("shieldlabs.param_discovery")

REQUEST_TIMEOUT = 8
DEFAULT_MAX_PARAMS = 5


def discover_injectable_targets(base_url: str, max_params: int = DEFAULT_MAX_PARAMS) -> list[str]:
    """
    Crawls base_url's homepage for candidate SQLi test targets.

    Args:
        base_url: e.g. "http://example.com"
        max_params: hard cap on how many candidate URLs to return

    Returns:
        List of full URLs (each with a query string) worth testing
        with sqlmap. Empty list on any failure — fails safe, never
        raises, since this feeds an opt-in deep-scan step.
    """
    candidates = []
    seen = set()

    try:
        resp = requests.get(base_url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except Exception:
        logger.warning("Could not fetch %s for parameter discovery.", base_url)
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    parsed_base = urlparse(base_url)
    base_origin = (parsed_base.scheme, parsed_base.netloc)

    # 1. Links with query strings, e.g. <a href="page.php?id=1">
    for a_tag in soup.find_all("a", href=True):
        full_url = urljoin(base_url, a_tag["href"])
        parsed = urlparse(full_url)

        if (parsed.scheme, parsed.netloc) != base_origin:
            continue  # same-origin only
        if not parsed.query:
            continue  # no parameters to test

        if full_url not in seen:
            seen.add(full_url)
            candidates.append(full_url)

        if len(candidates) >= max_params:
            break

    # 2. GET forms with input fields
    if len(candidates) < max_params:
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            if method != "get":
                continue  # POST forms not supported yet (see module docstring)

            action = form.get("action") or base_url
            form_url = urljoin(base_url, action)

            inputs = form.find_all(["input", "select", "textarea"])
            params = {}
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                params[name] = inp.get("value") or "1"  # dummy test value

            if not params:
                continue

            query_string = "&".join(k + "=" + str(v) for k, v in params.items())
            full_url = form_url + ("&" if "?" in form_url else "?") + query_string

            parsed = urlparse(full_url)
            if (parsed.scheme, parsed.netloc) != base_origin:
                continue

            if full_url not in seen:
                seen.add(full_url)
                candidates.append(full_url)

            if len(candidates) >= max_params:
                break

    logger.info("Parameter discovery for %s found %d candidate(s).", base_url, len(candidates))
    return candidates