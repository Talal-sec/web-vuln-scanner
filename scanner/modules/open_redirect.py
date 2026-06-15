import requests
from urllib.parse import urlparse
from dataclasses import dataclass
from ..crawler import Page, inject_param

REDIRECT_PARAMS = {
    "redirect", "redirect_url", "redirect_uri", "url", "next", "return",
    "return_url", "returnto", "goto", "destination", "dest", "target",
    "redir", "ref", "callback", "continue", "forward", "location", "link",
}

EVIL_URL = "https://evil-redirect-test.example.com"


@dataclass
class Finding:
    module: str
    severity: str
    url: str
    parameter: str
    evidence: str
    description: str


def scan(page: Page, session: requests.Session, timeout: int = 10) -> list[Finding]:
    findings = []

    for param in page.params:
        if param.lower() not in REDIRECT_PARAMS:
            continue
        test_url = inject_param(page.url, param, EVIL_URL)
        try:
            resp = session.get(test_url, timeout=timeout, allow_redirects=False)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if _points_to_evil(location):
                    findings.append(Finding(
                        module="open_redirect",
                        severity="MEDIUM",
                        url=test_url,
                        parameter=param,
                        evidence=f"Response redirected to: {location}",
                        description=f"Open Redirect in parameter '{param}' — redirects to attacker-controlled URL",
                    ))
        except Exception:
            continue

    for form in page.forms:
        for field in form.fields:
            if field.name.lower() not in REDIRECT_PARAMS:
                continue
            data = {f.name: (EVIL_URL if f.name == field.name else f.value or "test")
                    for f in form.fields}
            try:
                if form.method == "post":
                    resp = session.post(form.action, data=data, timeout=timeout, allow_redirects=False)
                else:
                    resp = session.get(form.action, params=data, timeout=timeout, allow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if _points_to_evil(location):
                        findings.append(Finding(
                            module="open_redirect",
                            severity="MEDIUM",
                            url=form.action,
                            parameter=field.name,
                            evidence=f"Response redirected to: {location}",
                            description=f"Open Redirect in form field '{field.name}'",
                        ))
            except Exception:
                continue

    return findings


def _points_to_evil(location: str) -> bool:
    try:
        return urlparse(location).netloc == urlparse(EVIL_URL).netloc
    except Exception:
        return False
