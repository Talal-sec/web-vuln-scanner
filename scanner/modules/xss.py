import requests
import html
from ..crawler import Page, inject_param
from ..models import Finding

PAYLOADS = [
    "<script>alert('xss')</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

def scan(page: Page, session: requests.Session, timeout: int = 10) -> list[Finding]:
    findings = []
    findings.extend(_test_url_params(page, session, timeout))
    findings.extend(_test_forms(page, session, timeout))
    return findings


def _is_reflected(payload: str, response_text: str) -> bool:
    return payload in response_text


def _test_url_params(page: Page, session: requests.Session, timeout: int) -> list[Finding]:
    findings = []
    for param in page.params:
        for payload in PAYLOADS:
            url = inject_param(page.url, param, payload)
            try:
                resp = session.get(url, timeout=timeout, allow_redirects=True)
                if _is_reflected(payload, resp.text):
                    findings.append(Finding(
                        module="xss",
                        severity="HIGH",
                        url=url,
                        parameter=param,
                        evidence=f"Payload reflected unescaped: {payload[:60]}",
                        description=f"Reflected XSS in URL parameter '{param}'",
                    ))
                    break
            except Exception:
                continue
    return findings


def _test_forms(page: Page, session: requests.Session, timeout: int) -> list[Finding]:
    findings = []
    for form in page.forms:
        for field in form.fields:
            if field.field_type in ("submit", "hidden", "button"):
                continue
            for payload in PAYLOADS:
                data = {f.name: (payload if f.name == field.name else f.value or "test")
                        for f in form.fields}
                try:
                    if form.method == "post":
                        resp = session.post(form.action, data=data, timeout=timeout)
                    else:
                        resp = session.get(form.action, params=data, timeout=timeout)
                    if _is_reflected(payload, resp.text):
                        findings.append(Finding(
                            module="xss",
                            severity="HIGH",
                            url=form.action,
                            parameter=field.name,
                            evidence=f"Payload reflected unescaped: {payload[:60]}",
                            description=f"Reflected XSS in form field '{field.name}'",
                        ))
                        break
                except Exception:
                    continue
    return findings
