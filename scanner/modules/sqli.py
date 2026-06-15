import requests
from urllib.parse import urljoin
from dataclasses import dataclass
from ..crawler import Page, inject_param

DB_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "sqlite3::exception",
    "ora-00907",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "jdbc",
    "sqlexception",
    "sql syntax",
    "syntax error",
    "mysql_fetch",
    "num_rows",
    "mysql_num_rows",
]

ERROR_PAYLOADS = ["'", "''", "`", "\"", "1'", "1\""]
BOOL_TRUE = "1 AND 1=1"
BOOL_FALSE = "1 AND 1=2"


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
    findings.extend(_test_url_params(page, session, timeout))
    findings.extend(_test_forms(page, session, timeout))
    return findings


def _has_db_error(text: str) -> str:
    lower = text.lower()
    for err in DB_ERRORS:
        if err in lower:
            return err
    return ""


def _test_url_params(page: Page, session: requests.Session, timeout: int) -> list[Finding]:
    findings = []
    for param in page.params:
        for payload in ERROR_PAYLOADS:
            url = inject_param(page.url, param, payload)
            try:
                resp = session.get(url, timeout=timeout, allow_redirects=True)
                matched = _has_db_error(resp.text)
                if matched:
                    findings.append(Finding(
                        module="sqli",
                        severity="HIGH",
                        url=url,
                        parameter=param,
                        evidence=f"DB error pattern: '{matched}'",
                        description=f"Possible SQL Injection in URL parameter '{param}' — error-based",
                    ))
                    break
            except Exception:
                continue

        # Boolean-based
        try:
            url_true = inject_param(page.url, param, BOOL_TRUE)
            url_false = inject_param(page.url, param, BOOL_FALSE)
            r_true = session.get(url_true, timeout=timeout)
            r_false = session.get(url_false, timeout=timeout)
            diff = abs(len(r_true.text) - len(r_false.text))
            if diff > 50:
                findings.append(Finding(
                    module="sqli",
                    severity="MEDIUM",
                    url=page.url,
                    parameter=param,
                    evidence=f"Response length difference: {diff} bytes (true vs false condition)",
                    description=f"Possible SQL Injection in URL parameter '{param}' — boolean-based",
                ))
        except Exception:
            pass
    return findings


def _test_forms(page: Page, session: requests.Session, timeout: int) -> list[Finding]:
    findings = []
    for form in page.forms:
        for field in form.fields:
            if field.field_type in ("submit", "hidden", "button"):
                continue
            for payload in ERROR_PAYLOADS:
                data = {f.name: (payload if f.name == field.name else f.value or "test")
                        for f in form.fields}
                try:
                    if form.method == "post":
                        resp = session.post(form.action, data=data, timeout=timeout)
                    else:
                        resp = session.get(form.action, params=data, timeout=timeout)
                    matched = _has_db_error(resp.text)
                    if matched:
                        findings.append(Finding(
                            module="sqli",
                            severity="HIGH",
                            url=form.action,
                            parameter=field.name,
                            evidence=f"DB error pattern: '{matched}'",
                            description=f"Possible SQL Injection in form field '{field.name}'",
                        ))
                        break
                except Exception:
                    continue
    return findings
