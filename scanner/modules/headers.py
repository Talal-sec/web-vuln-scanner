import requests
from ..models import Finding

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Content-Security-Policy header is missing. Without CSP, the browser has no policy to prevent XSS or data injection attacks.",
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Strict-Transport-Security (HSTS) header is missing. This leaves users vulnerable to SSL stripping and man-in-the-middle attacks.",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "X-Frame-Options header is missing. The page may be embeddable in iframes, enabling clickjacking attacks.",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, potentially executing malicious content.",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Referrer-Policy header is missing. Sensitive URL data may leak to third-party sites via the Referer header.",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Permissions-Policy header is missing. Browser features (camera, geolocation, etc.) are not explicitly restricted.",
    },
}

WEAK_VALUES = {
    "X-Frame-Options": ["ALLOW-FROM"],
    "Content-Security-Policy": ["unsafe-inline", "unsafe-eval"],
}


def scan(url: str, session: requests.Session, timeout: int = 10) -> list[Finding]:
    findings = []
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return findings

    for header, info in SECURITY_HEADERS.items():
        value = resp.headers.get(header)
        if value is None:
            findings.append(Finding(
                module="headers",
                severity=info["severity"],
                url=url,
                parameter=header,
                evidence=f"Header '{header}' not present in response",
                description=info["description"],
            ))
        elif header in WEAK_VALUES:
            for weak in WEAK_VALUES[header]:
                if weak.lower() in value.lower():
                    findings.append(Finding(
                        module="headers",
                        severity="MEDIUM",
                        url=url,
                        parameter=header,
                        evidence=f"Header '{header}: {value}' contains weak directive '{weak}'",
                        description=f"Weak {header} configuration — '{weak}' undermines security.",
                    ))
                    break

    return findings
