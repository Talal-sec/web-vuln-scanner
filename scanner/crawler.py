import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
from typing import Optional
import re


@dataclass
class FormField:
    name: str
    field_type: str
    value: str = ""


@dataclass
class Form:
    action: str
    method: str
    fields: list[FormField] = field(default_factory=list)


@dataclass
class Page:
    url: str
    forms: list[Form] = field(default_factory=list)
    params: dict = field(default_factory=dict)


class Crawler:
    def __init__(self, base_url: str, depth: int = 2, timeout: int = 10, session: Optional[requests.Session] = None):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.depth = depth
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = "WebVulnScanner/1.0 (Educational)"
        self.visited: set[str] = set()
        self.pages: list[Page] = []

    def crawl(self) -> list[Page]:
        self._visit(self.base_url, 0)
        return self.pages

    def _visit(self, url: str, current_depth: int):
        if current_depth > self.depth or url in self.visited:
            return
        self.visited.add(url)

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            resp.raise_for_status()
        except Exception:
            return

        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = self._extract_forms(url, soup)

        self.pages.append(Page(url=url, forms=forms, params=params))

        if current_depth < self.depth:
            for link in soup.find_all("a", href=True):
                href = urljoin(url, link["href"])
                href = href.split("#")[0]
                if self._same_domain(href) and href not in self.visited:
                    self._visit(href, current_depth + 1)

    def _extract_forms(self, page_url: str, soup: BeautifulSoup) -> list[Form]:
        forms = []
        for form_tag in soup.find_all("form"):
            action = urljoin(page_url, form_tag.get("action", page_url))
            method = form_tag.get("method", "get").lower()
            fields = []
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                fields.append(FormField(
                    name=name,
                    field_type=inp.get("type", "text"),
                    value=inp.get("value", ""),
                ))
            if fields:
                forms.append(Form(action=action, method=method, fields=fields))
        return forms

    def _same_domain(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self.base_domain
        except Exception:
            return False


def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
