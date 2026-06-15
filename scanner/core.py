import requests
from urllib3.exceptions import InsecureRequestWarning

from .crawler import Crawler
from .reporter import Reporter
from .modules import sqli, xss, headers, open_redirect

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

ALL_MODULES = ["sqli", "xss", "headers", "open_redirect"]

MODULE_MAP = {
    "sqli": sqli,
    "xss": xss,
    "headers": headers,
    "open_redirect": open_redirect,
}


class Scanner:
    def __init__(
        self,
        url: str,
        modules: list[str] | None = None,
        depth: int = 2,
        timeout: int = 10,
        verbose: bool = False,
        output: str | None = None,
    ):
        self.url = url.rstrip("/")
        self.modules = modules or ALL_MODULES
        self.depth = depth
        self.timeout = timeout
        self.verbose = verbose
        self.output = output
        self.session = requests.Session()
        self.session.verify = False
        self.reporter = Reporter(self.url, verbose=verbose)

    def run(self):
        print(f"[*] Starting scan on {self.url}")
        print(f"[*] Modules: {', '.join(self.modules)}")
        print(f"[*] Crawl depth: {self.depth}\n")

        # Security headers check on base URL (no crawl needed)
        if "headers" in self.modules:
            print("[*] Checking security headers...")
            found = headers.scan(self.url, self.session, self.timeout)
            for f in found:
                self.reporter.print_finding(f)
            self.reporter.add_findings(found)

        # Crawl
        active_modules = [m for m in self.modules if m != "headers"]
        if active_modules:
            print(f"[*] Crawling {self.url} (depth={self.depth})...")
            crawler = Crawler(self.url, depth=self.depth, timeout=self.timeout, session=self.session)
            pages = crawler.crawl()
            print(f"[*] Discovered {len(pages)} page(s)\n")

            for page in pages:
                if self.verbose:
                    print(f"[~] Scanning: {page.url}")

                if "sqli" in active_modules:
                    found = sqli.scan(page, self.session, self.timeout)
                    for f in found:
                        self.reporter.print_finding(f)
                    self.reporter.add_findings(found)

                if "xss" in active_modules:
                    found = xss.scan(page, self.session, self.timeout)
                    for f in found:
                        self.reporter.print_finding(f)
                    self.reporter.add_findings(found)

                if "open_redirect" in active_modules:
                    found = open_redirect.scan(page, self.session, self.timeout)
                    for f in found:
                        self.reporter.print_finding(f)
                    self.reporter.add_findings(found)

        self.reporter.print_summary()

        if self.output:
            self.reporter.save_json(self.output)
