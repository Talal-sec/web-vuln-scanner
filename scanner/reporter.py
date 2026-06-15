import json
import sys
from datetime import datetime, timezone
from colorama import init, Fore, Style

init(autoreset=True)

SEVERITY_COLORS = {
    "HIGH":   Fore.RED + Style.BRIGHT,
    "MEDIUM": Fore.YELLOW + Style.BRIGHT,
    "LOW":    Fore.CYAN,
    "INFO":   Fore.GREEN,
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


class Reporter:
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.start_time = datetime.now(timezone.utc)
        self.findings = []

    def add_findings(self, findings: list):
        self.findings.extend(findings)

    def print_finding(self, f):
        color = SEVERITY_COLORS.get(f.severity, "")
        print(f"{color}[{f.severity}] [{f.module.upper()}] {f.description}")
        print(f"  URL:       {f.url}")
        print(f"  Parameter: {f.parameter}")
        print(f"  Evidence:  {f.evidence}")
        print()

    def print_summary(self):
        end_time = datetime.now(timezone.utc)
        elapsed = (end_time - self.start_time).total_seconds()

        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1

        print(Style.BRIGHT + "=" * 60)
        print(Style.BRIGHT + " SCAN SUMMARY")
        print(Style.BRIGHT + "=" * 60)
        print(f"  Target:   {self.target}")
        print(f"  Duration: {elapsed:.1f}s")
        print(f"  Findings: {len(self.findings)} total")
        print(f"  {Fore.RED + Style.BRIGHT}HIGH:   {counts['HIGH']}")
        print(f"  {Fore.YELLOW + Style.BRIGHT}MEDIUM: {counts['MEDIUM']}")
        print(f"  {Fore.CYAN}LOW:    {counts['LOW']}")
        print(Style.BRIGHT + "=" * 60)

    def save_json(self, path: str):
        end_time = datetime.now(timezone.utc)
        data = {
            "target": self.target,
            "scan_start": self.start_time.isoformat() + "Z",
            "scan_end": end_time.isoformat() + "Z",
            "total_findings": len(self.findings),
            "findings": sorted(
                [
                    {
                        "module": f.module,
                        "severity": f.severity,
                        "url": f.url,
                        "parameter": f.parameter,
                        "evidence": f.evidence,
                        "description": f.description,
                    }
                    for f in self.findings
                ],
                key=lambda x: SEVERITY_ORDER.get(x["severity"], 99),
            ),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        print(Fore.GREEN + f"[+] JSON report saved to: {path}")
