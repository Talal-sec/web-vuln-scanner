#!/usr/bin/env python3
"""
Web Vulnerability Scanner
Detects: SQL Injection, Reflected XSS, Missing Security Headers, Open Redirects
"""

import argparse
import sys
from scanner.core import Scanner, ALL_MODULES


def parse_args():
    parser = argparse.ArgumentParser(
        prog="webvuln",
        description="Web Vulnerability Scanner — SQLi, XSS, Headers, Open Redirect",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --url http://testphp.vulnweb.com
  python main.py --url https://example.com --modules sqli xss --output report.json
  python main.py --url https://example.com --depth 3 --timeout 15 --verbose
        """,
    )
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument(
        "--modules",
        nargs="+",
        choices=ALL_MODULES,
        default=ALL_MODULES,
        metavar="MODULE",
        help=f"Modules to run (default: all). Choices: {', '.join(ALL_MODULES)}",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Crawl depth (default: 2)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save findings to a JSON file",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print each URL as it is scanned",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.url.startswith(("http://", "https://")):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)

    scanner = Scanner(
        url=args.url,
        modules=args.modules,
        depth=args.depth,
        timeout=args.timeout,
        verbose=args.verbose,
        output=args.output,
    )
    scanner.run()


if __name__ == "__main__":
    main()
