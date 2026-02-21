#!/usr/bin/env python3
"""Sample live client for pyhaveibeenpwned provider-model searches.

Run from the repository root or after installing the package.
"""

import argparse
import json
import os
import sys

from pyhaveibeenpwned import (
    BreachLookupClient,
    ProviderCredentials,
    SearchRequest,
    build_consolidated_report,
    __version__,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run live provider API checks for pyhaveibeenpwned."
    )
    parser.add_argument("--email", required=True, help="Email address to check.")
    parser.add_argument(
        "--provider",
        choices=("dehashed", "haveibeenpwned", "both"),
        default="both",
        help="Provider(s) to test.",
    )
    parser.add_argument(
        "--dehashed-api-key",
        default=os.getenv("DEHASHED_API_KEY", "").strip(),
        help="DeHashed API key (or set DEHASHED_API_KEY).",
    )
    parser.add_argument(
        "--dehashed-query",
        help="Optional explicit DeHashed query; defaults to email:<email>.",
    )
    parser.add_argument(
        "--hibp-api-key",
        default=os.getenv("HIBP_API_KEY", "").strip(),
        help="HIBP API key (or set HIBP_API_KEY).",
    )
    parser.add_argument(
        "--hibp-user-agent",
        default=(
            f"pyhaveibeenpwned-sample-client/{__version__} "
            "(+https://github.com/Hackman238/pyHaveIBeenPwned)"
        ),
        help="User-Agent sent to HIBP.",
    )
    parser.add_argument(
        "--hibp-qps",
        type=float,
        default=5.0,
        help="HIBP provider queries per second pacing (default: 5).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Request timeout in seconds.",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=5,
        help="Max findings to print per provider.",
    )
    parser.add_argument(
        "--output-format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--output-file",
        help="Optional path to write JSON output when --output-format json is used.",
    )
    return parser.parse_args()


def build_request(args):
    providers = []
    credentials_by_provider = {}
    criteria_by_provider = {}

    if args.provider in {"dehashed", "both"}:
        if not args.dehashed_api_key:
            raise ValueError(
                "Missing DeHashed API key. Set --dehashed-api-key or DEHASHED_API_KEY."
            )
        providers.append("dehashed")
        credentials_by_provider["dehashed"] = ProviderCredentials(
            api_key=args.dehashed_api_key
        )
        criteria_by_provider["dehashed"] = {
            "query": args.dehashed_query or f"email:{args.email}",
            "page": 1,
            "size": 25,
            "regex": False,
            "wildcard": False,
            "de_dupe": False,
        }

    if args.provider in {"haveibeenpwned", "both"}:
        if not args.hibp_api_key:
            raise ValueError("Missing HIBP API key. Set --hibp-api-key or HIBP_API_KEY.")
        providers.append("haveibeenpwned")
        credentials_by_provider["haveibeenpwned"] = ProviderCredentials(
            api_key=args.hibp_api_key,
            user_agent=args.hibp_user_agent,
        )
        criteria_by_provider["haveibeenpwned"] = {
            "queries_per_second": args.hibp_qps,
        }

    return SearchRequest(
        target_email=args.email,
        providers=providers,
        credentials_by_provider=credentials_by_provider,
        criteria_by_provider=criteria_by_provider,
        timeout=args.timeout,
    )


def print_provider_result(name, result, max_findings):
    print(f"\n[{name}]")
    print("ok:", result.ok)
    print("status_code:", result.status_code)
    print("error:", result.error)
    print("findings:", len(result.findings))
    for finding in result.findings[:max_findings]:
        print("-", finding.identifier)
    if result.raw:
        if isinstance(result.raw, dict):
            print("raw keys:", sorted(result.raw.keys()))
        else:
            print("raw type:", type(result.raw).__name__)


def main():
    args = parse_args()
    try:
        request = build_request(args)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2

    response = BreachLookupClient().search(request)
    any_failed = any(not result.ok for result in response.results.values())

    if args.output_format == "json":
        report = build_consolidated_report(request, response)
        rendered = json.dumps(report, indent=2, sort_keys=True)
        if args.output_file:
            with open(args.output_file, "w", encoding="utf-8") as handle:
                handle.write(rendered)
            print(f"Wrote JSON report to: {args.output_file}")
        else:
            print(rendered)
        return 1 if any_failed else 0

    print("pyhaveibeenpwned version:", __version__)
    print("target_email:", request.target_email)
    print("providers:", request.providers)

    for provider_name in request.providers:
        result = response.results[provider_name]
        print_provider_result(provider_name, result, args.max_findings)

    return 1 if any_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
