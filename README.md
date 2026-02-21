pyhaveibeenpwned (https://shanewilliamscott.com)
==
[![Python package](https://github.com/Hackman238/pyHaveIBeenPwned/actions/workflows/master.yml/badge.svg)](https://github.com/Hackman238/pyHaveIBeenPwned/actions/workflows/master.yml)
[![Known Vulnerabilities](https://snyk.io/test/github/Hackman238/pyHaveIBeenPwned/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/Hackman238/pyHaveIBeenPwned?targetFile=requirements.txt)

## Authors:
Shane Scott

## About pyhaveibeenpwned
Python library to query breach data providers through a unified interface. The package supports:
- `haveibeenpwned` (official HIBP v3 API)
- `dehashed`

The legacy `PyHaveIBeenPwned` client remains available for backward compatibility.

## Release 0.3.2
- Add a provider-model API with `BreachLookupClient`, `SearchRequest`, and normalized provider results.
- Add built-in providers for `haveibeenpwned` and `dehashed` with per-provider credentials/criteria.
- Consolidate package internals into dedicated modules and use a package `VERSION` file as the single version source of truth.
- Update DeHashed integration to v2 API (`POST /v2/search`, `DeHashed-Api-Key` header).
- Move HIBP to direct `requests.Session` calls (no scraper dependency) while keeping legacy compatibility.
- Add HIBP request pacing (`queries_per_second`), improved optional-endpoint handling, and descriptive default `User-Agent`.
- Add a tracked sample client (`examples/sample_client.py`) with consolidated JSON reporting (`--output-format json`).
- Keep legacy `PyHaveIBeenPwned` usage available for backward compatibility.

## Requirements
- Python 3.9–3.12
- Provider API keys (for example, HIBP API key and/or DeHashed API key)
- Runtime dependency: `requests` (installed automatically via `pip`)

## Installation
pip3 install pyhaveibeenpwned

## Sample Client Script
A tracked sample client is included at `examples/sample_client.py` for live checks against one provider or both providers in the same run.

Example (both providers):
```bash
HIBP_API_KEY='your_hibp_key' \
DEHASHED_API_KEY='your_dehashed_key' \
python examples/sample_client.py \
  --provider both \
  --email "user@example.com" \
  --hibp-qps 0.15
```

Structured JSON output (tool-consumable):
```bash
HIBP_API_KEY='your_hibp_key' \
DEHASHED_API_KEY='your_dehashed_key' \
python examples/sample_client.py \
  --provider both \
  --email "user@example.com" \
  --hibp-qps 0.15 \
  --output-format json \
  --output-file findings.json
```

JSON report top-level keys:
- `schema_version`
- `generated_at`
- `target_email`
- `providers_requested`
- `provider_results`
- `scope`
- `account_hits`

Example JSON output (trimmed for readability):
```json
{
  "schema_version": "1.0.0",
  "generated_at": "2026-02-21T18:45:00+00:00",
  "target_email": "user@example.com",
  "providers_requested": [
    "dehashed",
    "haveibeenpwned"
  ],
  "provider_results": {
    "dehashed": {
      "ok": true,
      "status_code": null,
      "error": null,
      "finding_count": 2
    },
    "haveibeenpwned": {
      "ok": true,
      "status_code": null,
      "error": null,
      "finding_count": 1
    }
  },
  "scope": {
    "total_findings": 3,
    "accounts_with_hits": 1,
    "provider_hit_counts": {
      "dehashed": 2,
      "haveibeenpwned": 1
    },
    "unique_hibp_breaches": [
      "LinkedIn"
    ],
    "hibp_leaked_data_classes": [
      "Email addresses",
      "Passwords"
    ],
    "dehashed_leaked_fields": [
      "database_name",
      "email",
      "password",
      "username"
    ]
  },
  "account_hits": [
    {
      "account": "user@example.com",
      "total_hits": 3,
      "providers": {
        "dehashed": {
          "hit_count": 2,
          "findings": [
            {
              "provider": "dehashed",
              "category": "leak_record",
              "identifier": "['user@example.com']",
              "record_id": "abc123",
              "scope": {
                "source": "example_combo_db",
                "username": "example_user",
                "domain": "example.com",
                "ip_address": null
              },
              "leaked_data": {
                "email": [
                  "user@example.com"
                ],
                "username": "example_user",
                "password": "redacted"
              },
              "leaked_fields": [
                "database_name",
                "email",
                "password",
                "username"
              ]
            }
          ]
        },
        "haveibeenpwned": {
          "hit_count": 1,
          "findings": [
            {
              "provider": "haveibeenpwned",
              "category": "breach",
              "identifier": "LinkedIn",
              "scope": {
                "breach_name": "LinkedIn",
                "title": "LinkedIn",
                "domain": "linkedin.com",
                "breach_date": "2012-05-05",
                "added_date": "2016-05-18T07:15:00Z",
                "modified_date": "2018-02-19T23:13:00Z",
                "pwn_count": 164611595,
                "is_verified": true,
                "is_sensitive": false,
                "is_retired": false,
                "is_spam_list": false,
                "is_malware": false,
                "is_fabricated": false,
                "is_stealer_log": false
              },
              "leaked_data": {
                "data_classes": [
                  "Email addresses",
                  "Passwords"
                ],
                "description": "Description text from provider."
              },
              "source": {
                "logo_path": "https://haveibeenpwned.com/Content/Images/PwnedLogos/LinkedIn.png"
              }
            }
          ]
        }
      }
    }
  ]
}
```

## Usage (Provider Model)
```python
from pyhaveibeenpwned import (
    BreachLookupClient,
    ProviderCredentials,
    SearchRequest,
    __version__,
)

print(__version__)

request = SearchRequest(
    target_email="user@example.com",
    providers=["haveibeenpwned", "dehashed"],
    credentials_by_provider={
        "haveibeenpwned": ProviderCredentials(
            api_key="your-hibp-api-key",
            user_agent="my-company-security-tool/1.0 (+https://example.com/security-contact)",
        ),
        "dehashed": ProviderCredentials(
            api_key="your-dehashed-api-key",
            user_agent="my-company-app/1.0",
        ),
    },
    criteria_by_provider={
        "haveibeenpwned": {
            "domain": "example.com",
            "queries_per_second": 5,
        },
        "dehashed": {
            "query": r"email:{target_email}",
            "page": 1,
            "size": 100,
            "regex": False,
            "wildcard": False,
            "de_dupe": False,
        },
    },
)

response = BreachLookupClient().search(request)
hibp_result = response.results["haveibeenpwned"]
dehashed_result = response.results["dehashed"]

print(hibp_result.ok, len(hibp_result.findings))
print(dehashed_result.ok, len(dehashed_result.findings))
```

> **Notes:**
> - Results are returned per provider so one provider failure does not block other provider results.
> - Each provider result includes normalized findings and raw provider payload.
> - A global request timeout can be supplied via `SearchRequest(timeout=...)`.
> - The HIBP API requires both an API key and a `User-Agent` header for authenticated endpoints.
> - HIBP applies strict rate limits; enabling `include_pastes` and `include_data_classes` adds extra API calls.
> - HIBP provider calls are rate-paced using `queries_per_second` (default: `5`).

## Legacy Usage (Backward Compatible)
```python
from pyhaveibeenpwned import PyHaveIBeenPwned, PyHaveIBeenPwnedError

client = PyHaveIBeenPwned(
    api_key="your-hibp-api-key",
    user_agent="my-company-security-tool/1.0 (+https://example.com/security-contact)",
)

try:
    breaches = client.get_account_breaches("user@example.com")
except PyHaveIBeenPwnedError as exc:
    print(f"API error: {exc}")
```

## Deprecations
Release 0.2 moves all public methods to snake_case to comply with PEP 8. Legacy camelCase helpers remain available for now and emit `DeprecationWarning`; update your code to use the new names before the next major release.

## Credits
Based on fork from https://github.com/GoVanguard/pyExploitDb by Shane Scott.
