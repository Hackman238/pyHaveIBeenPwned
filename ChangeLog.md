## v0.3.2 - 2026-02-21
- Add provider-model architecture with a normalized multi-provider search flow (`BreachLookupClient`, `SearchRequest`, `ProviderResult`).
- Add first-class providers for `haveibeenpwned` and `dehashed`, including provider-specific credentials and criteria handling.
- Add provider registry utilities and comprehensive tests for provider normalization, validation, and orchestration behavior.
- Move implementation from package `__init__.py` into dedicated modules (`client.py`, `exceptions.py`, `version.py`) and keep `__init__.py` as the public API export surface.
- Add a package `VERSION` file as the single source of truth for versioning; wire package runtime (`__version__`) and `setup.py` metadata to it.
- Add explicit SPDX license metadata (`GPL-2.0-only`) and modernize build backend declaration via `pyproject.toml`.
- Update the DeHashed provider to the current v2 search contract (`POST /v2/search` with `DeHashed-Api-Key` header and JSON query payload).
- Align DeHashed default search payload with v2 examples by sending `page=1`, `size=25`, `regex=false`, `wildcard=false`, and `de_dupe=false` when not explicitly provided.
- Remove scraper backend requirements from the HIBP client and use direct HTTP requests via `requests.Session`.
- Keep backward compatibility for `scraper_factory` as a deprecated alias while documenting that HIBP still requires a `User-Agent` header.
- Set a descriptive default HIBP `User-Agent` string that follows the API guide format (`product/version (+URL)`).
- Add HIBP provider request pacing via `queries_per_second` criteria and default it to `5` requests/second.
- Preserve partial HIBP findings when optional calls (pastes/data classes) fail, instead of dropping already-collected breach results.
- Treat HIBP `404` responses from optional endpoints as empty datasets so successful breach findings are not marked as provider failures.
- Add tracked sample client script at `examples/sample_client.py` and document dual-provider live test usage in README.
- Add consolidated JSON reporting for multi-provider findings (`build_consolidated_report`) and expose it through the sample client (`--output-format json`).

## v0.3.0 - 2025-11-19
- Target HIBP v3 endpoints and add configurable request timeouts; all HTTP errors now raise `PyHaveIBeenPwnedError` with status and optional `Retry-After`.
- Remove implicit live API call on module execution and harden JSON parsing/error wrapping.
- Declare runtime dependencies (`cfscrape`, `requests`) in `install_requires` and refresh README with supported Python versions and API key requirements.

## v0.2.1 - 2025-11-10
- Last commit by sscott-tantalumlabs: Bug fixes to search, Optimization, better PEP compliance, added smoke test, updated Git Action workflow, Readme

## v0.2.0 - 2025-10-30
- Adopt pep8-compliant snake_case public methods with deprecation shims for previous camelCase names.
- Cache the CloudFlare scraper per instance, URL-encode parameters before dispatching, and raise `PyHaveIBeenPwnedError` when the API responds with an unexpected client error.
- Added first-class support for supplying the official HIBP API key and User-Agent headers; 401 responses now return a clear guidance message.
- Renamed the published package to lowercase `pyhaveibeenpwned` to comply with PyPI naming conventions.
- Added regression tests covering the new API surface, deprecation warnings, and error handling.
- Documented the naming changes, custom exception, and deprecation schedule in the README.

## v0.1.10 - 2024-05-01
- Last commit by sscottgvit: Update workflow

## v0.1.9 - 2024-05-01
- Last commit by sscottgvit: Update workflow
