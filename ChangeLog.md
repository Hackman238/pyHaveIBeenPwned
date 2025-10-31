## v0.2.0 - 2025-10-30
- Adopt pep8-compliant snake_case public methods with deprecation shims for previous camelCase names.
- Cache the CloudFlare scraper per instance, URL-encode parameters before dispatching, and raise `PyHaveIBeenPwnedError` when the API responds with an unexpected client error.
- Added first-class support for supplying the official HIBP API key and User-Agent headers; 401 responses now return a clear guidance message.
- Renamed the published package to lowercase `pyhaveibeenpwned` to comply with PyPI naming conventions.
- Added regression tests covering the new API surface, deprecation warnings, and error handling.
- Documented the naming changes, custom exception, and deprecation schedule in the README.
## v0.1.9 - 2024-05-01
- Last commit by sscottgvit: Update workflow
## v0.1.9 - 2024-05-01
- Last commit by sscottgvit: Update workflow
## v0.1.10 - 2024-05-01
- Last commit by sscottgvit: Update workflow
