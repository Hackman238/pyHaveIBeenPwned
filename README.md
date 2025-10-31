pyhaveibeenpwned (https://shanewilliamscott.com)
==
[![Python package](https://github.com/Hackman238/pyHaveIBeenPwned/actions/workflows/master.yml/badge.svg)](https://github.com/Hackman238/pyHaveIBeenPwned/actions/workflows/master.yml)
[![Known Vulnerabilities](https://snyk.io/test/github/Hackman238/pyHaveIBeenPwned/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/Hackman238/pyHaveIBeenPwned?targetFile=requirements.txt)

## Authors:
Shane Scott

## About pyhaveibeenpwned
Python library to query HaveIBeenPwned.com with handling for CloudFlare anti-bot.

## Installation
pip3 install pyhaveibeenpwned

## Usage
```python
from pyhaveibeenpwned import PyHaveIBeenPwned, PyHaveIBeenPwnedError

client = PyHaveIBeenPwned(
    api_key="your-hibp-api-key",
    user_agent="my-company-app/1.0",
)

try:
    breaches = client.get_account_breaches("user@example.com")
except PyHaveIBeenPwnedError as exc:
    print(f"API error: {exc}")
```

> **Note:** HaveIBeenPwned requires both a valid API key and a descriptive User-Agent header for authenticated endpoints. The helper automatically adds these headers to every request.

## Deprecations
Release 0.2 moves all public methods to snake_case to comply with PEP 8. Legacy camelCase helpers remain available for now and emit `DeprecationWarning`; update your code to use the new names before the next major release.

## Credits
Based on fork from https://github.com/GoVanguard/pyExploitDb by Shane Scott.
