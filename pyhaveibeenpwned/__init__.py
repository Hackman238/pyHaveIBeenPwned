import json
import warnings
from urllib.parse import quote

import cfscrape


class PyHaveIBeenPwnedError(Exception):
    """Raised when the API responds with an unexpected error."""


class PyHaveIBeenPwned:
    API_ENDPOINT = "https://haveibeenpwned.com/api/v2/"
    ERROR_STRINGS = {
        400: "400 - Bad request - Invalid account specified",
        401: "401 - Unauthorized - Provide a valid HIBP API key and user agent",
        403: "403 - Forbidden - Request is forbidden",
        404: "404 - Not found - No account match",
        429: (
            "429 - Rate limit exceeded - The rate limit for the API has been reached. "
            "Please try again later"
        ),
        "5XX": "5XX - Server error - The server returned an error",
    }

    def __init__(self, api_key=None, user_agent=None, scraper_factory=None):
        self._scraper = None
        self._api_key = api_key
        self._user_agent = user_agent or "pyhaveibeenpwned"
        self._scraper_factory = scraper_factory or cfscrape.create_scraper
        self._headers = {
            "User-Agent": self._user_agent,
        }
        if self._api_key:
            self._headers["hibp-api-key"] = self._api_key

    def make_scraped_request(self, url_to_fetch):
        if self._scraper is None:
            self._scraper = self._scraper_factory()
        response = self._scraper.get(url=url_to_fetch, headers=self._headers)
        if response.status_code >= 500:
            return self.ERROR_STRINGS["5XX"]
        if 400 <= response.status_code < 500:
            if response.status_code in self.ERROR_STRINGS:
                return self.ERROR_STRINGS[response.status_code]
            raise PyHaveIBeenPwnedError(
                f"Unknown issue encountered (HTTP {response.status_code})"
            )
        try:
            return response.json()
        except json.JSONDecodeError as error:
            raise PyHaveIBeenPwnedError(
                "Unknown issue encountered while parsing the response payload."
            ) from error

    def get_account_breaches(self, email, domain=None):
        url_endpoint = "breachedaccount/"
        encoded_email = quote(email, safe="")
        url = f"{self.API_ENDPOINT}{url_endpoint}{encoded_email}"
        if domain:
            url += f"?domain={quote(domain, safe='')}"
        return self.make_scraped_request(url)

    def get_domain_breaches(self, domain):
        url_endpoint = "breaches/"
        url = f"{self.API_ENDPOINT}{url_endpoint}?domain={quote(domain, safe='')}"
        return self.make_scraped_request(url)

    def get_domain_breach(self, name):
        url_endpoint = "breach/"
        url = f"{self.API_ENDPOINT}{url_endpoint}{quote(name, safe='')}"
        return self.make_scraped_request(url)

    def get_data_classes(self):
        url_endpoint = "dataclasses/"
        url = f"{self.API_ENDPOINT}{url_endpoint}"
        return self.make_scraped_request(url)

    def get_account_pastes(self, email):
        url_endpoint = "pasteaccount/"
        encoded_email = quote(email, safe="")
        url = f"{self.API_ENDPOINT}{url_endpoint}{encoded_email}"
        return self.make_scraped_request(url)

    def test_me(self):
        return self.get_account_breaches("foo@bar.com")

    def makeScrapedRequest(self, urlToFetch):  # noqa: N802
        warnings.warn(
            "makeScrapedRequest is deprecated and will be removed in a future version. "
            "Use make_scraped_request instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.make_scraped_request(urlToFetch)

    def getAccountBreaches(self, email, domain=None):  # noqa: N802
        warnings.warn(
            "getAccountBreaches is deprecated and will be removed in a future version. "
            "Use get_account_breaches instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.get_account_breaches(email, domain=domain)

    def getDomainBreaches(self, domain):  # noqa: N802
        warnings.warn(
            "getDomainBreaches is deprecated and will be removed in a future version. "
            "Use get_domain_breaches instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.get_domain_breaches(domain)

    def getDomainBreach(self, name):  # noqa: N802
        warnings.warn(
            "getDomainBreach is deprecated and will be removed in a future version. "
            "Use get_domain_breach instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.get_domain_breach(name)

    def getDataClasses(self):  # noqa: N802
        warnings.warn(
            "getDataClasses is deprecated and will be removed in a future version. "
            "Use get_data_classes instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.get_data_classes()

    def getAccountPastes(self, email):  # noqa: N802
        warnings.warn(
            "getAccountPastes is deprecated and will be removed in a future version. "
            "Use get_account_pastes instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.get_account_pastes(email)

    def testMe(self):  # noqa: N802
        warnings.warn(
            "testMe is deprecated and will be removed in a future version. Use test_me instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.test_me()


if __name__ == "__main__":
    instance = PyHaveIBeenPwned()
    results = instance.test_me()
    print(results)
