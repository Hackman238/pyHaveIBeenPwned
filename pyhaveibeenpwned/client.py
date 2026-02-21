import warnings
from urllib.parse import quote

import requests

from .exceptions import PyHaveIBeenPwnedError
from .version import __version__


class PyHaveIBeenPwned:
    API_ENDPOINT = "https://haveibeenpwned.com/api/v3/"
    DEFAULT_TIMEOUT = 10
    DEFAULT_USER_AGENT = (
        f"pyhaveibeenpwned/{__version__} "
        "(+https://github.com/Hackman238/pyHaveIBeenPwned)"
    )
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

    def __init__(
        self,
        api_key=None,
        user_agent=None,
        scraper_factory=None,
        timeout=None,
        session=None,
    ):
        self._api_key = api_key
        self._user_agent = user_agent or self.DEFAULT_USER_AGENT
        self._timeout = self.DEFAULT_TIMEOUT if timeout is None else timeout
        if session is not None:
            self._session = session
        elif scraper_factory is not None:
            warnings.warn(
                "scraper_factory is deprecated and will be removed in a future version. "
                "Use session instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            self._session = scraper_factory()
        else:
            self._session = requests.Session()
        if self._session is None:
            self._session = requests.Session()
        self._headers = {
            "User-Agent": self._user_agent,
            "Accept": "application/json",
        }
        if self._api_key:
            self._headers["hibp-api-key"] = self._api_key

    def _raise_for_error(self, response):
        retry_after = response.headers.get("Retry-After")
        if response.status_code >= 500:
            message = self.ERROR_STRINGS["5XX"]
        elif 400 <= response.status_code < 500:
            message = self.ERROR_STRINGS.get(
                response.status_code,
                f"Unexpected client error (HTTP {response.status_code})",
            )
        else:
            return
        raise PyHaveIBeenPwnedError(
            message,
            status_code=response.status_code,
            retry_after=retry_after,
        )

    def make_scraped_request(self, url_to_fetch):
        try:
            response = self._session.get(
                url=url_to_fetch,
                headers=self._headers,
                timeout=self._timeout,
            )
        except requests.RequestException as error:
            raise PyHaveIBeenPwnedError("Unable to reach HIBP API") from error
        self._raise_for_error(response)
        try:
            return response.json()
        except ValueError as error:
            raise PyHaveIBeenPwnedError(
                "Unknown issue encountered while parsing the response payload.",
                status_code=response.status_code,
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
