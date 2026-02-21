import json
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

import requests

from pyhaveibeenpwned import PyHaveIBeenPwned, PyHaveIBeenPwnedError, __version__
from pyhaveibeenpwned.version import __version__ as version_module_version


class FakeResponse:
    def __init__(self, status_code, payload, headers=None, json_error=None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise self._json_error
        return self._payload


class FakeSession:
    def __init__(self, response, exception=None):
        self.response = response
        self.exception = exception
        self.urls = []
        self.headers = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        self.headers.append(kwargs.get("headers"))
        if self.exception:
            raise self.exception
        return self.response

    def reset(self, response=None, exception=None):
        if response is not None:
            self.response = response
        self.exception = exception
        self.urls.clear()
        self.headers.clear()


class TestPyHaveIBeenPwned(unittest.TestCase):
    def setUp(self):
        response = FakeResponse(200, {"status": "ok"})
        self.fake_session = FakeSession(response)
        self.instance = PyHaveIBeenPwned(
            api_key="test-key",
            user_agent="test-agent",
            session=self.fake_session,
        )
        self.version_file = Path(__file__).resolve().parents[1] / "pyhaveibeenpwned" / "VERSION"

    def test_get_account_breaches_returns_payload(self):
        result = self.instance.get_account_breaches("user@example.com")

        expected_url = f"{PyHaveIBeenPwned.API_ENDPOINT}breachedaccount/user%40example.com"
        self.assertEqual(self.fake_session.urls, [expected_url])
        self.assertEqual(result, {"status": "ok"})
        self.assertEqual(
            self.fake_session.headers,
            [
                {
                    "User-Agent": "test-agent",
                    "Accept": "application/json",
                    "hibp-api-key": "test-key",
                }
            ],
        )

    def test_package_exposes_version_from_version_file(self):
        expected_version = self.version_file.read_text(encoding="utf-8").strip()

        self.assertEqual(__version__, expected_version)
        self.assertEqual(version_module_version, expected_version)

    def test_get_account_breaches_supports_domain_filter(self):
        result = self.instance.get_account_breaches("user@example.com", domain="example.com")

        expected_url = (
            f"{PyHaveIBeenPwned.API_ENDPOINT}"
            "breachedaccount/user%40example.com?domain=example.com"
        )
        self.assertEqual(self.fake_session.urls, [expected_url])
        self.assertEqual(result, {"status": "ok"})

    def test_endpoint_helpers_build_expected_urls(self):
        domain_breaches = self.instance.get_domain_breaches("example.com")
        domain_breach = self.instance.get_domain_breach("example-breach")
        data_classes = self.instance.get_data_classes()
        account_pastes = self.instance.get_account_pastes("user@example.com")
        test_me = self.instance.test_me()

        expected_urls = [
            f"{PyHaveIBeenPwned.API_ENDPOINT}breaches/?domain=example.com",
            f"{PyHaveIBeenPwned.API_ENDPOINT}breach/example-breach",
            f"{PyHaveIBeenPwned.API_ENDPOINT}dataclasses/",
            f"{PyHaveIBeenPwned.API_ENDPOINT}pasteaccount/user%40example.com",
            f"{PyHaveIBeenPwned.API_ENDPOINT}breachedaccount/foo%40bar.com",
        ]
        self.assertEqual(self.fake_session.urls, expected_urls)
        self.assertEqual(domain_breaches, {"status": "ok"})
        self.assertEqual(domain_breach, {"status": "ok"})
        self.assertEqual(data_classes, {"status": "ok"})
        self.assertEqual(account_pastes, {"status": "ok"})
        self.assertEqual(test_me, {"status": "ok"})

    def test_deprecated_scraper_factory_still_works(self):
        custom_session = FakeSession(FakeResponse(200, {"status": "custom"}))
        factory_calls = []

        def scraper_factory():
            factory_calls.append("called")
            return custom_session

        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", DeprecationWarning)
            instance = PyHaveIBeenPwned(
                api_key="custom-key",
                user_agent="custom-agent",
                scraper_factory=scraper_factory,
            )

        result = instance.get_data_classes()

        self.assertEqual(factory_calls, ["called"])
        self.assertTrue(
            any(item.category is DeprecationWarning for item in captured),
            "Expected a DeprecationWarning when passing scraper_factory",
        )
        self.assertEqual(
            custom_session.urls,
            [f"{PyHaveIBeenPwned.API_ENDPOINT}dataclasses/"],
        )
        self.assertEqual(
            custom_session.headers,
            [
                {
                    "User-Agent": "custom-agent",
                    "Accept": "application/json",
                    "hibp-api-key": "custom-key",
                }
            ],
        )
        self.assertEqual(result, {"status": "custom"})

    def test_explicit_session_wins_over_scraper_factory(self):
        explicit_session = FakeSession(FakeResponse(200, {"status": "explicit"}))
        factory_calls = []

        def scraper_factory():
            factory_calls.append("called")
            return FakeSession(FakeResponse(200, {"status": "factory"}))

        instance = PyHaveIBeenPwned(
            api_key="k",
            user_agent="ua",
            session=explicit_session,
            scraper_factory=scraper_factory,
        )
        result = instance.get_data_classes()

        self.assertEqual(result, {"status": "explicit"})
        self.assertEqual(factory_calls, [])
        self.assertEqual(
            explicit_session.urls,
            [f"{PyHaveIBeenPwned.API_ENDPOINT}dataclasses/"],
        )

    def test_default_user_agent_is_applied(self):
        instance = PyHaveIBeenPwned(api_key="test-key", session=self.fake_session)
        self.fake_session.reset(FakeResponse(200, {"status": "ok"}))

        instance.get_data_classes()

        self.assertEqual(
            self.fake_session.headers[0]["User-Agent"],
            PyHaveIBeenPwned.DEFAULT_USER_AGENT,
        )

    def test_default_requests_session_is_used_when_session_not_provided(self):
        fallback_session = FakeSession(FakeResponse(200, {"status": "fallback"}))
        with patch("pyhaveibeenpwned.client.requests.Session", return_value=fallback_session):
            instance = PyHaveIBeenPwned(api_key="k", user_agent="ua")

        result = instance.get_data_classes()

        self.assertEqual(result, {"status": "fallback"})
        self.assertEqual(
            fallback_session.urls,
            [f"{PyHaveIBeenPwned.API_ENDPOINT}dataclasses/"],
        )

    def test_scraper_factory_none_falls_back_to_requests_session(self):
        fallback_session = FakeSession(FakeResponse(200, {"status": "fallback"}))
        with patch("pyhaveibeenpwned.client.requests.Session", return_value=fallback_session):
            with warnings.catch_warnings(record=True) as captured:
                warnings.simplefilter("always", DeprecationWarning)
                instance = PyHaveIBeenPwned(
                    api_key="k",
                    user_agent="ua",
                    scraper_factory=lambda: None,
                )

        result = instance.get_data_classes()

        self.assertTrue(
            any(item.category is DeprecationWarning for item in captured),
            "Expected a DeprecationWarning when passing scraper_factory",
        )
        self.assertEqual(result, {"status": "fallback"})

    def test_deprecated_alias_emits_warning(self):
        self.fake_session.urls.clear()

        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", DeprecationWarning)
            result = self.instance.getAccountBreaches("user@example.com")

        self.assertTrue(
            any(item.category is DeprecationWarning for item in captured),
            "Expected a DeprecationWarning from getAccountBreaches",
        )
        expected_url = f"{PyHaveIBeenPwned.API_ENDPOINT}breachedaccount/user%40example.com"
        self.assertEqual(self.fake_session.urls, [expected_url])
        self.assertEqual(result, {"status": "ok"})

    def test_unknown_client_error_raises_custom_exception(self):
        self.fake_session.reset(FakeResponse(451, {}))

        with self.assertRaises(PyHaveIBeenPwnedError) as context:
            self.instance.get_account_breaches("user@example.com")

        self.assertIn("Unexpected client error", str(context.exception))

    def test_unauthorized_raises_with_message(self):
        self.fake_session.reset(FakeResponse(401, {}))

        with self.assertRaises(PyHaveIBeenPwnedError) as context:
            self.instance.get_account_breaches("user@example.com")

        self.assertEqual(str(context.exception), PyHaveIBeenPwned.ERROR_STRINGS[401])

    def test_rate_limit_raises_and_exposes_retry_after(self):
        self.fake_session.reset(FakeResponse(429, {}, headers={"Retry-After": "5"}))

        with self.assertRaises(PyHaveIBeenPwnedError) as context:
            self.instance.get_account_breaches("user@example.com")

        self.assertEqual(context.exception.retry_after, "5")
        self.assertIn("Rate limit exceeded", str(context.exception))

    def test_server_error_raises_custom_exception(self):
        self.fake_session.reset(FakeResponse(503, {}))

        with self.assertRaises(PyHaveIBeenPwnedError) as context:
            self.instance.get_account_breaches("user@example.com")

        self.assertEqual(context.exception.status_code, 503)
        self.assertIn("Server error", str(context.exception))

    def test_json_decode_error_raises_custom_exception(self):
        decode_error = json.JSONDecodeError("msg", "doc", 0)
        self.fake_session.reset(FakeResponse(200, {}, json_error=decode_error))

        with self.assertRaises(PyHaveIBeenPwnedError) as context:
            self.instance.get_account_breaches("user@example.com")

        self.assertIsNone(context.exception.retry_after)
        self.assertEqual(context.exception.status_code, 200)
        self.assertIn("parsing the response payload", str(context.exception))

    def test_request_error_is_wrapped(self):
        self.fake_session.reset(exception=requests.RequestException("boom"))

        with self.assertRaises(PyHaveIBeenPwnedError) as context:
            self.instance.get_account_breaches("user@example.com")

        self.assertIn("Unable to reach HIBP API", str(context.exception))

    def test_make_scraped_request_alias_emits_warning(self):
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", DeprecationWarning)
            result = self.instance.makeScrapedRequest("https://example.com/resource")

        self.assertTrue(
            any(item.category is DeprecationWarning for item in captured),
            "Expected a DeprecationWarning from makeScrapedRequest",
        )
        self.assertEqual(self.fake_session.urls, ["https://example.com/resource"])
        self.assertEqual(result, {"status": "ok"})

    def test_remaining_deprecated_aliases_emit_warning(self):
        cases = [
            (
                "getDomainBreaches",
                ("example.com",),
                f"{PyHaveIBeenPwned.API_ENDPOINT}breaches/?domain=example.com",
            ),
            (
                "getDomainBreach",
                ("example-breach",),
                f"{PyHaveIBeenPwned.API_ENDPOINT}breach/example-breach",
            ),
            (
                "getDataClasses",
                tuple(),
                f"{PyHaveIBeenPwned.API_ENDPOINT}dataclasses/",
            ),
            (
                "getAccountPastes",
                ("user@example.com",),
                f"{PyHaveIBeenPwned.API_ENDPOINT}pasteaccount/user%40example.com",
            ),
            (
                "testMe",
                tuple(),
                f"{PyHaveIBeenPwned.API_ENDPOINT}breachedaccount/foo%40bar.com",
            ),
        ]

        for method_name, args, expected_url in cases:
            self.fake_session.reset(FakeResponse(200, {"alias": method_name}))

            with warnings.catch_warnings(record=True) as captured:
                warnings.simplefilter("always", DeprecationWarning)
                result = getattr(self.instance, method_name)(*args)

            self.assertTrue(
                any(item.category is DeprecationWarning for item in captured),
                f"Expected a DeprecationWarning from {method_name}",
            )
            self.assertEqual(self.fake_session.urls, [expected_url])
            self.assertEqual(result, {"alias": method_name})


if __name__ == "__main__":
    unittest.main()
