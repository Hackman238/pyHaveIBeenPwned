import importlib
import sys
import types
import unittest
import warnings


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class FakeScraper:
    def __init__(self, response):
        self.response = response
        self.urls = []
        self.headers = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        self.headers.append(kwargs.get("headers"))
        return self.response

    def reset(self, response):
        self.response = response
        self.urls.clear()
        self.headers.clear()


class TestPyHaveIBeenPwned(unittest.TestCase):
    module_name = "pyhaveibeenpwned"

    def setUp(self):
        response = FakeResponse(200, {"status": "ok"})
        self.fake_scraper = FakeScraper(response)
        sys.modules["cfscrape"] = types.SimpleNamespace(create_scraper=lambda: self.fake_scraper)
        module = importlib.import_module(self.module_name)
        self.module = importlib.reload(module)
        self.instance = self.module.PyHaveIBeenPwned(api_key="test-key", user_agent="test-agent")

    def tearDown(self):
        sys.modules.pop("cfscrape", None)

    def test_get_account_breaches_returns_payload(self):
        email = "user@example.com"

        result = self.instance.get_account_breaches(email)

        expected_url = (
            f"{self.module.PyHaveIBeenPwned.API_ENDPOINT}"
            f"breachedaccount/user%40example.com"
        )
        self.assertEqual(self.fake_scraper.urls, [expected_url])
        self.assertEqual(result, {"status": "ok"})
        self.assertEqual(
            self.fake_scraper.headers,
            [{"User-Agent": "test-agent", "hibp-api-key": "test-key"}],
        )

    def test_deprecated_alias_emits_warning(self):
        email = "user@example.com"
        self.fake_scraper.urls.clear()

        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", DeprecationWarning)
            result = self.instance.getAccountBreaches(email)

        self.assertTrue(
            any(item.category is DeprecationWarning for item in captured),
            "Expected a DeprecationWarning from getAccountBreaches",
        )
        expected_url = (
            f"{self.module.PyHaveIBeenPwned.API_ENDPOINT}"
            f"breachedaccount/user%40example.com"
        )
        self.assertEqual(self.fake_scraper.urls, [expected_url])
        self.assertEqual(result, {"status": "ok"})

    def test_unknown_client_error_raises_custom_exception(self):
        self.fake_scraper.reset(FakeResponse(451, {}))

        with self.assertRaises(self.module.PyHaveIBeenPwnedError) as context:
            self.instance.get_account_breaches("user@example.com")

        self.assertIn("Unknown issue encountered", str(context.exception))

    def test_unauthorized_returns_helpful_message(self):
        self.fake_scraper.reset(FakeResponse(401, {}))

        result = self.instance.get_account_breaches("user@example.com")

        self.assertEqual(
            result, self.module.PyHaveIBeenPwned.ERROR_STRINGS[401]
        )


if __name__ == "__main__":
    unittest.main()
