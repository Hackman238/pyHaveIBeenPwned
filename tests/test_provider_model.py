import unittest

import requests

from pyhaveibeenpwned.exceptions import PyHaveIBeenPwnedError
from pyhaveibeenpwned.models import ProviderResult, SearchRequest
from pyhaveibeenpwned.orchestrator import BreachLookupClient
from pyhaveibeenpwned.provider_registry import list_providers, register_provider
from pyhaveibeenpwned.providers.base import BaseProvider
from pyhaveibeenpwned.providers.dehashed import DeHashedProvider
from pyhaveibeenpwned.providers.haveibeenpwned import HaveIBeenPwnedProvider


class FakeHIBPClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def get_account_breaches(self, email, domain=None):
        return [{"Name": "ExampleBreach", "Email": email, "Domain": domain}]

    def get_account_pastes(self, email):
        return [{"Source": "Pastebin", "Email": email}]

    def get_data_classes(self):
        return ["Email addresses", "Passwords"]


class FakeHTTPResponse:
    def __init__(self, status_code, payload, headers=None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = str(payload)

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("get", url, kwargs))
        return self.response

    def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        return self.response


class RaisingSession:
    def post(self, url, **kwargs):
        raise requests.RequestException("boom")


class BadJsonResponse(FakeHTTPResponse):
    def json(self):
        raise ValueError("bad json")


class FakeClock:
    def __init__(self, start=0.0):
        self.now = start
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class TestProviderModel(unittest.TestCase):
    def test_search_request_normalizes_inputs(self):
        request = SearchRequest(
            target_email="user@example.com",
            providers=["HaveIBeenPwned", "DEHASHED"],
            credentials_by_provider={
                "HaveIBeenPwned": {"api_key": "hibp-key"},
                "DEHASHED": {"api_key": "dehashed-key", "account_email": "acct@example.com"},
            },
            criteria_by_provider={"HaveIBeenPwned": {"domain": "example.com"}},
        )

        self.assertEqual(request.providers, ["haveibeenpwned", "dehashed"])
        self.assertEqual(
            request.get_credentials("haveibeenpwned").api_key,
            "hibp-key",
        )
        self.assertEqual(
            request.get_credentials("dehashed").account_email,
            "acct@example.com",
        )
        self.assertEqual(
            request.get_criteria("haveibeenpwned"),
            {"domain": "example.com"},
        )

    def test_haveibeenpwned_provider_search(self):
        created_clients = []

        def client_factory(**kwargs):
            client = FakeHIBPClient(**kwargs)
            created_clients.append(client)
            return client

        provider = HaveIBeenPwnedProvider(client_factory=client_factory)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={
                "haveibeenpwned": {"api_key": "hibp-key", "user_agent": "test-agent/1.0"}
            },
            criteria_by_provider={
                "haveibeenpwned": {
                    "domain": "example.com",
                    "include_pastes": True,
                    "include_data_classes": True,
                }
            },
            timeout=20,
        )

        result = provider.search(request)

        self.assertTrue(result.ok)
        self.assertEqual(result.provider, "haveibeenpwned")
        self.assertGreaterEqual(len(result.findings), 3)
        self.assertEqual(created_clients[0].kwargs["api_key"], "hibp-key")
        self.assertEqual(created_clients[0].kwargs["user_agent"], "test-agent/1.0")
        self.assertEqual(created_clients[0].kwargs["timeout"], 20)
        self.assertIn("breaches", result.raw)
        self.assertIn("pastes", result.raw)
        self.assertIn("data_classes", result.raw)

    def test_haveibeenpwned_provider_requires_api_key(self):
        provider = HaveIBeenPwnedProvider(client_factory=FakeHIBPClient)
        request = SearchRequest(target_email="user@example.com")

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertIn("requires an api_key", result.error)

    def test_haveibeenpwned_provider_requires_email(self):
        provider = HaveIBeenPwnedProvider(client_factory=FakeHIBPClient)
        request = SearchRequest(
            credentials_by_provider={"haveibeenpwned": {"api_key": "hibp-key"}}
        )

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertIn("requires target_email", result.error)

    def test_haveibeenpwned_provider_handles_provider_exception(self):
        class FailingHIBPClient(FakeHIBPClient):
            def get_account_breaches(self, email, domain=None):
                raise PyHaveIBeenPwnedError("boom", status_code=503, retry_after="3")

        provider = HaveIBeenPwnedProvider(client_factory=FailingHIBPClient)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"haveibeenpwned": {"api_key": "hibp-key"}},
        )

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.retry_after, "3")

    def test_haveibeenpwned_provider_preserves_partial_findings_on_optional_failure(self):
        class PartialFailingHIBPClient(FakeHIBPClient):
            def get_account_pastes(self, email):
                raise PyHaveIBeenPwnedError("rate-limited", status_code=429, retry_after="2")

        provider = HaveIBeenPwnedProvider(client_factory=PartialFailingHIBPClient)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"haveibeenpwned": {"api_key": "hibp-key"}},
            criteria_by_provider={"haveibeenpwned": {"include_pastes": True}},
        )

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertEqual(result.status_code, 429)
        self.assertEqual(result.retry_after, "2")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].identifier, "ExampleBreach")
        self.assertIn("breaches", result.raw)

    def test_haveibeenpwned_provider_treats_optional_404_as_empty(self):
        class OptionalNotFoundHIBPClient(FakeHIBPClient):
            def get_account_pastes(self, email):
                raise PyHaveIBeenPwnedError("not found", status_code=404)

        provider = HaveIBeenPwnedProvider(client_factory=OptionalNotFoundHIBPClient)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"haveibeenpwned": {"api_key": "hibp-key"}},
            criteria_by_provider={"haveibeenpwned": {"include_pastes": True}},
        )

        result = provider.search(request)

        self.assertTrue(result.ok)
        self.assertIsNone(result.status_code)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].identifier, "ExampleBreach")
        self.assertEqual(result.raw["pastes"], [])

    def test_haveibeenpwned_provider_treats_breach_404_as_empty(self):
        class BreachNotFoundHIBPClient(FakeHIBPClient):
            def get_account_breaches(self, email, domain=None):
                raise PyHaveIBeenPwnedError("not found", status_code=404)

        provider = HaveIBeenPwnedProvider(client_factory=BreachNotFoundHIBPClient)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"haveibeenpwned": {"api_key": "hibp-key"}},
            criteria_by_provider={"haveibeenpwned": {"include_pastes": True}},
        )

        result = provider.search(request)

        self.assertTrue(result.ok)
        self.assertIsNone(result.status_code)
        self.assertIsNone(result.error)
        self.assertEqual(result.raw["breaches"], [])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].category, "paste")

    def test_haveibeenpwned_provider_treats_data_classes_404_as_empty(self):
        class DataClassesNotFoundHIBPClient(FakeHIBPClient):
            def get_data_classes(self):
                raise PyHaveIBeenPwnedError("not found", status_code=404)

        provider = HaveIBeenPwnedProvider(client_factory=DataClassesNotFoundHIBPClient)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"haveibeenpwned": {"api_key": "hibp-key"}},
            criteria_by_provider={"haveibeenpwned": {"include_data_classes": True}},
        )

        result = provider.search(request)

        self.assertTrue(result.ok)
        self.assertEqual(result.raw["data_classes"], [])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].category, "breach")

    def test_haveibeenpwned_provider_fails_when_data_classes_non_404_error(self):
        class DataClassesFailingHIBPClient(FakeHIBPClient):
            def get_data_classes(self):
                raise PyHaveIBeenPwnedError("boom", status_code=503, retry_after="9")

        provider = HaveIBeenPwnedProvider(client_factory=DataClassesFailingHIBPClient)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"haveibeenpwned": {"api_key": "hibp-key"}},
            criteria_by_provider={"haveibeenpwned": {"include_data_classes": True}},
        )

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.retry_after, "9")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].category, "breach")

    def test_haveibeenpwned_provider_applies_default_queries_per_second(self):
        clock = FakeClock(start=100.0)
        provider = HaveIBeenPwnedProvider(
            client_factory=FakeHIBPClient,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"haveibeenpwned": {"api_key": "hibp-key"}},
            criteria_by_provider={
                "haveibeenpwned": {
                    "include_pastes": True,
                    "include_data_classes": True,
                }
            },
        )

        result = provider.search(request)

        self.assertTrue(result.ok)
        self.assertEqual(len(clock.sleeps), 2)
        self.assertAlmostEqual(clock.sleeps[0], 0.2, places=6)
        self.assertAlmostEqual(clock.sleeps[1], 0.2, places=6)

    def test_haveibeenpwned_provider_uses_custom_queries_per_second(self):
        clock = FakeClock(start=100.0)
        provider = HaveIBeenPwnedProvider(
            client_factory=FakeHIBPClient,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"haveibeenpwned": {"api_key": "hibp-key"}},
            criteria_by_provider={
                "haveibeenpwned": {
                    "include_pastes": True,
                    "queries_per_second": 2,
                }
            },
        )

        result = provider.search(request)

        self.assertTrue(result.ok)
        self.assertEqual(len(clock.sleeps), 1)
        self.assertAlmostEqual(clock.sleeps[0], 0.5, places=6)

    def test_haveibeenpwned_provider_rejects_invalid_queries_per_second(self):
        provider = HaveIBeenPwnedProvider(client_factory=FakeHIBPClient)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"haveibeenpwned": {"api_key": "hibp-key"}},
            criteria_by_provider={
                "haveibeenpwned": {"queries_per_second": 0}
            },
        )

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertIn("queries_per_second must be greater than 0", result.error)

    def test_haveibeenpwned_provider_rejects_non_numeric_queries_per_second(self):
        provider = HaveIBeenPwnedProvider(client_factory=FakeHIBPClient)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"haveibeenpwned": {"api_key": "hibp-key"}},
            criteria_by_provider={
                "haveibeenpwned": {"queries_per_second": "fast"}
            },
        )

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertIn("queries_per_second must be a number", result.error)

    def test_haveibeenpwned_normalize_items_non_list(self):
        findings = HaveIBeenPwnedProvider._normalize_items("haveibeenpwned", "breach", {})

        self.assertEqual(findings, [])

    def test_dehashed_provider_search(self):
        fake_payload = {"entries": [{"email": "user@example.com", "password": "secret"}]}
        session = FakeSession(FakeHTTPResponse(200, fake_payload))
        provider = DeHashedProvider(session=session)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={
                "dehashed": {
                    "api_key": "dehashed-key",
                    "user_agent": "test-agent/1.0",
                }
            },
            criteria_by_provider={
                "dehashed": {
                    "page": 2,
                    "size": 50,
                    "regex": False,
                    "wildcard": False,
                    "de_dupe": True,
                }
            },
            timeout=15,
        )

        result = provider.search(request)

        self.assertTrue(result.ok)
        self.assertEqual(result.provider, "dehashed")
        self.assertEqual(result.findings[0].identifier, "user@example.com")
        self.assertEqual(session.calls[0][0], "post")
        self.assertEqual(session.calls[0][1], DeHashedProvider.API_ENDPOINT)
        self.assertEqual(session.calls[0][2]["json"]["query"], "email:user@example.com")
        self.assertEqual(session.calls[0][2]["json"]["page"], 2)
        self.assertEqual(session.calls[0][2]["json"]["size"], 50)
        self.assertEqual(session.calls[0][2]["json"]["regex"], False)
        self.assertEqual(session.calls[0][2]["json"]["wildcard"], False)
        self.assertEqual(session.calls[0][2]["json"]["de_dupe"], True)
        self.assertEqual(session.calls[0][2]["headers"]["DeHashed-Api-Key"], "dehashed-key")
        self.assertEqual(session.calls[0][2]["timeout"], 15)

    def test_dehashed_provider_applies_v2_defaults(self):
        fake_payload = {"entries": [{"email": "user@example.com"}]}
        session = FakeSession(FakeHTTPResponse(200, fake_payload))
        provider = DeHashedProvider(session=session)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"dehashed": {"api_key": "dehashed-key"}},
        )

        result = provider.search(request)

        self.assertTrue(result.ok)
        body = session.calls[0][2]["json"]
        self.assertEqual(body["query"], "email:user@example.com")
        self.assertEqual(body["page"], 1)
        self.assertEqual(body["size"], 25)
        self.assertFalse(body["regex"])
        self.assertFalse(body["wildcard"])
        self.assertFalse(body["de_dupe"])

    def test_dehashed_provider_requires_api_key(self):
        session = FakeSession(FakeHTTPResponse(200, {"entries": []}))
        provider = DeHashedProvider(session=session)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"dehashed": {}},
        )

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertIn("requires an api_key", result.error)

    def test_dehashed_provider_requires_target_or_query(self):
        session = FakeSession(FakeHTTPResponse(200, {"entries": []}))
        provider = DeHashedProvider(session=session)
        request = SearchRequest(
            credentials_by_provider={
                "dehashed": {"api_key": "dehashed-key"}
            }
        )

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertIn("requires target_email or criteria query", result.error)

    def test_dehashed_provider_handles_request_exception(self):
        provider = DeHashedProvider(session=RaisingSession())
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"dehashed": {"api_key": "dehashed-key"}},
        )

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertIn("Unable to reach dehashed API", result.error)

    def test_dehashed_provider_handles_error_response_and_bad_json(self):
        session = FakeSession(BadJsonResponse(429, payload={}, headers={"Retry-After": "5"}))
        provider = DeHashedProvider(session=session)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"dehashed": {"api_key": "dehashed-key"}},
        )

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertEqual(result.status_code, 429)
        self.assertEqual(result.retry_after, "5")
        self.assertIn("dehashed request failed", result.error)
        self.assertIn("raw_text", result.raw)

    def test_dehashed_provider_handles_error_response_with_message(self):
        session = FakeSession(FakeHTTPResponse(401, {"message": "Invalid credentials"}))
        provider = DeHashedProvider(session=session)
        request = SearchRequest(
            target_email="user@example.com",
            credentials_by_provider={"dehashed": {"api_key": "dehashed-key"}},
        )

        result = provider.search(request)

        self.assertFalse(result.ok)
        self.assertEqual(result.error, "Invalid credentials")

    def test_dehashed_provider_normalization_non_dict_entry(self):
        findings = DeHashedProvider._normalize_entries({"entries": ["raw-entry"]})

        self.assertEqual(findings[0].identifier, "raw-entry")
        self.assertEqual(findings[0].attributes, {"value": "raw-entry"})

    def test_dehashed_provider_normalization_nested_data_entries(self):
        findings = DeHashedProvider._normalize_entries(
            {"data": {"entries": [{"email": "nested@example.com"}]}}
        )

        self.assertEqual(findings[0].identifier, "nested@example.com")

    def test_dehashed_provider_normalization_data_list(self):
        findings = DeHashedProvider._normalize_entries(
            {"data": [{"email": "list@example.com"}]}
        )

        self.assertEqual(findings[0].identifier, "list@example.com")

    def test_dehashed_provider_normalization_unsupported_payload(self):
        self.assertEqual(DeHashedProvider._normalize_entries("not-a-dict"), [])
        self.assertEqual(DeHashedProvider._normalize_entries({"balance": 10}), [])

    def test_provider_credentials_from_value_paths(self):
        from pyhaveibeenpwned.models import ProviderCredentials

        self.assertEqual(ProviderCredentials.from_value(None), ProviderCredentials())

        credentials = ProviderCredentials(api_key="a")
        self.assertIs(ProviderCredentials.from_value(credentials), credentials)

        mapped = ProviderCredentials.from_value(
            {"email": "acct@example.com", "api_key": "k", "extras": None, "region": "us"}
        )
        self.assertEqual(mapped.account_email, "acct@example.com")
        self.assertEqual(mapped.extras, {"region": "us"})

        with self.assertRaises(TypeError):
            ProviderCredentials.from_value("bad-type")

    def test_orchestrator_multi_provider_and_unknown_provider(self):
        class OkProvider(BaseProvider):
            name = "unit-ok-provider"

            def validate_request(self, request):
                return None

            def search(self, request):
                return ProviderResult(provider=self.name, ok=True)

        register_provider(OkProvider.name, OkProvider)
        client = BreachLookupClient(default_providers=[OkProvider.name])
        ok_request = SearchRequest(target_email="user@example.com")
        ok_response = client.search(ok_request)

        self.assertIn(OkProvider.name, ok_response.results)
        self.assertTrue(ok_response.results[OkProvider.name].ok)

        unknown_request = SearchRequest(
            target_email="user@example.com",
            providers=["does-not-exist-provider"],
        )
        unknown_response = client.search(unknown_request)

        self.assertFalse(unknown_response.results["does-not-exist-provider"].ok)
        self.assertIn("Unknown provider", unknown_response.results["does-not-exist-provider"].error)

    def test_list_providers_includes_defaults(self):
        providers = list_providers()

        self.assertIn("haveibeenpwned", providers)
        self.assertIn("dehashed", providers)


if __name__ == "__main__":
    unittest.main()
