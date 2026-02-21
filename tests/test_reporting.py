import unittest

from pyhaveibeenpwned.models import Finding, ProviderResult, SearchRequest, SearchResponse
from pyhaveibeenpwned.reporting import _non_empty_keys, build_consolidated_report


class TestReporting(unittest.TestCase):
    def test_non_empty_keys_handles_non_dict(self):
        self.assertEqual(_non_empty_keys("not-a-dict"), [])

    def test_build_consolidated_report_combines_provider_data(self):
        request = SearchRequest(
            target_email="user@example.com",
            providers=["dehashed", "haveibeenpwned"],
        )
        response = SearchResponse(
            results={
                "dehashed": ProviderResult(
                    provider="dehashed",
                    ok=True,
                    findings=[
                        Finding(
                            provider="dehashed",
                            category="leak_record",
                            identifier="['user@example.com']",
                            attributes={
                                "id": "abc123",
                                "email": ["user@example.com"],
                                "username": "example_user",
                                "password": "secret",
                                "database_name": "combo_db",
                                "ip_address": "1.2.3.4",
                                "empty_field": "",
                            },
                        )
                    ],
                ),
                "haveibeenpwned": ProviderResult(
                    provider="haveibeenpwned",
                    ok=True,
                    findings=[
                        Finding(
                            provider="haveibeenpwned",
                            category="breach",
                            identifier="LinkedIn",
                            attributes={
                                "Name": "LinkedIn",
                                "Title": "LinkedIn",
                                "Domain": "linkedin.com",
                                "BreachDate": "2012-05-05",
                                "PwnCount": 12345,
                                "DataClasses": ["Email addresses", "Passwords"],
                                "Description": "Example leak",
                                "LogoPath": "https://example.com/logo.png",
                                "IsVerified": True,
                            },
                        )
                    ],
                ),
            }
        )

        report = build_consolidated_report(
            request,
            response,
            generated_at="2026-02-21T00:00:00Z",
        )

        self.assertEqual(report["schema_version"], "1.0.0")
        self.assertEqual(report["generated_at"], "2026-02-21T00:00:00Z")
        self.assertEqual(report["target_email"], "user@example.com")
        self.assertEqual(report["scope"]["total_findings"], 2)
        self.assertEqual(report["scope"]["accounts_with_hits"], 1)
        self.assertEqual(report["scope"]["provider_hit_counts"]["dehashed"], 1)
        self.assertEqual(report["scope"]["provider_hit_counts"]["haveibeenpwned"], 1)
        self.assertEqual(report["scope"]["unique_hibp_breaches"], ["LinkedIn"])
        self.assertEqual(
            report["scope"]["hibp_leaked_data_classes"],
            ["Email addresses", "Passwords"],
        )
        self.assertIn("password", report["scope"]["dehashed_leaked_fields"])

        account_hit = report["account_hits"][0]
        self.assertEqual(account_hit["account"], "user@example.com")
        self.assertEqual(account_hit["providers"]["dehashed"]["hit_count"], 1)
        self.assertEqual(account_hit["providers"]["haveibeenpwned"]["hit_count"], 1)

        dehashed_finding = account_hit["providers"]["dehashed"]["findings"][0]
        self.assertEqual(dehashed_finding["scope"]["source"], "combo_db")
        self.assertEqual(dehashed_finding["leaked_data"]["password"], "secret")
        self.assertNotIn("empty_field", dehashed_finding["leaked_fields"])

    def test_build_consolidated_report_dehashed_uses_target_email_fallback(self):
        request = SearchRequest(
            target_email="target@example.com",
            providers=["dehashed"],
        )
        response = SearchResponse(
            results={
                "dehashed": ProviderResult(
                    provider="dehashed",
                    ok=True,
                    findings=[
                        Finding(
                            provider="dehashed",
                            category="leak_record",
                            identifier="row-1",
                            attributes={
                                "id": "abc",
                                "password": "pw",
                            },
                        )
                    ],
                )
            }
        )

        report = build_consolidated_report(request, response)

        self.assertEqual(report["account_hits"][0]["account"], "target@example.com")
        self.assertEqual(report["account_hits"][0]["providers"]["dehashed"]["hit_count"], 1)

    def test_build_consolidated_report_generic_provider_uses_unknown_account(self):
        request = SearchRequest(
            providers=["custom"],
        )
        response = SearchResponse(
            results={
                "custom": ProviderResult(
                    provider="custom",
                    ok=True,
                    findings=[
                        Finding(
                            provider="custom",
                            category="custom_hit",
                            identifier="record-1",
                            attributes={"field": "value"},
                        )
                    ],
                )
            }
        )

        report = build_consolidated_report(
            request,
            response,
            generated_at="2026-02-21T10:00:00+00:00",
        )

        self.assertEqual(report["generated_at"], "2026-02-21T10:00:00+00:00")
        self.assertEqual(report["account_hits"][0]["account"], "<unknown>")
        self.assertEqual(report["account_hits"][0]["providers"]["custom"]["hit_count"], 1)
        self.assertEqual(report["scope"]["total_findings"], 1)

    def test_build_consolidated_report_generic_provider_uses_target_email(self):
        request = SearchRequest(
            target_email="target@example.com",
            providers=["custom"],
        )
        response = SearchResponse(
            results={
                "custom": ProviderResult(
                    provider="custom",
                    ok=True,
                    findings=[
                        Finding(
                            provider="custom",
                            category="custom_hit",
                            identifier="record-1",
                            attributes={"field": "value"},
                        )
                    ],
                )
            }
        )

        report = build_consolidated_report(request, response)

        self.assertEqual(report["account_hits"][0]["account"], "target@example.com")

    def test_build_consolidated_report_covers_hibp_edge_values(self):
        request = SearchRequest(
            providers=["haveibeenpwned"],
        )
        response = SearchResponse(
            results={
                "haveibeenpwned": ProviderResult(
                    provider="haveibeenpwned",
                    ok=True,
                    findings=[
                        Finding(
                            provider="haveibeenpwned",
                            category="breach",
                            identifier="",
                            attributes={
                                "DataClasses": "Passwords",
                            },
                        ),
                        Finding(
                            provider="haveibeenpwned",
                            category="breach",
                            identifier="Example",
                            attributes={
                                "DataClasses": [None, 123],
                            },
                        ),
                    ],
                )
            }
        )

        report = build_consolidated_report(request, response)

        self.assertEqual(report["account_hits"][0]["account"], "<unknown>")
        self.assertIn("123", report["scope"]["hibp_leaked_data_classes"])

    def test_build_consolidated_report_dehashed_non_dict_attributes(self):
        request = SearchRequest(
            target_email="user@example.com",
            providers=["dehashed"],
        )
        response = SearchResponse(
            results={
                "dehashed": ProviderResult(
                    provider="dehashed",
                    ok=True,
                    findings=[
                        Finding(
                            provider="dehashed",
                            category="leak_record",
                            identifier="record-xyz",
                            attributes="raw-string",
                        )
                    ],
                )
            }
        )

        report = build_consolidated_report(request, response)

        dehashed = report["account_hits"][0]["providers"]["dehashed"]["findings"][0]
        self.assertEqual(dehashed["leaked_fields"], [])

    def test_build_consolidated_report_includes_provider_errors(self):
        request = SearchRequest(
            target_email="user@example.com",
            providers=["haveibeenpwned"],
        )
        response = SearchResponse(
            results={
                "haveibeenpwned": ProviderResult(
                    provider="haveibeenpwned",
                    ok=False,
                    findings=[],
                    status_code=429,
                    error="rate limited",
                )
            }
        )

        report = build_consolidated_report(request, response)

        self.assertFalse(report["provider_results"]["haveibeenpwned"]["ok"])
        self.assertEqual(report["provider_results"]["haveibeenpwned"]["status_code"], 429)
        self.assertEqual(report["provider_results"]["haveibeenpwned"]["error"], "rate limited")
        self.assertEqual(report["scope"]["total_findings"], 0)
        self.assertEqual(report["account_hits"], [])


if __name__ == "__main__":
    unittest.main()
