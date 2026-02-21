from datetime import datetime, timezone
import re


EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.IGNORECASE)


def _is_non_empty(value):
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) > 0
    return True


def _extract_emails(value):
    found = set()

    def walk(node):
        if isinstance(node, dict):
            for nested in node.values():
                walk(nested)
            return
        if isinstance(node, (list, tuple, set)):
            for nested in node:
                walk(nested)
            return
        if isinstance(node, str):
            for match in EMAIL_PATTERN.findall(node):
                found.add(match.lower())

    walk(value)
    return sorted(found)


def _non_empty_keys(data):
    if not isinstance(data, dict):
        return []
    return sorted(str(key) for key, value in data.items() if _is_non_empty(value))


def _normalize_hibp_finding(finding, target_email):
    attributes = finding.attributes if isinstance(finding.attributes, dict) else {}
    accounts = _extract_emails(attributes)
    if target_email:
        accounts.append(target_email.lower())
    accounts = sorted(set(accounts))

    data_classes = attributes.get("DataClasses")
    if not isinstance(data_classes, list):
        data_classes = []

    normalized = {
        "provider": finding.provider,
        "category": finding.category,
        "identifier": finding.identifier,
        "scope": {
            "breach_name": attributes.get("Name") or finding.identifier,
            "title": attributes.get("Title"),
            "domain": attributes.get("Domain"),
            "breach_date": attributes.get("BreachDate"),
            "added_date": attributes.get("AddedDate"),
            "modified_date": attributes.get("ModifiedDate"),
            "pwn_count": attributes.get("PwnCount"),
            "is_verified": attributes.get("IsVerified"),
            "is_sensitive": attributes.get("IsSensitive"),
            "is_retired": attributes.get("IsRetired"),
            "is_spam_list": attributes.get("IsSpamList"),
            "is_malware": attributes.get("IsMalware"),
            "is_fabricated": attributes.get("IsFabricated"),
            "is_stealer_log": attributes.get("IsStealerLog"),
        },
        "leaked_data": {
            "data_classes": data_classes,
            "description": attributes.get("Description"),
        },
        "source": {
            "logo_path": attributes.get("LogoPath"),
        },
    }
    return accounts, normalized


def _normalize_dehashed_finding(finding, target_email):
    attributes = finding.attributes if isinstance(finding.attributes, dict) else {}
    accounts = _extract_emails(attributes)
    if not accounts:
        accounts = _extract_emails(finding.identifier)
    if not accounts and target_email:
        accounts = [target_email.lower()]

    leaked_fields = _non_empty_keys(attributes)
    leaked_data = {
        key: attributes.get(key)
        for key in leaked_fields
        if key not in {"id", "database_name", "source", "breach"}
    }

    normalized = {
        "provider": finding.provider,
        "category": finding.category,
        "identifier": finding.identifier,
        "record_id": attributes.get("id"),
        "scope": {
            "source": attributes.get("database_name")
            or attributes.get("source")
            or attributes.get("breach"),
            "username": attributes.get("username"),
            "domain": attributes.get("domain"),
            "ip_address": attributes.get("ip_address"),
        },
        "leaked_data": leaked_data,
        "leaked_fields": leaked_fields,
    }
    return sorted(set(accounts)), normalized


def _normalize_generic_finding(finding, target_email):
    attributes = finding.attributes if isinstance(finding.attributes, dict) else {}
    accounts = _extract_emails(attributes)
    if not accounts:
        accounts = _extract_emails(finding.identifier)
    if not accounts and target_email:
        accounts = [target_email.lower()]
    if not accounts:
        accounts = ["<unknown>"]

    normalized = {
        "provider": finding.provider,
        "category": finding.category,
        "identifier": finding.identifier,
        "scope": {},
        "leaked_data": attributes,
        "leaked_fields": _non_empty_keys(attributes),
    }
    return sorted(set(accounts)), normalized


def _normalize_finding(finding, target_email):
    provider = (finding.provider or "").lower()
    if provider == "haveibeenpwned":
        return _normalize_hibp_finding(finding, target_email)
    if provider == "dehashed":
        return _normalize_dehashed_finding(finding, target_email)
    return _normalize_generic_finding(finding, target_email)


def build_consolidated_report(request, response, generated_at=None):
    timestamp = generated_at
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    provider_results = {}
    provider_hit_counts = {}
    total_findings = 0

    for provider_name, result in response.results.items():
        count = len(result.findings)
        provider_results[provider_name] = {
            "ok": result.ok,
            "status_code": result.status_code,
            "error": result.error,
            "finding_count": count,
        }
        provider_hit_counts[provider_name] = count
        total_findings += count

    account_map = {}
    hibp_breaches = set()
    hibp_data_classes = set()
    dehashed_fields = set()

    for provider_name, result in response.results.items():
        for finding in result.findings:
            accounts, normalized = _normalize_finding(finding, request.target_email)
            if not accounts:
                accounts = ["<unknown>"]

            if provider_name == "haveibeenpwned":
                breach_name = normalized["scope"].get("breach_name")
                if _is_non_empty(breach_name):
                    hibp_breaches.add(str(breach_name))
                for item in normalized["leaked_data"].get("data_classes", []):
                    if _is_non_empty(item):
                        hibp_data_classes.add(str(item))

            if provider_name == "dehashed":
                for field in normalized.get("leaked_fields", []):
                    dehashed_fields.add(str(field))

            for account in accounts:
                account_entry = account_map.setdefault(
                    account,
                    {
                        "account": account,
                        "providers": {},
                    },
                )
                provider_entry = account_entry["providers"].setdefault(
                    provider_name,
                    {
                        "hit_count": 0,
                        "findings": [],
                    },
                )
                provider_entry["hit_count"] += 1
                provider_entry["findings"].append(normalized)

    account_hits = []
    for account in sorted(account_map.keys()):
        source_entry = account_map[account]
        providers = {}
        total_hits = 0
        for provider_name in sorted(source_entry["providers"].keys()):
            provider_entry = source_entry["providers"][provider_name]
            total_hits += provider_entry["hit_count"]
            providers[provider_name] = provider_entry
        account_hits.append(
            {
                "account": account,
                "total_hits": total_hits,
                "providers": providers,
            }
        )

    return {
        "schema_version": "1.0.0",
        "generated_at": timestamp,
        "target_email": request.target_email,
        "providers_requested": request.providers,
        "provider_results": provider_results,
        "scope": {
            "total_findings": total_findings,
            "accounts_with_hits": len(account_hits),
            "provider_hit_counts": provider_hit_counts,
            "unique_hibp_breaches": sorted(hibp_breaches),
            "hibp_leaked_data_classes": sorted(hibp_data_classes),
            "dehashed_leaked_fields": sorted(dehashed_fields),
        },
        "account_hits": account_hits,
    }
