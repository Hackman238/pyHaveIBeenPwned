from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ProviderCredentials:
    api_key: Optional[str] = None
    account_email: Optional[str] = None
    user_agent: Optional[str] = None
    extras: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_value(cls, value):
        if value is None:
            return cls()
        if isinstance(value, cls):
            return value
        if isinstance(value, dict):
            data = dict(value)
            extras = data.pop("extras", {})
            if extras is None:
                extras = {}
            return cls(
                api_key=data.pop("api_key", None),
                account_email=data.pop("account_email", data.pop("email", None)),
                user_agent=data.pop("user_agent", None),
                extras={**extras, **data},
            )
        raise TypeError("Provider credentials must be ProviderCredentials, dict, or None.")


@dataclass
class SearchRequest:
    target_email: Optional[str] = None
    providers: List[str] = field(default_factory=list)
    criteria_by_provider: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    credentials_by_provider: Dict[str, ProviderCredentials] = field(default_factory=dict)
    timeout: Optional[float] = None

    def __post_init__(self):
        normalized = {}
        for provider_name, credentials in self.credentials_by_provider.items():
            normalized[provider_name.lower()] = ProviderCredentials.from_value(credentials)
        self.credentials_by_provider = normalized
        self.providers = [provider.lower() for provider in self.providers]
        self.criteria_by_provider = {
            provider.lower(): (criteria or {})
            for provider, criteria in self.criteria_by_provider.items()
        }

    def get_credentials(self, provider_name):
        return self.credentials_by_provider.get(provider_name.lower(), ProviderCredentials())

    def get_criteria(self, provider_name):
        return self.criteria_by_provider.get(provider_name.lower(), {})


@dataclass
class Finding:
    provider: str
    category: str
    identifier: str
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderResult:
    provider: str
    ok: bool
    findings: List[Finding] = field(default_factory=list)
    status_code: Optional[int] = None
    error: Optional[str] = None
    retry_after: Optional[str] = None
    raw: Any = None


@dataclass
class SearchResponse:
    results: Dict[str, ProviderResult] = field(default_factory=dict)
