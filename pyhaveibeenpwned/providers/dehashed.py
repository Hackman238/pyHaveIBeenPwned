import requests

from ..exceptions import PyHaveIBeenPwnedError
from ..models import Finding, ProviderResult
from .base import BaseProvider


class DeHashedProvider(BaseProvider):
    name = "dehashed"
    API_ENDPOINT = "https://api.dehashed.com/v2/search"
    DEFAULT_TIMEOUT = 10
    DEFAULT_PAGE = 1
    DEFAULT_SIZE = 25

    def __init__(self, session=None):
        self._session = session or requests.Session()

    def validate_request(self, request):
        credentials = request.get_credentials(self.name)
        criteria = request.get_criteria(self.name)
        query = criteria.get("query")
        if not credentials.api_key:
            raise PyHaveIBeenPwnedError("dehashed provider requires an api_key.")
        if not query and not request.target_email:
            raise PyHaveIBeenPwnedError(
                "dehashed provider requires target_email or criteria query."
            )

    @staticmethod
    def _extract_entries(payload):
        if not isinstance(payload, dict):
            return []

        for key in ("entries", "results", "records", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return value

        data = payload.get("data")
        if isinstance(data, dict):
            for key in ("entries", "results", "records", "items"):
                value = data.get(key)
                if isinstance(value, list):
                    return value

        if isinstance(data, list):
            return data

        return []

    @classmethod
    def _normalize_entries(cls, payload):
        findings = []
        entries = cls._extract_entries(payload)
        for entry in entries:
            if isinstance(entry, dict):
                identifier = (
                    entry.get("email")
                    or entry.get("username")
                    or entry.get("id")
                    or "<unknown>"
                )
                attributes = entry
            else:
                identifier = str(entry)
                attributes = {"value": entry}
            findings.append(
                Finding(
                    provider=DeHashedProvider.name,
                    category="leak_record",
                    identifier=str(identifier),
                    attributes=attributes,
                )
            )
        return findings

    @staticmethod
    def _extract_error_message(response, payload):
        if isinstance(payload, dict):
            message = payload.get("error") or payload.get("message")
            if message:
                return str(message)
        return f"dehashed request failed (HTTP {response.status_code})"

    def search(self, request):
        try:
            self.validate_request(request)
        except PyHaveIBeenPwnedError as error:
            return ProviderResult(
                provider=self.name,
                ok=False,
                error=str(error),
                status_code=error.status_code,
                retry_after=error.retry_after,
            )

        credentials = request.get_credentials(self.name)
        criteria = request.get_criteria(self.name)
        query = criteria.get("query") or f"email:{request.target_email}"
        timeout = request.timeout if request.timeout is not None else criteria.get(
            "timeout", self.DEFAULT_TIMEOUT
        )
        params = {
            "query": query,
            "page": criteria.get("page", self.DEFAULT_PAGE),
            "size": criteria.get("size", self.DEFAULT_SIZE),
            "regex": criteria.get("regex", False),
            "wildcard": criteria.get("wildcard", False),
            "de_dupe": criteria.get("de_dupe", False),
        }

        try:
            response = self._session.post(
                self.API_ENDPOINT,
                json=params,
                headers={
                    "DeHashed-Api-Key": credentials.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": credentials.user_agent or "pyhaveibeenpwned",
                },
                timeout=timeout,
            )
        except requests.RequestException as error:
            return ProviderResult(
                provider=self.name,
                ok=False,
                error=f"Unable to reach dehashed API: {error}",
            )

        try:
            payload = response.json()
        except ValueError:
            payload = {"raw_text": response.text}

        if response.status_code >= 400:
            return ProviderResult(
                provider=self.name,
                ok=False,
                error=self._extract_error_message(response, payload),
                status_code=response.status_code,
                retry_after=response.headers.get("Retry-After"),
                raw=payload,
            )

        return ProviderResult(
            provider=self.name,
            ok=True,
            findings=self._normalize_entries(payload),
            raw=payload,
        )
