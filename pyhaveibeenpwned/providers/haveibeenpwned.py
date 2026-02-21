import time

from ..client import PyHaveIBeenPwned
from ..exceptions import PyHaveIBeenPwnedError
from ..models import Finding, ProviderResult
from .base import BaseProvider


class HaveIBeenPwnedProvider(BaseProvider):
    name = "haveibeenpwned"
    DEFAULT_QUERIES_PER_SECOND = 5.0

    def __init__(self, client_factory=None, monotonic=None, sleep=None):
        self._client_factory = client_factory or PyHaveIBeenPwned
        self._monotonic = monotonic or time.monotonic
        self._sleep = sleep or time.sleep
        self._last_request_at = None

    def _resolve_queries_per_second(self, criteria):
        raw_qps = criteria.get("queries_per_second", self.DEFAULT_QUERIES_PER_SECOND)
        try:
            qps = float(raw_qps)
        except (TypeError, ValueError) as error:
            raise PyHaveIBeenPwnedError(
                "haveibeenpwned provider queries_per_second must be a number."
            ) from error

        if qps <= 0:
            raise PyHaveIBeenPwnedError(
                "haveibeenpwned provider queries_per_second must be greater than 0."
            )

        return qps

    def _wait_for_rate_limit_window(self, queries_per_second):
        if self._last_request_at is None:
            return

        minimum_interval = 1.0 / queries_per_second
        elapsed = self._monotonic() - self._last_request_at
        remaining = minimum_interval - elapsed
        if remaining > 0:
            self._sleep(remaining)

    def _call_with_rate_limit(self, queries_per_second, call, *args, **kwargs):
        self._wait_for_rate_limit_window(queries_per_second)
        result = call(*args, **kwargs)
        self._last_request_at = self._monotonic()
        return result

    def validate_request(self, request):
        credentials = request.get_credentials(self.name)
        criteria = request.get_criteria(self.name)
        email = criteria.get("email") or request.target_email
        if not credentials.api_key:
            raise PyHaveIBeenPwnedError("haveibeenpwned provider requires an api_key.")
        if not email:
            raise PyHaveIBeenPwnedError(
                "haveibeenpwned provider requires target_email or criteria email."
            )
        self._resolve_queries_per_second(criteria)

    def _build_client(self, request):
        credentials = request.get_credentials(self.name)
        criteria = request.get_criteria(self.name)
        timeout = request.timeout if request.timeout is not None else criteria.get("timeout")
        return self._client_factory(
            api_key=credentials.api_key,
            user_agent=credentials.user_agent,
            timeout=timeout,
        )

    @staticmethod
    def _normalize_items(provider_name, category, payload):
        findings = []
        if not isinstance(payload, list):
            return findings
        for item in payload:
            if isinstance(item, dict):
                identifier = (
                    item.get("Name")
                    or item.get("Title")
                    or item.get("Source")
                    or item.get("Id")
                    or "<unknown>"
                )
                attributes = item
            else:
                identifier = str(item)
                attributes = {"value": item}
            findings.append(
                Finding(
                    provider=provider_name,
                    category=category,
                    identifier=str(identifier),
                    attributes=attributes,
                )
            )
        return findings

    @staticmethod
    def _is_not_found_error(error):
        return isinstance(error, PyHaveIBeenPwnedError) and error.status_code == 404

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

        criteria = request.get_criteria(self.name)
        email = criteria.get("email") or request.target_email
        domain = criteria.get("domain")
        include_pastes = bool(criteria.get("include_pastes"))
        include_data_classes = bool(criteria.get("include_data_classes"))
        queries_per_second = self._resolve_queries_per_second(criteria)
        client = self._build_client(request)
        self._last_request_at = None
        raw = {}
        findings = []

        try:
            try:
                breaches = self._call_with_rate_limit(
                    queries_per_second,
                    client.get_account_breaches,
                    email,
                    domain=domain,
                )
            except PyHaveIBeenPwnedError as error:
                if self._is_not_found_error(error):
                    breaches = []
                else:
                    raise
            raw["breaches"] = breaches
            findings.extend(self._normalize_items(self.name, "breach", breaches))

            if include_pastes:
                try:
                    pastes = self._call_with_rate_limit(
                        queries_per_second,
                        client.get_account_pastes,
                        email,
                    )
                except PyHaveIBeenPwnedError as error:
                    if self._is_not_found_error(error):
                        pastes = []
                    else:
                        raise
                raw["pastes"] = pastes
                findings.extend(self._normalize_items(self.name, "paste", pastes))

            if include_data_classes:
                try:
                    data_classes = self._call_with_rate_limit(
                        queries_per_second,
                        client.get_data_classes,
                    )
                except PyHaveIBeenPwnedError as error:
                    if self._is_not_found_error(error):
                        data_classes = []
                    else:
                        raise
                raw["data_classes"] = data_classes
                findings.extend(
                    self._normalize_items(self.name, "data_class", data_classes)
                )
        except PyHaveIBeenPwnedError as error:
            return ProviderResult(
                provider=self.name,
                ok=False,
                findings=findings,
                error=str(error),
                status_code=error.status_code,
                retry_after=error.retry_after,
                raw=raw or None,
            )

        return ProviderResult(
            provider=self.name,
            ok=True,
            findings=findings,
            raw=raw,
        )
