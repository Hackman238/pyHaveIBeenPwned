from .exceptions import PyHaveIBeenPwnedError
from .models import ProviderResult, SearchResponse
from .provider_registry import get_provider


class BreachLookupClient:
    def __init__(self, default_providers=None):
        self._default_providers = default_providers or ["haveibeenpwned"]

    def search(self, request):
        providers = request.providers or self._default_providers
        results = {}
        for provider_name in providers:
            normalized_name = provider_name.lower()
            try:
                provider_cls = get_provider(normalized_name)
                provider = provider_cls()
                result = provider.search(request)
            except PyHaveIBeenPwnedError as error:
                result = ProviderResult(
                    provider=normalized_name,
                    ok=False,
                    error=str(error),
                    status_code=error.status_code,
                    retry_after=error.retry_after,
                )
            results[normalized_name] = result
        return SearchResponse(results=results)
