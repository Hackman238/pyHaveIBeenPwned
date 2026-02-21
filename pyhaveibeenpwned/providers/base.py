from abc import ABC, abstractmethod


class BaseProvider(ABC):
    name = ""

    @abstractmethod
    def validate_request(self, request):
        """Validate request data for this provider."""

    @abstractmethod
    def search(self, request):
        """Execute a provider search and return ProviderResult."""
