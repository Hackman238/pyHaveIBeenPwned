from .exceptions import PyHaveIBeenPwnedError
from .providers import DeHashedProvider, HaveIBeenPwnedProvider

_PROVIDERS = {
    HaveIBeenPwnedProvider.name: HaveIBeenPwnedProvider,
    DeHashedProvider.name: DeHashedProvider,
}


def register_provider(name, provider_cls):
    _PROVIDERS[name.lower()] = provider_cls


def get_provider(name):
    provider_name = name.lower()
    if provider_name not in _PROVIDERS:
        raise PyHaveIBeenPwnedError(f"Unknown provider: {name}")
    return _PROVIDERS[provider_name]


def list_providers():
    return sorted(_PROVIDERS.keys())
