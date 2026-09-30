class ProviderError(Exception):
    """Base exception for vulnerability providers."""


class ProviderConnectionError(ProviderError):
    """Unable to contact the provider."""


class ProviderResponseError(ProviderError):
    """Invalid response returned by the provider."""


class ProviderRateLimitError(ProviderError):
    """Provider rate limit exceeded."""
