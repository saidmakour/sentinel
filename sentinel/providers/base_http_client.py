import httpx


class BaseHttpClient:
    def __init__(
        self,
        *,
        timeout: int,
        client: httpx.Client | None = None,
    ) -> None:
        self.client = client or httpx.Client(
            timeout=timeout,
        )

    def close(self) -> None:
        self.client.close()
