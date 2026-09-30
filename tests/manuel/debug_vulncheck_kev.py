import httpx

from sentinel.config.settings import settings

url = f"{settings.vulncheck_kev_base_url}/backup/vulncheck-kev"

headers = {
    "Accept": "application/json",
    "Authorization": (f"Bearer {settings.vulncheck_kev_api_token}"),
}

response = httpx.get(
    url,
    headers=headers,
    timeout=settings.vulncheck_kev_default_timeout,
)

print("HTTP status:", response.status_code)
print("Content-Type:", response.headers.get("content-type"))
print("Content-Length:", response.headers.get("content-length"))
print()
print(response.text[:5000])
