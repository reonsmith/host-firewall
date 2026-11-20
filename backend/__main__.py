import uvicorn

from backend.config import load_settings


def main() -> None:
    settings = load_settings()
    uvicorn.run(
        "backend.app:get_app",
        factory=True,
        host=settings.bind_host,
        port=settings.bind_port,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


if __name__ == "__main__":
    main()
