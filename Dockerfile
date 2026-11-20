FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ufw iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY backend ./backend
RUN pip install --no-cache-dir .

ENV HOST_FIREWALL_DATA_DIR=/app/data \
    HOST_FIREWALL_UFW_DIR=/etc/ufw \
    HOST_FIREWALL_BIND=0.0.0.0 \
    HOST_FIREWALL_PORT=8080

EXPOSE 8080
CMD ["python", "-m", "backend"]
