FROM python:3.15-slim

LABEL org.opencontainers.image.title="Host Firewall" \
      org.opencontainers.image.description="Web panel for host UFW with labelled rules and confirm-or-rollback" \
      org.opencontainers.image.source="https://github.com/reonsmith/host-firewall" \
      org.opencontainers.image.licenses="MIT"

LABEL org.opencontainers.image.title="Host Firewall" \
      org.opencontainers.image.description="Web panel for host UFW with labelled rules and confirm-or-rollback" \
      org.opencontainers.image.source="https://github.com/reonsmith/host-firewall" \
      org.opencontainers.image.licenses="MIT"

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
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request as u; h=os.environ.get('HOST_FIREWALL_BIND','0.0.0.0'); h='127.0.0.1' if h in ('','0.0.0.0','::') else h; u.urlopen('http://%s:%s/api/health' % (h, os.environ.get('HOST_FIREWALL_PORT','8080')), timeout=4)" || exit 1
CMD ["python", "-m", "backend"]
