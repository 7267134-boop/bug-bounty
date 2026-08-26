# Worker Node - Kali-based, least privilege, no inbound network exposure.
# NOTE: pin by digest in production (docker images --digests kalilinux/kali-rolling).
FROM kalilinux/kali-rolling

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    GOBIN=/usr/local/bin

# Base runtime + toolchain. Go tools are version-pinned for reproducibility;
# bump the pins deliberately and re-test parsers when you do.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip ca-certificates curl git golang nmap massdns \
        wpscan sqlmap arjun trufflehog \
    && rm -rf /var/lib/apt/lists/* \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7 \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.2 \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9 \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.3 \
    && go install github.com/projectdiscovery/katana/cmd/katana@v1.1.0 \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.9 \
    && go install github.com/projectdiscovery/uncover/cmd/uncover@v1.0.9 \
    && go install github.com/hahwul/dalfox/v2/cmd/dalfox@v2.9.5 \
    && go install github.com/ffuf/ffuf/v2/cmd/ffuf@v2.1.0 \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.2 \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9 \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.3 \
    && go install github.com/projectdiscovery/katana/cmd/katana@v1.1.0 \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.9 \
    && go install github.com/projectdiscovery/uncover/cmd/uncover@v1.0.9 \
    && go install github.com/hahwul/dalfox/v2/cmd/dalfox@v2.9.5 \
    && go install github.com/tomnomnom/assetfinder@latest \
    && go install github.com/tomnomnom/waybackurls@latest \
    # Visual recon (gowitness) needs Chromium (~500MB). Enable deliberately:
    # && apt-get install -y --no-install-recommends chromium \
    # && go install github.com/sensepost/gowitness@v3.0.5 \
    # CORS scanner (Stage 3): cloned script, executed directly (no shell)
    # && git clone --depth 1 https://github.com/s0md3v/Corsy /opt/corsy \
    # && chmod +x /opt/corsy/corsy.py \
    && chmod -R a+rX /usr/local/go /root/.cache 2>/dev/null || true

WORKDIR /app

COPY worker/requirements.txt /app/worker/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /app/worker/requirements.txt

# Dedicated non-root user; tools run as this user only.
RUN groupadd -g 10001 worker && useradd -u 10001 -g worker -m -s /usr/sbin/nologin worker \
    && mkdir -p /tmp/tasks && chown -R worker:worker /tmp/tasks

COPY common/ /app/common/
COPY worker/ /app/worker/

RUN chown -R root:worker /app && chmod -R g+rX /app

USER 10001:10001

# No EXPOSE: the worker must never listen on a port.

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python3 -c "import os,sys; sys.exit(0 if os.environ.get('WORKER_HEALTH','1')=='1' else 1)"

CMD ["python3", "-m", "worker.main"]
