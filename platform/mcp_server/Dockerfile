# MCP gateway (Stage 5) - stdio JSON-RPC bridge to the Master API.
# AI agents spawn this process; it has NO inbound ports and NO direct
# database/queue access. Stdlib-only image (no pip install needed).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY mcp_server/ /app/mcp_server/

RUN groupadd -g 10002 mcp && useradd -u 10002 -g mcp -s /usr/sbin/nologin mcp

USER 10002:10002

# No EXPOSE: stdio transport only — the agent owns the process.
ENTRYPOINT ["python3", "-m", "mcp_server.server"]