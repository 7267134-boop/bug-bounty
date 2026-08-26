"""Central configuration, loaded strictly from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _get(name: str, default: str | None = None, *, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value  # type: ignore[return-value]


@dataclass(frozen=True)
class Settings:
    # --- PostgreSQL ---
    pg_host: str = "postgres"
    pg_port: int = 5432
    pg_db: str = "bb_platform"
    pg_user: str = "bb_app"
    pg_password: str = ""

    # --- Redis ---
    redis_url: str = "redis://redis:6379/0"

    # --- Security ---
    api_token: str = ""

    # --- Queue ---
    stream_key: str = "bb:tasks"
    consumer_group: str = "workers"
    consumer_name: str = "worker-unset"
    block_secs: int = 5
    stale_requeue_secs: int = 900

    # --- Execution limits ---
    task_timeout_secs: int = 600
    max_output_bytes: int = 1_000_000
    worker_concurrency: int = 2
    worker_rate_rps: float = 10.0
    extra_env_keys: list[str] = field(default_factory=list)
    webhook_url: str = ""

    # --- Worker resilience ------------------------------------------- #
    # TUNABLE(final-tuning-pending): these values are safe engineering
    # defaults; they are on the manual-tuning checklist in docs/TUNING.md.
    # Consume-loop error backoff: delay before re-polling Redis after a
    # consume failure. Grows exponentially (base * 2^(n-1)), capped at max,
    # resets to base after one successful consume. Prevents CPU hot-spin
    # and log floods during persistent outages.
    consume_error_backoff_secs: float = 3.0
    consume_error_backoff_max_secs: float = 30.0

    # --- Misc ---
    log_level: str = "INFO"
    workflows_dir: str = "/app/workflows"

    @property
    def pg_dsn(self) -> str:
        return (
            f"postgres://{self.pg_user}:{self.pg_password}"
            f"@{self.pg_host}:{self.pg_port}/{self.pg_db}"
        )


def load_settings() -> Settings:
    """Build Settings from the environment. Raises when mandatory vars absent."""
    return Settings(
        pg_host=_get("POSTGRES_HOST", "postgres"),
        pg_port=int(_get("POSTGRES_PORT", "5432")),
        pg_db=_get("POSTGRES_DB", "bb_platform"),
        pg_user=_get("POSTGRES_USER", "bb_app"),
        pg_password=_get("POSTGRES_PASSWORD", "", required=True),
        redis_url=_get("REDIS_URL", "redis://redis:6379/0"),
        api_token=_get("MASTER_API_TOKEN", "", required=True),
        consumer_name=_get("WORKER_ID", "worker-unset"),
        block_secs=int(_get("BLOCK_SECS", "5")),
        stale_requeue_secs=int(_get("STALE_REQUEUE_SECS", "900")),
        task_timeout_secs=int(_get("TASK_TIMEOUT_SECS", "600")),
        max_output_bytes=int(_get("MAX_OUTPUT_BYTES", "1000000")),
        worker_concurrency=int(_get("WORKER_CONCURRENCY", "2")),
        worker_rate_rps=float(_get("WORKER_RATE_RPS", "10")),
        # TUNABLE(final-tuning-pending): see docs/TUNING.md
        consume_error_backoff_secs=float(_get("CONSUME_ERROR_BACKOFF_SECS", "3")),
        consume_error_backoff_max_secs=float(_get("CONSUME_ERROR_BACKOFF_MAX_SECS", "30")),
        extra_env_keys=[
            k.strip() for k in _get("WORKER_ENV_PASSTHROUGH", "").split(",") if k.strip()
        ],
        webhook_url=_get("WEBHOOK_URL", ""),
        log_level=_get("LOG_LEVEL", "INFO").upper(),
        workflows_dir=_get("WORKFLOWS_DIR", "/app/workflows"),
    )
