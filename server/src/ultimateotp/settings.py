# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Configuration from `UOTP_*` environment variables (12-factor), as in UltimateTunes."""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ultimateotp.netaddr import IpNetwork, parse_networks

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
EnrollmentScope = Literal["lan", "anywhere"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="UOTP_", extra="ignore", frozen=True, hide_input_in_errors=True
    )

    data_dir: Path = Path("/data")
    database_path: Path | None = None
    # Plain SQL migrations shipped next to the code (contracts/db/migrations in the repo).
    migrations_dir: Path = Path("/app/migrations")
    # Loopback unless told otherwise; the image sets UOTP_HOST=0.0.0.0 and compose decides exposure.
    host: str = "127.0.0.1"
    port: int = Field(default=8047, ge=1, le=65535)
    log_level: LogLevel = "INFO"

    # --- Client address and network policy (forwarded.py, docs/deploy.md) -------------------
    # CIDRs of reverse proxies whose X-Forwarded-For is believed (Traefik's pinned address and
    # cloudflared). Empty: nobody's; the TCP peer is the client and a request carrying forwarding
    # headers counts as coming from outside the LAN.
    trusted_proxies: str = ""
    # Where the enrollment surface is allowed from (decision 4): `lan` (default) or `anywhere`.
    enrollment_scope: EnrollmentScope = "lan"
    # The owner's LAN (and tailnet). NEVER a Docker range such as 172.16.0.0/12: cloudflared and
    # every container on the proxy network live there. Narrow it to your /24 in production.
    lan_networks: str = "127.0.0.0/8,::1/128,192.168.0.0/16,fd00::/8"
    # Always outside the LAN, whatever lan_networks says (e.g. the proxy network itself).
    denied_networks: str = ""
    # Who may read /metrics (Prometheus).
    metrics_networks: str = "127.0.0.0/8,::1/128"

    # --- Protocol limits ------------------------------------------------------------------
    signature_max_skew_s: int = Field(default=60, ge=5, le=600)
    enrollment_token_ttl_s: int = Field(default=600, ge=60, le=86_400)
    pairing_ttl_s: int = Field(default=600, ge=60, le=3_600)
    recovery_fetch_limit: int = Field(default=5, ge=1, le=100)
    max_body_bytes: int = Field(default=4 * 1024 * 1024, ge=64 * 1024)
    max_blob_bytes: int = Field(default=64 * 1024, ge=1024)
    max_wrap_bytes: int = Field(default=4 * 1024, ge=256)
    max_items: int = Field(default=2000, ge=1)

    # --- Live sync (docs/sync.md) ---------------------------------------------------------
    sse_keepalive_s: float = Field(default=15.0, gt=0, le=120)
    sse_max_age_s: float = Field(default=3600.0, gt=0)
    sse_max_streams_per_device: int = Field(default=3, ge=1, le=20)

    # --- Rate limits (ratelimit.py), per client address or per device ----------------------
    ratelimit_enabled: bool = True
    enroll_rate_per_s: float = Field(default=1.0, gt=0)
    enroll_burst: int = Field(default=10, ge=1)
    auth_failure_rate_per_s: float = Field(default=0.2, gt=0)
    auth_failure_burst: int = Field(default=20, ge=1)
    mint_rate_per_s: float = Field(default=0.1, gt=0)
    mint_burst: int = Field(default=5, ge=1)
    write_rate_per_s: float = Field(default=5.0, gt=0)
    write_burst: int = Field(default=20, ge=1)

    # --- Listener -------------------------------------------------------------------------
    limit_concurrency: int = Field(default=256, ge=8, le=10_000)
    keepalive_timeout_s: int = Field(default=5, ge=1, le=120)
    shutdown_timeout_s: int = Field(default=5, ge=1, le=60)

    @field_validator("trusted_proxies", "lan_networks", "denied_networks", "metrics_networks")
    @classmethod
    def _valid_networks(cls, value: str) -> str:
        parse_networks(value)
        return value

    @property
    def proxy_networks(self) -> tuple[IpNetwork, ...]:
        return parse_networks(self.trusted_proxies)

    @property
    def lan_network_list(self) -> tuple[IpNetwork, ...]:
        return parse_networks(self.lan_networks)

    @property
    def denied_network_list(self) -> tuple[IpNetwork, ...]:
        return parse_networks(self.denied_networks)

    @property
    def metrics_network_list(self) -> tuple[IpNetwork, ...]:
        return parse_networks(self.metrics_networks)

    @property
    def database_file(self) -> Path:
        return self.database_path or self.data_dir / "ultimateotp.db"
