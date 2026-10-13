# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Configuration from `UOTP_*` environment variables (12-factor), as in UltimateTunes."""

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ultimateotp.netaddr import IpNetwork, parse_networks

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
EnrollmentScope = Literal["lan", "anywhere"]
Switch = Literal["enabled", "disabled"]

# Docker secrets: `/run/secrets/uotp_smtp_password`, `/run/secrets/uotp_ntfy_token`.
_SECRETS_DIR = Path("/run/secrets")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="UOTP_",
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
        secrets_dir=_SECRETS_DIR if _SECRETS_DIR.is_dir() else None,
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
    # Where password login (email code + SRP, decision 6) and sign-up are allowed from.
    enrollment_scope: EnrollmentScope = "anywhere"
    # Where enrollment tokens (bootstrap, CLI-minted) and device pairing are allowed from.
    pairing_scope: EnrollmentScope = "lan"
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

    # --- Accounts, SRP login and email codes (decisions 6, 8, 13) --------------------------
    # Public sign-up (`POST /otp/v1/signup`); accounts come from the CLI by default.
    signup: Switch = "disabled"
    srp_session_ttl_s: int = Field(default=300, ge=30, le=3600)
    # Consecutive SRP failures before the account locks, then base * 2^(n - threshold) seconds.
    srp_lockout_threshold: int = Field(default=5, ge=1, le=100)
    srp_lockout_base_s: int = Field(default=60, ge=1)
    srp_lockout_max_s: int = Field(default=86_400, ge=60)
    # Emailed one-time codes. `disabled` is for local development only.
    email_verification: Switch = "enabled"
    email_code_ttl_s: int = Field(default=600, ge=60, le=3600)
    email_code_max_attempts: int = Field(default=5, ge=1, le=20)
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_user: str = "resend"
    smtp_from: str = ""
    # The Resend API key: Docker secret `uotp_smtp_password` only.
    smtp_password: SecretStr | None = None
    # Extra CA bundle for the relay's certificate (tests, private relays). Empty: system CAs.
    smtp_ca_file: Path | None = None
    smtp_timeout_s: float = Field(default=15.0, gt=0)

    # --- Notifications (decision 7) -------------------------------------------------------
    # The full topic URL, e.g. https://ntfy.example.org/ultimateotp. Empty: log only.
    ntfy_url: str = ""
    # Docker secret `uotp_ntfy_token` (an ntfy access token), optional.
    ntfy_token: SecretStr | None = None

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
    # SRP handshakes per client address.
    srp_rate_per_s: float = Field(default=0.2, gt=0)
    srp_burst: int = Field(default=10, ge=1)
    # Emails sent: per client address and per destination address (anti-spam).
    email_ip_per_hour: float = Field(default=10.0, gt=0)
    email_ip_burst: int = Field(default=5, ge=1)
    email_address_per_hour: float = Field(default=3.0, gt=0)
    email_address_burst: int = Field(default=3, ge=1)

    # --- Listener -------------------------------------------------------------------------
    limit_concurrency: int = Field(default=256, ge=8, le=10_000)
    keepalive_timeout_s: int = Field(default=5, ge=1, le=120)
    shutdown_timeout_s: int = Field(default=5, ge=1, le=60)

    @field_validator("trusted_proxies", "lan_networks", "denied_networks", "metrics_networks")
    @classmethod
    def _valid_networks(cls, value: str) -> str:
        parse_networks(value)
        return value

    def require_email_transport(self) -> None:
        """Decision 13: the api (and the CLI commands that email) refuse to start without SMTP
        unless email verification is explicitly disabled. `migrate` and `backup` do not care."""
        if self.email_verification == "enabled" and not (
            self.smtp_host and self.smtp_from and self.smtp_password
        ):
            raise SystemExit(
                "email verification needs UOTP_SMTP_HOST, UOTP_SMTP_FROM and the Docker secret"
                " uotp_smtp_password; set UOTP_EMAIL_VERIFICATION=disabled only for development"
            )

    @model_validator(mode="after")
    def _valid_ntfy_url(self) -> "Settings":
        if self.ntfy_url and not self.ntfy_url.startswith(("https://", "http://")):
            raise ValueError("UOTP_NTFY_URL must be an http(s) URL")
        return self

    @property
    def email_enabled(self) -> bool:
        return self.email_verification == "enabled"

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
