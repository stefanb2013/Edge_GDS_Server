"""Centralized configuration, loaded from environment variables.

Every setting has a sane default for local/dev use except secrets (admin
password, session secret), which are randomly generated at startup if not
supplied -- see main.py.

Docker Compose passes real environment variables directly, so there's
nothing more to do there. As a fallback (never overriding a real env var
that's already set), this also loads a `.env` file placed next to the
running executable -- useful for a frozen (PyInstaller-style) build with no
easy way to set per-process environment variables otherwise.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def _exe_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


load_dotenv(_exe_dir() / ".env", override=False)


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    hostname: str = field(default_factory=lambda: os.environ.get("GDS_HOSTNAME", "localhost"))
    opcua_port: int = field(default_factory=lambda: int(os.environ.get("GDS_OPCUA_PORT", "4840")))
    http_port: int = field(default_factory=lambda: int(os.environ.get("GDS_HTTP_PORT", "8443")))

    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("GDS_DATA_DIR", "./data")))

    ca_common_name: str = field(default_factory=lambda: os.environ.get("GDS_CA_COMMON_NAME", "GDS Root CA"))
    ca_organization: str = field(default_factory=lambda: os.environ.get("GDS_CA_ORGANIZATION", "Example Org"))
    ca_country: str = field(default_factory=lambda: os.environ.get("GDS_CA_COUNTRY", "DE"))
    ca_key_bits: int = field(default_factory=lambda: int(os.environ.get("GDS_CA_KEY_BITS", "3072")))
    ca_valid_days: int = field(default_factory=lambda: int(os.environ.get("GDS_CA_VALID_DAYS", "7300")))
    issued_cert_valid_days: int = field(
        default_factory=lambda: int(os.environ.get("GDS_ISSUED_CERT_VALID_DAYS", "730"))
    )
    # How long before an issued certificate expires GetCertificateStatus (pull
    # mode) tells the application it should renew -- overridable at runtime
    # from the web UI's Settings page (see gds/db.py's settings_kv table),
    # which takes precedence over this env-var default once set.
    renew_before_days: int = field(
        default_factory=lambda: int(os.environ.get("GDS_RENEW_BEFORE_DAYS", "30"))
    )
    crl_validity_days: int = field(
        default_factory=lambda: int(os.environ.get("GDS_CRL_VALIDITY_DAYS", "30"))
    )

    # Push mode has no equivalent of pull mode's client-initiated
    # GetCertificateStatus -- a pushed device never calls back to ask "am I
    # still good?", so if it loses its certificate entirely (a factory
    # reset, a config wipe) the GDS would otherwise never notice. This
    # background loop (gds/push_client.py's auto_reprovision_loop) polls
    # every configured push device's currently-presented certificate on an
    # unauthenticated channel and re-pushes automatically if it isn't ours,
    # is expired, or is due for renewal.
    push_auto_reprovision_enabled: bool = field(
        default_factory=lambda: _env_bool("GDS_PUSH_AUTO_REPROVISION", True)
    )
    push_health_check_interval_seconds: int = field(
        default_factory=lambda: int(os.environ.get("GDS_PUSH_HEALTH_CHECK_INTERVAL", "300"))
    )

    admin_user: str = field(default_factory=lambda: os.environ.get("GDS_ADMIN_USER", "admin"))
    admin_password: str = field(default_factory=lambda: os.environ.get("GDS_ADMIN_PASSWORD", ""))
    session_secret: str = field(default_factory=lambda: os.environ.get("GDS_SESSION_SECRET", ""))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "gds.db"

    @property
    def pki_dir(self) -> Path:
        return self.data_dir / "pki"

    @property
    def ca_dir(self) -> Path:
        return self.pki_dir / "ca"

    @property
    def issued_dir(self) -> Path:
        return self.pki_dir / "issued"

    @property
    def trusted_dir(self) -> Path:
        return self.pki_dir / "trusted"

    @property
    def crl_path(self) -> Path:
        return self.ca_dir / "ca.crl"

    @property
    def opcua_endpoint(self) -> str:
        return f"opc.tcp://0.0.0.0:{self.opcua_port}/gds/"

    @property
    def opcua_own_cert_dir(self) -> Path:
        return self.pki_dir / "server_instance"

    @property
    def web_tls_cert_dir(self) -> Path:
        return self.pki_dir / "web_ui"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.pki_dir, self.ca_dir, self.issued_dir,
                   self.trusted_dir, self.opcua_own_cert_dir, self.web_tls_cert_dir):
            d.mkdir(parents=True, exist_ok=True)


settings = Settings()
