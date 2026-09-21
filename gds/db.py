"""SQLite-backed storage shared by the OPC UA server and the web admin app.

Plain sqlite3, no ORM: this is a low-concurrency admin tool, not a
high-throughput service. Every public function here is synchronous; callers
from async code (both the asyncua handlers and the FastAPI routes) should
wrap calls in `asyncio.to_thread(...)`.

A single module-level connection is used with `check_same_thread=False` plus
a lock, which is simple and sufficient at this scale.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Optional

from gds.models import (
    ApplicationRecord,
    CertificateRecord,
    PushDeviceRecord,
    TrustListEntry,
    UserRecord,
    utcnow_iso,
)

_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    application_uri TEXT UNIQUE NOT NULL,
    application_name TEXT NOT NULL,
    application_type INTEGER NOT NULL,
    product_uri TEXT NOT NULL DEFAULT '',
    discovery_urls TEXT NOT NULL DEFAULT '[]',
    server_capabilities TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(id),
    certificate_group TEXT NOT NULL DEFAULT 'DefaultApplicationGroup',
    serial_number TEXT NOT NULL,
    subject TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    pem TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trust_list_entries (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    pem TEXT NOT NULL,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS push_devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    endpoint_url TEXT NOT NULL,
    security_policy_uri TEXT NOT NULL,
    security_mode TEXT NOT NULL,
    username TEXT NOT NULL,
    password_encrypted TEXT NOT NULL,
    regenerate_private_key INTEGER NOT NULL DEFAULT 1,
    trust_ca_on_device INTEGER NOT NULL DEFAULT 1,
    last_test_status TEXT NOT NULL DEFAULT 'untested',
    last_test_message TEXT NOT NULL DEFAULT '',
    last_test_at TEXT,
    last_push_status TEXT NOT NULL DEFAULT 'never',
    last_push_message TEXT NOT NULL DEFAULT '',
    last_push_at TEXT,
    last_crl_push_status TEXT NOT NULL DEFAULT 'never',
    last_crl_push_message TEXT NOT NULL DEFAULT '',
    last_crl_push_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings_kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    event TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
"""


def init_db(db_path: Path) -> None:
    global _conn
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _conn = sqlite3.connect(str(db_path), check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA foreign_keys = ON")
    with _lock:
        _conn.executescript(SCHEMA)
        _migrate_users_table()
        _migrate_push_devices_table()
        _conn.commit()


def _migrate_users_table() -> None:
    """Adds columns introduced after a users table may already exist on an
    already-deployed instance (CREATE TABLE IF NOT EXISTS doesn't add
    columns to an existing table) -- role/must_change_password were added
    for user management; this keeps upgrading in place safe."""
    existing = {row["name"] for row in _conn.execute("PRAGMA table_info(users)").fetchall()}
    if "role" not in existing:
        _conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
    if "must_change_password" not in existing:
        _conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")


def _migrate_push_devices_table() -> None:
    """Adds the last_crl_push_* columns for an already-deployed push_devices
    table (CRL push tracking was added after push devices already existed)."""
    existing = {row["name"] for row in _conn.execute("PRAGMA table_info(push_devices)").fetchall()}
    if "last_crl_push_status" not in existing:
        _conn.execute("ALTER TABLE push_devices ADD COLUMN last_crl_push_status TEXT NOT NULL DEFAULT 'never'")
    if "last_crl_push_message" not in existing:
        _conn.execute("ALTER TABLE push_devices ADD COLUMN last_crl_push_message TEXT NOT NULL DEFAULT ''")
    if "last_crl_push_at" not in existing:
        _conn.execute("ALTER TABLE push_devices ADD COLUMN last_crl_push_at TEXT")


def _c() -> sqlite3.Connection:
    if _conn is None:
        raise RuntimeError("db not initialized; call init_db() first")
    return _conn


def log_event(event: str, detail: str = "") -> None:
    with _lock:
        _c().execute(
            "INSERT INTO audit_log (id, event, detail, created_at) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), event, detail, utcnow_iso()),
        )
        _c().commit()


# --------------------------------------------------------------------------
# Applications
# --------------------------------------------------------------------------

def create_application(
    application_uri: str,
    application_name: str,
    application_type: int,
    product_uri: str = "",
    discovery_urls: Optional[list[str]] = None,
    server_capabilities: Optional[list[str]] = None,
) -> ApplicationRecord:
    now = utcnow_iso()
    with _lock:
        existing = _c().execute(
            "SELECT * FROM applications WHERE application_uri = ?", (application_uri,)
        ).fetchone()
        if existing is not None:
            # Re-registration: update fields, keep id + status (matches GDS semantics
            # where RegisterApplication with a known ApplicationUri updates the record).
            app_id = existing["id"]
            _c().execute(
                """UPDATE applications SET application_name=?, application_type=?,
                   product_uri=?, discovery_urls=?, server_capabilities=?, updated_at=?
                   WHERE id=?""",
                (
                    application_name,
                    application_type,
                    product_uri,
                    json.dumps(discovery_urls or []),
                    json.dumps(server_capabilities or []),
                    now,
                    app_id,
                ),
            )
            _c().commit()
            row = _c().execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
            return ApplicationRecord.from_row(row)

        app_id = str(uuid.uuid4())
        _c().execute(
            """INSERT INTO applications
               (id, application_uri, application_name, application_type, product_uri,
                discovery_urls, server_capabilities, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                app_id,
                application_uri,
                application_name,
                application_type,
                product_uri,
                json.dumps(discovery_urls or []),
                json.dumps(server_capabilities or []),
                "pending",
                now,
                now,
            ),
        )
        _c().commit()
        row = _c().execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
    log_event("application.register", application_uri)
    return ApplicationRecord.from_row(row)


def get_application(app_id: str) -> Optional[ApplicationRecord]:
    row = _c().execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
    return ApplicationRecord.from_row(row) if row else None


def get_application_by_uri(uri: str) -> Optional[ApplicationRecord]:
    row = _c().execute("SELECT * FROM applications WHERE application_uri=?", (uri,)).fetchone()
    return ApplicationRecord.from_row(row) if row else None


def find_applications(uri_substring: str = "") -> list[ApplicationRecord]:
    if uri_substring:
        rows = _c().execute(
            "SELECT * FROM applications WHERE application_uri LIKE ? ORDER BY created_at DESC",
            (f"%{uri_substring}%",),
        ).fetchall()
    else:
        rows = _c().execute("SELECT * FROM applications ORDER BY created_at DESC").fetchall()
    return [ApplicationRecord.from_row(r) for r in rows]


def set_application_status(app_id: str, status: str) -> None:
    with _lock:
        _c().execute(
            "UPDATE applications SET status=?, updated_at=? WHERE id=?",
            (status, utcnow_iso(), app_id),
        )
        _c().commit()
    log_event("application.status", f"{app_id} -> {status}")


def delete_application(app_id: str) -> None:
    with _lock:
        _c().execute("DELETE FROM certificates WHERE application_id=?", (app_id,))
        _c().execute("DELETE FROM applications WHERE id=?", (app_id,))
        _c().commit()
    log_event("application.unregister", app_id)


# --------------------------------------------------------------------------
# Certificates
# --------------------------------------------------------------------------

def add_certificate(
    application_id: str,
    serial_number: str,
    subject: str,
    not_before: str,
    not_after: str,
    pem: str,
    certificate_group: str = "DefaultApplicationGroup",
) -> CertificateRecord:
    cert_id = str(uuid.uuid4())
    now = utcnow_iso()
    with _lock:
        _c().execute(
            """INSERT INTO certificates
               (id, application_id, certificate_group, serial_number, subject,
                not_before, not_after, status, pem, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)""",
            (cert_id, application_id, certificate_group, serial_number, subject,
             not_before, not_after, pem, now),
        )
        _c().commit()
        row = _c().execute("SELECT * FROM certificates WHERE id=?", (cert_id,)).fetchone()
    log_event("certificate.issue", f"{application_id} serial={serial_number}")
    return CertificateRecord.from_row(row)


def get_certificate(cert_id: str) -> Optional[CertificateRecord]:
    row = _c().execute("SELECT * FROM certificates WHERE id=?", (cert_id,)).fetchone()
    return CertificateRecord.from_row(row) if row else None


def list_certificates(application_id: Optional[str] = None) -> list[CertificateRecord]:
    if application_id:
        rows = _c().execute(
            "SELECT * FROM certificates WHERE application_id=? ORDER BY created_at DESC",
            (application_id,),
        ).fetchall()
    else:
        rows = _c().execute("SELECT * FROM certificates ORDER BY created_at DESC").fetchall()
    return [CertificateRecord.from_row(r) for r in rows]


def revoke_certificate(cert_id: str) -> Optional[CertificateRecord]:
    with _lock:
        _c().execute("UPDATE certificates SET status='revoked' WHERE id=?", (cert_id,))
        _c().commit()
        row = _c().execute("SELECT * FROM certificates WHERE id=?", (cert_id,)).fetchone()
    log_event("certificate.revoke", cert_id)
    return CertificateRecord.from_row(row) if row else None


def active_certificates_for(application_id: str, certificate_group: str) -> list[CertificateRecord]:
    rows = _c().execute(
        """SELECT * FROM certificates WHERE application_id=? AND certificate_group=?
           AND status='active' ORDER BY created_at DESC""",
        (application_id, certificate_group),
    ).fetchall()
    return [CertificateRecord.from_row(r) for r in rows]


def all_revoked_certificates() -> list[CertificateRecord]:
    rows = _c().execute("SELECT * FROM certificates WHERE status='revoked'").fetchall()
    return [CertificateRecord.from_row(r) for r in rows]


# --------------------------------------------------------------------------
# Trust list entries (trusted/issuer certs & CRLs distributed to applications)
# --------------------------------------------------------------------------

def add_trust_list_entry(kind: str, label: str, pem: str) -> TrustListEntry:
    entry_id = str(uuid.uuid4())
    now = utcnow_iso()
    with _lock:
        _c().execute(
            "INSERT INTO trust_list_entries (id, kind, label, pem, added_at) VALUES (?, ?, ?, ?, ?)",
            (entry_id, kind, label, pem, now),
        )
        _c().commit()
        row = _c().execute("SELECT * FROM trust_list_entries WHERE id=?", (entry_id,)).fetchone()
    log_event("trustlist.add", f"{kind}:{label}")
    return TrustListEntry.from_row(row)


def list_trust_list_entries(kind: Optional[str] = None) -> list[TrustListEntry]:
    if kind:
        rows = _c().execute(
            "SELECT * FROM trust_list_entries WHERE kind=? ORDER BY added_at DESC", (kind,)
        ).fetchall()
    else:
        rows = _c().execute("SELECT * FROM trust_list_entries ORDER BY added_at DESC").fetchall()
    return [TrustListEntry.from_row(r) for r in rows]


def delete_trust_list_entry(entry_id: str) -> None:
    with _lock:
        _c().execute("DELETE FROM trust_list_entries WHERE id=?", (entry_id,))
        _c().commit()
    log_event("trustlist.delete", entry_id)


# --------------------------------------------------------------------------
# Push devices (OPC UA Part 12 push-mode targets configured via the web UI)
# --------------------------------------------------------------------------

def create_push_device(
    name: str,
    endpoint_url: str,
    security_policy_uri: str,
    security_mode: str,
    username: str,
    password_encrypted: str,
    regenerate_private_key: bool = True,
    trust_ca_on_device: bool = True,
) -> PushDeviceRecord:
    device_id = str(uuid.uuid4())
    now = utcnow_iso()
    with _lock:
        _c().execute(
            """INSERT INTO push_devices
               (id, name, endpoint_url, security_policy_uri, security_mode, username,
                password_encrypted, regenerate_private_key, trust_ca_on_device, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (device_id, name, endpoint_url, security_policy_uri, security_mode, username,
             password_encrypted, int(regenerate_private_key), int(trust_ca_on_device), now, now),
        )
        _c().commit()
        row = _c().execute("SELECT * FROM push_devices WHERE id=?", (device_id,)).fetchone()
    log_event("push_device.create", f"{name} ({endpoint_url})")
    return PushDeviceRecord.from_row(row)


def get_push_device(device_id: str) -> Optional[PushDeviceRecord]:
    row = _c().execute("SELECT * FROM push_devices WHERE id=?", (device_id,)).fetchone()
    return PushDeviceRecord.from_row(row) if row else None


def list_push_devices() -> list[PushDeviceRecord]:
    rows = _c().execute("SELECT * FROM push_devices ORDER BY created_at DESC").fetchall()
    return [PushDeviceRecord.from_row(r) for r in rows]


def update_push_device(
    device_id: str,
    name: str,
    endpoint_url: str,
    security_policy_uri: str,
    security_mode: str,
    username: str,
    regenerate_private_key: bool,
    trust_ca_on_device: bool,
    password_encrypted: Optional[str] = None,
) -> None:
    """Updates a push device's configuration. `password_encrypted` is
    optional so the edit form can leave the stored password untouched when
    the admin doesn't want to change it (never re-displayed once saved)."""
    with _lock:
        if password_encrypted is not None:
            _c().execute(
                """UPDATE push_devices SET name=?, endpoint_url=?, security_policy_uri=?,
                   security_mode=?, username=?, password_encrypted=?, regenerate_private_key=?,
                   trust_ca_on_device=?, updated_at=? WHERE id=?""",
                (name, endpoint_url, security_policy_uri, security_mode, username, password_encrypted,
                 int(regenerate_private_key), int(trust_ca_on_device), utcnow_iso(), device_id),
            )
        else:
            _c().execute(
                """UPDATE push_devices SET name=?, endpoint_url=?, security_policy_uri=?,
                   security_mode=?, username=?, regenerate_private_key=?,
                   trust_ca_on_device=?, updated_at=? WHERE id=?""",
                (name, endpoint_url, security_policy_uri, security_mode, username,
                 int(regenerate_private_key), int(trust_ca_on_device), utcnow_iso(), device_id),
            )
        _c().commit()
    log_event("push_device.update", device_id)


def delete_push_device(device_id: str) -> None:
    with _lock:
        _c().execute("DELETE FROM push_devices WHERE id=?", (device_id,))
        _c().commit()
    log_event("push_device.delete", device_id)


def record_push_device_test(device_id: str, status: str, message: str) -> None:
    with _lock:
        _c().execute(
            "UPDATE push_devices SET last_test_status=?, last_test_message=?, last_test_at=? WHERE id=?",
            (status, message, utcnow_iso(), device_id),
        )
        _c().commit()
    log_event("push_device.test", f"{device_id} -> {status}")


def record_push_device_push(device_id: str, status: str, message: str) -> None:
    with _lock:
        _c().execute(
            "UPDATE push_devices SET last_push_status=?, last_push_message=?, last_push_at=? WHERE id=?",
            (status, message, utcnow_iso(), device_id),
        )
        _c().commit()
    log_event("push_device.push", f"{device_id} -> {status}")


def record_push_device_crl_push(device_id: str, status: str, message: str) -> None:
    with _lock:
        _c().execute(
            "UPDATE push_devices SET last_crl_push_status=?, last_crl_push_message=?, last_crl_push_at=? WHERE id=?",
            (status, message, utcnow_iso(), device_id),
        )
        _c().commit()
    log_event("push_device.crl_push", f"{device_id} -> {status}")


# --------------------------------------------------------------------------
# Settings overrides (runtime-editable policy: cert validity, renewal
# threshold, CRL validity -- see web/routers/ca_settings.py). Anything not
# present here just keeps using gds.config.Settings' env-var-based default.
# --------------------------------------------------------------------------

def get_setting(key: str) -> Optional[str]:
    row = _c().execute("SELECT value FROM settings_kv WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(key: str, value: str) -> None:
    with _lock:
        _c().execute(
            "INSERT INTO settings_kv (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        _c().commit()
    log_event("settings.update", f"{key}={value}")


def all_settings() -> dict:
    rows = _c().execute("SELECT key, value FROM settings_kv").fetchall()
    return {r["key"]: r["value"] for r in rows}


OVERRIDABLE_INT_SETTINGS = (
    "issued_cert_valid_days", "renew_before_days", "crl_validity_days",
    "push_health_check_interval_seconds",
)
OVERRIDABLE_BOOL_SETTINGS = ("push_auto_reprovision_enabled",)


def apply_persisted_settings(settings) -> None:
    """Overwrites `settings`'s overridable fields in place with any values
    saved via the web UI's Settings page, so a restart keeps an admin's
    changes instead of reverting to the env-var defaults. Call once at
    startup, after init_db(), before the Settings object is handed to
    anything else."""
    for key in OVERRIDABLE_INT_SETTINGS:
        value = get_setting(key)
        if value is not None:
            setattr(settings, key, int(value))
    for key in OVERRIDABLE_BOOL_SETTINGS:
        value = get_setting(key)
        if value is not None:
            setattr(settings, key, value == "1")


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------

def create_user(
    username: str, password_hash: str, role: str = "admin", must_change_password: bool = False,
) -> UserRecord:
    """Raises sqlite3.IntegrityError if `username` already exists -- callers
    (the Users admin page) should treat that as "username taken", not
    silently overwrite an existing account."""
    now = utcnow_iso()
    with _lock:
        _c().execute(
            """INSERT INTO users (username, password_hash, role, must_change_password, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (username, password_hash, role, int(must_change_password), now),
        )
        _c().commit()
        row = _c().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    log_event("user.create", f"{username} ({role})")
    return UserRecord.from_row(row)


def get_user(username: str) -> Optional[UserRecord]:
    row = _c().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return UserRecord.from_row(row) if row else None


def list_users() -> list[UserRecord]:
    rows = _c().execute("SELECT * FROM users ORDER BY created_at ASC").fetchall()
    return [UserRecord.from_row(r) for r in rows]


def set_user_password(username: str, password_hash: str, must_change_password: bool = False) -> None:
    with _lock:
        _c().execute(
            "UPDATE users SET password_hash=?, must_change_password=? WHERE username=?",
            (password_hash, int(must_change_password), username),
        )
        _c().commit()
    log_event("user.password_change", username)


def set_user_role(username: str, role: str) -> None:
    with _lock:
        _c().execute("UPDATE users SET role=? WHERE username=?", (role, username))
        _c().commit()
    log_event("user.role_change", f"{username} -> {role}")


def delete_user(username: str) -> None:
    with _lock:
        _c().execute("DELETE FROM users WHERE username=?", (username,))
        _c().commit()
    log_event("user.delete", username)


def count_admins() -> int:
    row = _c().execute("SELECT COUNT(*) as c FROM users WHERE role='admin'").fetchone()
    return row["c"]


def any_users_exist() -> bool:
    row = _c().execute("SELECT COUNT(*) as c FROM users").fetchone()
    return row["c"] > 0


def recent_audit_log(limit: int = 50) -> list[sqlite3.Row]:
    return _c().execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()


def counts() -> dict:
    apps = _c().execute("SELECT status, COUNT(*) c FROM applications GROUP BY status").fetchall()
    certs = _c().execute("SELECT status, COUNT(*) c FROM certificates GROUP BY status").fetchall()
    return {
        "applications": {r["status"]: r["c"] for r in apps},
        "certificates": {r["status"]: r["c"] for r in certs},
    }
