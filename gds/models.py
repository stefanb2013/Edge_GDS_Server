"""Plain dataclasses used to move records between db.py, pki.py, the OPC UA
method handlers and the web layer. Kept independent of any ORM/UA library.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Optional


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApplicationType(IntEnum):
    SERVER = 0
    CLIENT = 1
    CLIENT_AND_SERVER = 2
    DISCOVERY_SERVER = 3


class ApplicationStatus:
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class CertificateStatus:
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class ApplicationRecord:
    id: str
    application_uri: str
    application_name: str
    application_type: int
    product_uri: str
    discovery_urls: list[str] = field(default_factory=list)
    server_capabilities: list[str] = field(default_factory=list)
    status: str = ApplicationStatus.PENDING
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)

    @property
    def discovery_hosts(self) -> list[str]:
        """host[:port] pulled out of each DiscoveryUrl (e.g.
        "opc.tcp://192.168.0.2:4840/gds/" -> "192.168.0.2:4840") -- shown on
        the Applications list so an admin can tell registered applications
        apart by address at a glance, without opening each one. Whatever the
        application declared as its own DiscoveryUrl -- may be a hostname,
        not necessarily a literal IP.
        """
        from urllib.parse import urlparse
        hosts = []
        for url in self.discovery_urls:
            hostname = urlparse(url).hostname
            if not hostname:
                continue
            port = urlparse(url).port
            hosts.append(f"{hostname}:{port}" if port else hostname)
        return hosts

    @classmethod
    def from_row(cls, row) -> "ApplicationRecord":
        return cls(
            id=row["id"],
            application_uri=row["application_uri"],
            application_name=row["application_name"],
            application_type=row["application_type"],
            product_uri=row["product_uri"],
            discovery_urls=json.loads(row["discovery_urls"] or "[]"),
            server_capabilities=json.loads(row["server_capabilities"] or "[]"),
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


@dataclass
class CertificateRecord:
    id: str
    application_id: str
    certificate_group: str
    serial_number: str
    subject: str
    not_before: str
    not_after: str
    status: str
    pem: str
    created_at: str = field(default_factory=utcnow_iso)

    @classmethod
    def from_row(cls, row) -> "CertificateRecord":
        return cls(
            id=row["id"],
            application_id=row["application_id"],
            certificate_group=row["certificate_group"],
            serial_number=row["serial_number"],
            subject=row["subject"],
            not_before=row["not_before"],
            not_after=row["not_after"],
            status=row["status"],
            pem=row["pem"],
            created_at=row["created_at"],
        )


class Role:
    ADMIN = "admin"
    USER = "user"


@dataclass
class UserRecord:
    username: str
    password_hash: str
    role: str = Role.ADMIN
    must_change_password: bool = False
    created_at: str = field(default_factory=utcnow_iso)

    @classmethod
    def from_row(cls, row) -> "UserRecord":
        return cls(
            username=row["username"],
            password_hash=row["password_hash"],
            role=row["role"],
            must_change_password=bool(row["must_change_password"]),
            created_at=row["created_at"],
        )


class PushCheckStatus:
    """Status of a push device's last connection test or push attempt --
    shared vocabulary so the web UI can render both with the same badge
    logic (see web/templates/devices.html)."""
    UNTESTED = "untested"
    NEVER = "never"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class PushDeviceRecord:
    id: str
    name: str
    endpoint_url: str
    security_policy_uri: str
    security_mode: str
    username: str
    password_encrypted: str
    regenerate_private_key: bool = True
    trust_ca_on_device: bool = True
    last_test_status: str = PushCheckStatus.UNTESTED
    last_test_message: str = ""
    last_test_at: Optional[str] = None
    last_push_status: str = PushCheckStatus.NEVER
    last_push_message: str = ""
    last_push_at: Optional[str] = None
    last_crl_push_status: str = PushCheckStatus.NEVER
    last_crl_push_message: str = ""
    last_crl_push_at: Optional[str] = None
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)

    @property
    def security_policy_name(self) -> str:
        return self.security_policy_uri.rsplit("#", 1)[-1]

    @classmethod
    def from_row(cls, row) -> "PushDeviceRecord":
        return cls(
            id=row["id"],
            name=row["name"],
            endpoint_url=row["endpoint_url"],
            security_policy_uri=row["security_policy_uri"],
            security_mode=row["security_mode"],
            username=row["username"],
            password_encrypted=row["password_encrypted"],
            regenerate_private_key=bool(row["regenerate_private_key"]),
            trust_ca_on_device=bool(row["trust_ca_on_device"]),
            last_test_status=row["last_test_status"],
            last_test_message=row["last_test_message"],
            last_test_at=row["last_test_at"],
            last_push_status=row["last_push_status"],
            last_push_message=row["last_push_message"],
            last_push_at=row["last_push_at"],
            last_crl_push_status=row["last_crl_push_status"],
            last_crl_push_message=row["last_crl_push_message"],
            last_crl_push_at=row["last_crl_push_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


@dataclass
class TrustListEntry:
    id: str
    kind: str  # trusted_cert | trusted_crl | issuer_cert | issuer_crl
    label: str
    pem: str
    added_at: str = field(default_factory=utcnow_iso)

    @classmethod
    def from_row(cls, row) -> "TrustListEntry":
        return cls(
            id=row["id"],
            kind=row["kind"],
            label=row["label"],
            pem=row["pem"],
            added_at=row["added_at"],
        )
