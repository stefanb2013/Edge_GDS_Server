"""Implementations of the GDS `Directory` object's methods.

This binds to the **real** OPC UA Part 12 information model imported from
the official `Opc.Ua.Gds.NodeSet2.xml` (see gds/opcua_server.py) -- real
NodeIds, real `ApplicationRecordDataType`/`TrustListDataType` structures,
real FileType-based trust list distribution. Any standards-conformant GDS
client (a real PLC's "managed certificate store" pull client included)
should be able to browse to `Directory` and call these directly.

All handlers are `async def handler(parent, *args) -> list[...]` per
asyncua's method-node calling convention (arguments already unwrapped from
`ua.Variant` by the small `_unwrap_variants` wrapper in opcua_server.py), and
do their DB/PKI work in a thread via `asyncio.to_thread` since gds.db/gds.pki
are synchronous.

Two synthetic identifier spaces are minted here, both String-typed NodeIds
under our own namespace (see `GdsContext.own_ids_ns` in opcua_server.py) so
they're unambiguously ours and never collide with real GDS/base-spec
NodeIds: ApplicationId (= our `applications.id` UUID) and RequestId (= our
`certificates.id` UUID, since a signing/key-pair request completes
synchronously into an already-issued certificate record).
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

from asyncua import ua

from gds import db, pki
from gds.config import Settings
from gds.models import ApplicationStatus

DEFAULT_CERTIFICATE_GROUP = "DefaultApplicationGroup"
_PENDING_KEY_TTL_SECONDS = 600


@dataclass
class GdsContext:
    ca: pki.RootCA
    settings: Settings
    # Encrypts/decrypts push-device passwords stored in the DB (see
    # gds/secrets_store.py) -- loaded once alongside the CA in main.py.
    secret_key: bytes = b""
    # Populated by opcua_server.create_server() once the real GDS address
    # space has been imported and browsed -- NodeIds are runtime-assigned by
    # asyncua on import, so these can't be module-level constants.
    own_ids_ns: int = 0
    default_group_nodeid: Optional[ua.NodeId] = None
    trust_list_nodeids: list = field(default_factory=list)

    # request_id (str) -> ((private_key_pem, requester_cert_pem), expires_at).
    # Populated only for StartNewKeyPairRequest (the GDS generated the key);
    # consumed exactly once by FinishRequest and never written to disk/DB.
    pending_keys: dict = field(default_factory=dict)

    # file_handle (int) -> (buffer_bytes, position). Populated by the
    # TrustList FileType's Open/OpenWithMasks, consumed by Read, freed by
    # Close. Not persisted -- a live download in progress only.
    open_files: dict = field(default_factory=dict)
    _next_file_handle: int = 1

    def wrap_id(self, internal_id: str) -> ua.NodeId:
        return ua.NodeId(Identifier=internal_id, NamespaceIndex=self.own_ids_ns, NodeIdType=ua.NodeIdType.String)

    def unwrap_id(self, node_id: ua.NodeId) -> str:
        return str(node_id.Identifier)

    def stash_key(self, request_id: str, payload: tuple) -> None:
        self.pending_keys[request_id] = (payload, time.time() + _PENDING_KEY_TTL_SECONDS)

    def pop_key(self, request_id: str) -> Optional[tuple]:
        self._gc()
        entry = self.pending_keys.pop(request_id, None)
        return entry[0] if entry else None

    def _gc(self) -> None:
        now = time.time()
        expired = [k for k, (_, exp) in self.pending_keys.items() if exp < now]
        for k in expired:
            self.pending_keys.pop(k, None)

    def open_file(self, data: bytes) -> int:
        handle = self._next_file_handle
        self._next_file_handle += 1
        self.open_files[handle] = [data, 0]
        return handle


def _require_approved(app) -> None:
    if app is None:
        raise ua.uaerrors.BadNodeIdUnknown("Unknown ApplicationId")
    if app.status != ApplicationStatus.APPROVED:
        raise ua.uaerrors.BadUserAccessDenied(
            f"Application is '{app.status}', not approved by a GDS administrator yet"
        )


def _to_application_record(ctx: GdsContext, app) -> ua.ApplicationRecordDataType:
    rec = ua.ApplicationRecordDataType()
    rec.ApplicationId = ctx.wrap_id(app.id)
    rec.ApplicationUri = app.application_uri
    rec.ApplicationType = ua.ApplicationType(app.application_type)
    rec.ApplicationNames = [ua.LocalizedText(app.application_name)]
    rec.ProductUri = app.product_uri
    rec.DiscoveryUrls = list(app.discovery_urls)
    rec.ServerCapabilities = list(app.server_capabilities)
    return rec


def build_handlers(ctx: GdsContext) -> dict:
    """Returns {method_name: async_callable} to be linked to method nodes."""

    async def register_application(parent, record: ua.ApplicationRecordDataType):
        application_name = record.ApplicationNames[0].Text if record.ApplicationNames else record.ApplicationUri
        app = await asyncio.to_thread(
            db.create_application,
            record.ApplicationUri,
            application_name,
            int(record.ApplicationType),
            record.ProductUri or "",
            list(record.DiscoveryUrls or []),
            list(record.ServerCapabilities or []),
        )
        return [ua.Variant(ctx.wrap_id(app.id), ua.VariantType.NodeId)]

    async def unregister_application(parent, application_id: ua.NodeId):
        await asyncio.to_thread(db.delete_application, ctx.unwrap_id(application_id))
        return []

    async def find_applications(parent, application_uri: str):
        apps = await asyncio.to_thread(db.find_applications, application_uri)
        records = [_to_application_record(ctx, a) for a in apps]
        return [ua.Variant(records, ua.VariantType.ExtensionObject)]

    async def get_certificate_groups(parent, application_id: ua.NodeId):
        app = await asyncio.to_thread(db.get_application, ctx.unwrap_id(application_id))
        _require_approved(app)
        return [ua.Variant([ctx.default_group_nodeid], ua.VariantType.NodeId)]

    async def get_trust_list(parent, application_id: ua.NodeId, certificate_group_id: ua.NodeId):
        app = await asyncio.to_thread(db.get_application, ctx.unwrap_id(application_id))
        _require_approved(app)
        # v1 scope: one certificate group, so every group id maps to the same
        # trust list regardless of which of the group's own NodeId was passed.
        return [ua.Variant(ctx.trust_list_nodeids[0], ua.VariantType.NodeId)]

    async def start_signing_request(parent, application_id: ua.NodeId, certificate_group_id: ua.NodeId,
                                     certificate_type_id: ua.NodeId, certificate_request: bytes):
        app = await asyncio.to_thread(db.get_application, ctx.unwrap_id(application_id))
        _require_approved(app)

        def _issue():
            csr_pem = certificate_request  # accept either PEM or DER
            if isinstance(csr_pem, (bytes, bytearray)) and not csr_pem.lstrip().startswith(b"-----BEGIN"):
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                csr_pem = x509.load_der_x509_csr(bytes(csr_pem)).public_bytes(serialization.Encoding.PEM)
            issued = pki.issue_from_csr(
                ctx.ca, csr_pem.decode() if isinstance(csr_pem, (bytes, bytearray)) else csr_pem,
                app.application_uri, ctx.settings.issued_cert_valid_days,
            )
            rec = db.add_certificate(
                application_id=app.id,
                serial_number=issued.serial_hex,
                subject=issued.subject,
                not_before=issued.not_before,
                not_after=issued.not_after,
                pem=issued.cert_pem,
                certificate_group=DEFAULT_CERTIFICATE_GROUP,
            )
            return rec.id

        cert_record_id = await asyncio.to_thread(_issue)
        return [ua.Variant(ctx.wrap_id(cert_record_id), ua.VariantType.NodeId)]

    async def start_new_key_pair_request(parent, application_id: ua.NodeId, certificate_group_id: ua.NodeId,
                                          certificate_type_id: ua.NodeId, subject_name: str, domain_names,
                                          private_key_format: str, private_key_password: str):
        app = await asyncio.to_thread(db.get_application, ctx.unwrap_id(application_id))
        _require_approved(app)
        domains = list(domain_names or [])

        def _issue():
            pair = pki.generate_key_pair_and_cert(
                ctx.ca, app.application_uri, subject_name or app.application_name,
                dns_names=domains, ip_addresses=[],
                valid_days=ctx.settings.issued_cert_valid_days,
            )
            rec = db.add_certificate(
                application_id=app.id,
                serial_number=pair.issued.serial_hex,
                subject=pair.issued.subject,
                not_before=pair.issued.not_before,
                not_after=pair.issued.not_after,
                pem=pair.issued.cert_pem,
                certificate_group=DEFAULT_CERTIFICATE_GROUP,
            )
            return rec.id, pair.private_key_pem

        cert_record_id, private_key_pem = await asyncio.to_thread(_issue)
        # Protect the new private key with an envelope addressed to a
        # certificate the requester already holds the matching private key
        # for. Real GDS-pull clients don't have a prior GDS-issued cert to
        # offer on their very first request, so PrivateKeyPassword doubles as
        # that wrapping material isn't modeled here (out of v1 scope,
        # documented in README); we fall back to relying on the secure
        # channel's own encryption when no PEM cert is supplied there.
        wrap_cert_pem = private_key_password if (private_key_password or "").lstrip().startswith("-----BEGIN") else ""
        ctx.stash_key(cert_record_id, (private_key_pem, wrap_cert_pem))
        return [ua.Variant(ctx.wrap_id(cert_record_id), ua.VariantType.NodeId)]

    async def finish_request(parent, application_id: ua.NodeId, request_id: ua.NodeId):
        app = await asyncio.to_thread(db.get_application, ctx.unwrap_id(application_id))
        _require_approved(app)
        cert_record_id = ctx.unwrap_id(request_id)
        cert = await asyncio.to_thread(db.get_certificate, cert_record_id)
        if cert is None or cert.application_id != app.id:
            raise ua.uaerrors.BadNodeIdUnknown("Unknown RequestId")

        stashed = ctx.pop_key(cert_record_id)
        if stashed is not None:
            private_key_pem, requester_cert_pem = stashed
            if requester_cert_pem:
                key_blob = await asyncio.to_thread(
                    pki.hybrid_encrypt_for_client, private_key_pem.encode(), requester_cert_pem
                )
            else:
                key_blob = private_key_pem.encode()
        else:
            key_blob = b""

        return [
            ua.Variant(cert.pem.encode(), ua.VariantType.ByteString),
            ua.Variant(key_blob, ua.VariantType.ByteString),
            ua.Variant([ctx.ca.cert_pem.encode()], ua.VariantType.ByteString),
        ]

    async def get_certificate_status(parent, application_id: ua.NodeId, certificate_group_id: ua.NodeId,
                                      certificate_type_id: ua.NodeId):
        app = await asyncio.to_thread(db.get_application, ctx.unwrap_id(application_id))
        _require_approved(app)
        certs = await asyncio.to_thread(db.active_certificates_for, app.id, DEFAULT_CERTIFICATE_GROUP)

        def _update_required() -> bool:
            if not certs:
                return True
            from datetime import datetime, timedelta, timezone
            not_after = datetime.fromisoformat(certs[0].not_after)
            return not_after < datetime.now(timezone.utc) + timedelta(days=ctx.settings.renew_before_days)

        return [ua.Variant(_update_required(), ua.VariantType.Boolean)]

    async def revoke_certificate(parent, application_id: ua.NodeId, certificate: bytes):
        app = await asyncio.to_thread(db.get_application, ctx.unwrap_id(application_id))
        _require_approved(app)

        def _revoke():
            from cryptography import x509
            leaf = x509.load_der_x509_certificate(bytes(certificate))
            serial_hex = format(leaf.serial_number, "x")
            for c in db.list_certificates(app.id):
                if c.serial_number == serial_hex:
                    db.revoke_certificate(c.id)
                    return True
            return False

        found = await asyncio.to_thread(_revoke)
        if not found:
            raise ua.uaerrors.BadNodeIdUnknown("Certificate not found for this application")
        return []

    return {
        "RegisterApplication": register_application,
        "UnregisterApplication": unregister_application,
        "FindApplications": find_applications,
        "GetCertificateGroups": get_certificate_groups,
        "GetTrustList": get_trust_list,
        "StartSigningRequest": start_signing_request,
        "StartNewKeyPairRequest": start_new_key_pair_request,
        "FinishRequest": finish_request,
        "GetCertificateStatus": get_certificate_status,
        "RevokeCertificate": revoke_certificate,
    }


# --------------------------------------------------------------------------
# TrustList FileType (Open/OpenWithMasks/Read/Close/GetPosition), bound to
# each of the nodeset's pre-built .../CertificateGroups/*/TrustList nodes.
# --------------------------------------------------------------------------

TRUST_LIST_MASK_TRUSTED_CERTS = 1
TRUST_LIST_MASK_TRUSTED_CRLS = 2
TRUST_LIST_MASK_ISSUER_CERTS = 4
TRUST_LIST_MASK_ISSUER_CRLS = 8
TRUST_LIST_MASK_ALL = 15


def _pem_certs_to_der(pems: list[str]) -> list[bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    return [x509.load_pem_x509_certificate(p.encode()).public_bytes(serialization.Encoding.DER) for p in pems]


def _pem_crls_to_der(pems: list[str]) -> list[bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    return [x509.load_pem_x509_crl(p.encode()).public_bytes(serialization.Encoding.DER) for p in pems]


def build_trust_list_data_type(ctx: GdsContext, masks: int) -> ua.TrustListDataType:
    """Builds the real, spec-shaped structure -- distinct from
    gds.pki.trust_list_bundle_pem(), which is the plain-PEM bundle used by
    the web UI and (as a documented simplification) by nothing else now.
    """
    tl = ua.TrustListDataType()
    tl.SpecifiedLists = masks

    def _revoked_serials() -> list[str]:
        return [c.serial_number for c in db.all_revoked_certificates()]

    crl_pem = pki.build_crl(ctx.ca, _revoked_serials(), ctx.settings.crl_validity_days)
    trusted_cert_pems = [e.pem for e in db.list_trust_list_entries("trusted_cert")]
    trusted_crl_pems = [e.pem for e in db.list_trust_list_entries("trusted_crl")]
    issuer_cert_pems = [e.pem for e in db.list_trust_list_entries("issuer_cert")]
    issuer_crl_pems = [e.pem for e in db.list_trust_list_entries("issuer_crl")]

    tl.TrustedCertificates = (
        _pem_certs_to_der([ctx.ca.cert_pem, *trusted_cert_pems]) if masks & TRUST_LIST_MASK_TRUSTED_CERTS else []
    )
    tl.TrustedCrls = _pem_crls_to_der([crl_pem, *trusted_crl_pems]) if masks & TRUST_LIST_MASK_TRUSTED_CRLS else []
    tl.IssuerCertificates = _pem_certs_to_der(issuer_cert_pems) if masks & TRUST_LIST_MASK_ISSUER_CERTS else []
    tl.IssuerCrls = _pem_crls_to_der(issuer_crl_pems) if masks & TRUST_LIST_MASK_ISSUER_CRLS else []
    return tl


def build_trust_list_file_handlers(ctx: GdsContext) -> dict:
    from asyncua.ua.ua_binary import struct_to_binary

    def _build_and_open(masks: int) -> int:
        data = struct_to_binary(build_trust_list_data_type(ctx, masks))
        return ctx.open_file(data)

    async def open_(parent, mode: int):
        handle = await asyncio.to_thread(_build_and_open, TRUST_LIST_MASK_ALL)
        return [ua.Variant(handle, ua.VariantType.UInt32)]

    async def open_with_masks(parent, masks: int):
        handle = await asyncio.to_thread(_build_and_open, int(masks))
        return [ua.Variant(handle, ua.VariantType.UInt32)]

    async def read(parent, file_handle: int, length: int):
        state = ctx.open_files.get(file_handle)
        if state is None:
            raise ua.uaerrors.BadInvalidArgument("Unknown or already-closed FileHandle")
        data, pos = state
        chunk = data[pos:] if length < 0 else data[pos:pos + length]
        state[1] = pos + len(chunk)
        return [ua.Variant(bytes(chunk), ua.VariantType.ByteString)]

    async def get_position(parent, file_handle: int):
        state = ctx.open_files.get(file_handle)
        if state is None:
            raise ua.uaerrors.BadInvalidArgument("Unknown or already-closed FileHandle")
        return [ua.Variant(state[1], ua.VariantType.UInt64)]

    async def close(parent, file_handle: int):
        ctx.open_files.pop(file_handle, None)
        return []

    return {
        "Open": open_,
        "OpenWithMasks": open_with_masks,
        "Read": read,
        "GetPosition": get_position,
        "Close": close,
    }
