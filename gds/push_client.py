"""OPC UA push-mode certificate provisioning.

The counterpart to gds/opcua_server.py's pull-mode Directory: instead of a
device pulling a certificate from this GDS, this module connects *to a
device's own OPC UA server* as an authenticated admin client and installs a
certificate on it directly, via the standard `ServerConfiguration` object
(OPC UA Part 12) -- for devices that don't (or can't, or won't) run a
GDS-pull client themselves.

The exact NodeIds and argument shapes used here were confirmed empirically
against a real device during development (see the project's README/plan
history) rather than assumed from the spec text alone:

  ServerConfiguration                          ns=0;i=12637 (fixed base-spec NodeId)
  .CreateSigningRequest(CertificateGroupId, CertificateTypeId,
                         SubjectName, RegeneratePrivateKey, Nonce)
      -> CertificateRequest: ByteString
  .UpdateCertificate(CertificateGroupId, CertificateTypeId, Certificate,
                      IssuerCertificates[], PrivateKeyFormat, PrivateKey)
      -> ApplyChangesRequired: Boolean
  .ApplyChanges()
  .CertificateGroups/DefaultApplicationGroup/TrustList
      .AddCertificate(Certificate, IsTrustedCertificate)
      .Open(Mode: Byte) -> FileHandle: UInt32              (Mode: Write=2, EraseExisting=4)
      .Write(FileHandle, Data: ByteString)
      .CloseAndUpdate(FileHandle) -> ApplyChangesRequired: Boolean

The last three back this module's push_crl(): unlike certificates, there is
no single-shot "AddCrl" method in the base spec -- a CRL is installed by
writing a whole encoded TrustListDataType (with only the lists you're
updating set, per SpecifiedLists) through the TrustList's own FileType
Open/Write/CloseAndUpdate, then ApplyChanges() same as a certificate update.
Confirmed against the real device by round-tripping: after a push_crl() call,
re-reading the TrustList back out (Open(Read)/Read/Close) showed the new CRL
in place and the previously-added trusted certificates undisturbed.

Since the device generates and keeps its own private key
(RegeneratePrivateKey=True), the private key never has to cross the network
-- a cleaner story than the pull flow's server-generated-key option.
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from asyncua import Client, ua
from asyncua.ua.ua_binary import struct_to_binary
from asyncua.crypto.security_policies import (
    SecurityPolicyAes128Sha256RsaOaep,
    SecurityPolicyAes256Sha256RsaPss,
    SecurityPolicyBasic128Rsa15,
    SecurityPolicyBasic256,
    SecurityPolicyBasic256Sha256,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from gds import db, pki, secrets_store
from gds.config import Settings
from gds.models import ApplicationStatus, ApplicationType, PushCheckStatus, PushDeviceRecord

logger = logging.getLogger("gds.push_client")

SERVER_CONFIGURATION_NODEID = ua.NodeId(12637, 0)
RSA_SHA256_CERT_TYPE = ua.NodeId(ua.ObjectIds.RsaSha256ApplicationCertificateType, 0)
DEFAULT_APPLICATION_GROUP = "0:DefaultApplicationGroup"
PUSH_CLIENT_APPLICATION_URI = "urn:gds:push-client"

# Secured policies this client knows how to speak, keyed by their wire URI.
# Deliberately excludes SecurityPolicyNone: the push flow always authenticates
# with a username/password identity token and installs a certificate, and an
# unsecured channel can't carry either safely.
SECURITY_POLICIES: dict[str, type] = {
    SecurityPolicyBasic128Rsa15.URI: SecurityPolicyBasic128Rsa15,
    SecurityPolicyBasic256.URI: SecurityPolicyBasic256,
    SecurityPolicyBasic256Sha256.URI: SecurityPolicyBasic256Sha256,
    SecurityPolicyAes128Sha256RsaOaep.URI: SecurityPolicyAes128Sha256RsaOaep,
    SecurityPolicyAes256Sha256RsaPss.URI: SecurityPolicyAes256Sha256RsaPss,
}


def _resolve_security_policy(security_policy_uri: str, security_mode: ua.MessageSecurityMode) -> type:
    if security_mode == ua.MessageSecurityMode.None_:
        raise ValueError(
            "Push mode needs a signed/encrypted channel (it authenticates with a "
            "password and installs a private certificate) -- SecurityMode None isn't usable here."
        )
    policy_cls = SECURITY_POLICIES.get(security_policy_uri)
    if policy_cls is None:
        raise ValueError(f"Unsupported security policy for push mode: {security_policy_uri!r}")
    return policy_cls


@dataclass
class PushResult:
    device_application_uri: str
    serial_hex: str
    subject: str
    not_after: str
    apply_changes_required: bool
    certificate_record_id: str
    application_id: str


@dataclass
class EndpointInfo:
    """One entry from a device's own GetEndpoints response -- the "browse
    for OPC UA servers" step of push-mode setup surfaces these so an admin
    can pick which security policy/mode to configure, the same way UaExpert's
    "double click a server, then choose an endpoint" flow works."""
    endpoint_url: str
    security_policy_uri: str
    security_mode: str
    security_level: int
    server_application_uri: str
    server_application_name: str
    server_certificate_subject: str = ""

    @property
    def security_policy_name(self) -> str:
        return self.security_policy_uri.rsplit("#", 1)[-1]

    @property
    def usable_for_push(self) -> bool:
        return (
            self.security_mode != ua.MessageSecurityMode.None_.name
            and self.security_policy_uri in SECURITY_POLICIES
        )


async def discover_endpoints(endpoint_url: str, request_timeout: float = 10.0) -> list[EndpointInfo]:
    """Opens a throwaway, unencrypted channel to `endpoint_url` just long
    enough to list what it offers, then disconnects -- no credentials are
    needed or used here. Most devices (this one's real B&R PLC included)
    refuse anonymous *sessions* but still hand out GetEndpoints on an
    unsecured channel, since that's how every OPC UA client is expected to
    find out what security it needs to use in the first place.

    Results are sorted richest-security-first (matching the SecurityLevel
    ordering the server itself assigns), so the best usable option is the
    natural default in the web UI's endpoint picker.
    """
    client = Client(url=endpoint_url, timeout=request_timeout)
    endpoints = await client.connect_and_get_server_endpoints()
    results = []
    for ep in endpoints:
        subject = ""
        if ep.ServerCertificate:
            try:
                subject = x509.load_der_x509_certificate(bytes(ep.ServerCertificate)).subject.rfc4514_string()
            except Exception:
                subject = ""
        app_name = ""
        if ep.Server and ep.Server.ApplicationName:
            app_name = ep.Server.ApplicationName.Text or ""
        results.append(EndpointInfo(
            endpoint_url=ep.EndpointUrl,
            security_policy_uri=ep.SecurityPolicyUri,
            security_mode=ep.SecurityMode.name,
            security_level=ep.SecurityLevel,
            server_application_uri=ep.Server.ApplicationUri if ep.Server else "",
            server_application_name=app_name,
            server_certificate_subject=subject,
        ))
    results.sort(key=lambda e: e.security_level, reverse=True)
    return results


@dataclass
class ConnectionTestResult:
    success: bool
    message: str
    server_application_uri: str = ""
    has_server_configuration: bool = False


async def test_connection(
    endpoint_url: str,
    username: str,
    password: str,
    settings: Settings,
    *,
    security_policy_uri: str = SecurityPolicyBasic256Sha256.URI,
    security_mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt,
    request_timeout: float = 30.0,
) -> ConnectionTestResult:
    """Authenticates against `endpoint_url` with the given credentials and
    security settings, then confirms the device actually exposes the
    standard `ServerConfiguration` object before disconnecting.

    That last check matters: without it, "wrong password" and "this device
    doesn't support push mode at all" would both surface identically once
    you got as far as CreateSigningRequest -- this gives the web UI's "Test
    connection" button a real answer either way, before anyone commits to
    typing in credentials permanently.
    """
    try:
        policy_cls = _resolve_security_policy(security_policy_uri, security_mode)
    except ValueError as exc:
        return ConnectionTestResult(success=False, message=str(exc))

    key_path, cert_path = _ensure_push_client_identity(settings)
    client = Client(url=endpoint_url, timeout=request_timeout, watchdog_intervall=max(300.0, request_timeout * 5))
    client.application_uri = PUSH_CLIENT_APPLICATION_URI
    client.set_user(username)
    client.set_password(password)
    try:
        await client.set_security(
            policy_cls, certificate=cert_path, private_key=key_path, mode=security_mode,
        )
    except Exception as exc:
        return ConnectionTestResult(success=False, message=f"Could not prepare secure channel: {exc}")

    try:
        async with client:
            endpoints = await client.get_endpoints()
            device_application_uri = endpoints[0].Server.ApplicationUri if endpoints else ""
            has_server_configuration = True
            try:
                server_config = client.get_node(SERVER_CONFIGURATION_NODEID)
                await server_config.get_child("0:CreateSigningRequest")
            except Exception:
                has_server_configuration = False
    except Exception as exc:
        return ConnectionTestResult(success=False, message=f"{type(exc).__name__}: {exc}")

    if not has_server_configuration:
        return ConnectionTestResult(
            success=False,
            message="Connected and authenticated, but this device does not expose a standard "
                    "ServerConfiguration/CreateSigningRequest -- it doesn't support OPC UA push-mode "
                    "certificate provisioning.",
            server_application_uri=device_application_uri,
            has_server_configuration=False,
        )
    return ConnectionTestResult(
        success=True,
        message="Connected, authenticated, and confirmed push-mode (ServerConfiguration) support.",
        server_application_uri=device_application_uri,
        has_server_configuration=True,
    )


def _ensure_push_client_identity(settings: Settings) -> tuple[str, str]:
    """A persistent self-signed identity, generated once and reused for
    every push -- unlike a fresh throwaway cert per call, this lets a device
    eventually be locked down to trust this one specific client certificate.
    """
    d = settings.pki_dir / "push_client"
    d.mkdir(parents=True, exist_ok=True)
    key_path = d / "client_key.pem"
    cert_path = d / "client_cert.pem"
    if not (key_path.exists() and cert_path.exists()):
        key_pem, cert_pem = pki.generate_self_signed_app_cert(
            application_uri=PUSH_CLIENT_APPLICATION_URI,
            common_name="GDS Push Client",
            hostname=settings.hostname,
            valid_days=3650,
        )
        key_path.write_text(key_pem)
        cert_path.write_text(cert_pem)
    return str(key_path), str(cert_path)


def _record_pushed_certificate(device_application_uri: str, endpoint_url: str, issued: pki.IssuedCertificate):
    app = db.get_application_by_uri(device_application_uri)
    if app is None:
        app = db.create_application(
            application_uri=device_application_uri,
            application_name=device_application_uri,
            application_type=int(ApplicationType.SERVER),
            discovery_urls=[endpoint_url],
        )
    # A human deliberately pushed to this device -- treat it as approved,
    # same status a pull-mode admin approval would leave it in.
    db.set_application_status(app.id, ApplicationStatus.APPROVED)
    cert = db.add_certificate(
        application_id=app.id,
        serial_number=issued.serial_hex,
        subject=issued.subject,
        not_before=issued.not_before,
        not_after=issued.not_after,
        pem=issued.cert_pem,
    )
    return app.id, cert.id


async def push_certificate(
    endpoint_url: str,
    username: str,
    password: str,
    ca: pki.RootCA,
    settings: Settings,
    *,
    security_policy_uri: str = SecurityPolicyBasic256Sha256.URI,
    security_mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt,
    regenerate_private_key: bool = True,
    trust_ca_on_device: bool = True,
    request_timeout: float = 60.0,
    progress: Optional[Callable[[str], None]] = None,
) -> PushResult:
    """Connects to `endpoint_url` as an authenticated admin client and
    pushes a certificate signed by `ca` onto it via the standard
    ServerConfiguration push flow. `progress`, if given, is called with
    short human-readable status strings as the flow proceeds.

    `request_timeout` defaults well above asyncua's own 4-second default:
    `CreateSigningRequest` with `RegeneratePrivateKey=True` asks the device
    to generate a fresh RSA key pair itself, which can take much longer than
    4 seconds on constrained hardware -- a plain request timeout there looks
    exactly like a hang, not a slow-but-successful call.

    Separately from that per-request timeout, asyncua also runs a background
    connection-health watchdog that periodically probes the server and tears
    the connection down (`ConnectionError: client is disconnected`) if a
    probe doesn't answer in time -- observed happening *during* a slow
    `UpdateCertificate` call against a real device, because its single-
    threaded OPC UA stack can't answer the health probe while still busy
    with our own request. `watchdog_intervall` below is set to something
    comfortably longer than this whole flow ever takes, so that background
    probe realistically never fires during a push -- appropriate here since
    this is a short-lived one-shot admin connection, not a long-running
    monitored session.
    """

    def report(msg: str) -> None:
        if progress:
            progress(msg)

    policy_cls = _resolve_security_policy(security_policy_uri, security_mode)
    key_path, cert_path = _ensure_push_client_identity(settings)

    client = Client(url=endpoint_url, timeout=request_timeout, watchdog_intervall=max(300.0, request_timeout * 5))
    client.application_uri = PUSH_CLIENT_APPLICATION_URI
    client.set_user(username)
    client.set_password(password)
    await client.set_security(
        policy_cls,
        certificate=cert_path,
        private_key=key_path,
        mode=security_mode,
    )

    report(f"Connecting to {endpoint_url} as {username} ...")
    async with client:
        endpoints = await client.get_endpoints()
        device_application_uri = endpoints[0].Server.ApplicationUri if endpoints else endpoint_url
        report(f"Connected. Device ApplicationUri: {device_application_uri}")

        server_config = client.get_node(SERVER_CONFIGURATION_NODEID)
        cert_groups = await server_config.get_child("0:CertificateGroups")
        default_group = await cert_groups.get_child(DEFAULT_APPLICATION_GROUP)

        report("Requesting a certificate signing request from the device ...")
        create_csr = await server_config.get_child("0:CreateSigningRequest")
        csr_der = await server_config.call_method(
            create_csr,
            ua.Variant(default_group.nodeid, ua.VariantType.NodeId),
            ua.Variant(RSA_SHA256_CERT_TYPE, ua.VariantType.NodeId),
            ua.Variant("", ua.VariantType.String),
            ua.Variant(regenerate_private_key, ua.VariantType.Boolean),
            ua.Variant(os.urandom(32), ua.VariantType.ByteString),
        )

        report("Signing the CSR with the GDS root CA ...")
        csr_pem = x509.load_der_x509_csr(bytes(csr_der)).public_bytes(serialization.Encoding.PEM).decode()
        # verify_signature=False: some devices' CreateSigningRequest produces a CSR whose own
        # self-signature doesn't verify (see gds.pki.issue_from_csr's docstring) -- the trust
        # boundary here is the authenticated admin session we fetched this CSR over, not the
        # CSR's self-signature, so that check isn't the thing protecting this flow anyway.
        issued = pki.issue_from_csr(
            ca, csr_pem, device_application_uri, settings.issued_cert_valid_days, verify_signature=False
        )
        cert_der = x509.load_pem_x509_certificate(issued.cert_pem.encode()).public_bytes(serialization.Encoding.DER)
        ca_der = x509.load_pem_x509_certificate(ca.cert_pem.encode()).public_bytes(serialization.Encoding.DER)

        report("Installing the signed certificate on the device ...")
        update_certificate = await server_config.get_child("0:UpdateCertificate")
        apply_changes_required = await server_config.call_method(
            update_certificate,
            ua.Variant(default_group.nodeid, ua.VariantType.NodeId),
            ua.Variant(RSA_SHA256_CERT_TYPE, ua.VariantType.NodeId),
            ua.Variant(bytes(cert_der), ua.VariantType.ByteString),
            ua.Variant([bytes(ca_der)], ua.VariantType.ByteString),
            ua.Variant("", ua.VariantType.String),
            ua.Variant(b"", ua.VariantType.ByteString),
        )

        if trust_ca_on_device:
            report("Adding the GDS root CA to the device's own trust list ...")
            trust_list = await default_group.get_child("0:TrustList")
            add_certificate = await trust_list.get_child("0:AddCertificate")
            await trust_list.call_method(
                add_certificate,
                ua.Variant(bytes(ca_der), ua.VariantType.ByteString),
                ua.Variant(True, ua.VariantType.Boolean),
            )

        if apply_changes_required:
            report("Applying changes on the device -- it may restart its OPC UA endpoint now ...")
            apply_changes = await server_config.get_child("0:ApplyChanges")
            try:
                await server_config.call_method(apply_changes)
            except Exception:
                # The device commonly drops the connection immediately when
                # it restarts its endpoint to pick up the new certificate --
                # that's the expected outcome here, not a failure.
                report("Device dropped the connection while applying changes (expected).")

    application_id, certificate_record_id = await asyncio.to_thread(
        _record_pushed_certificate, device_application_uri, endpoint_url, issued
    )

    return PushResult(
        device_application_uri=device_application_uri,
        serial_hex=issued.serial_hex,
        subject=issued.subject,
        not_after=issued.not_after,
        apply_changes_required=bool(apply_changes_required),
        certificate_record_id=certificate_record_id,
        application_id=application_id,
    )


@dataclass
class CrlPushResult:
    revoked_count: int
    apply_changes_required: bool


async def push_crl(
    endpoint_url: str,
    username: str,
    password: str,
    ca: pki.RootCA,
    settings: Settings,
    *,
    security_policy_uri: str = SecurityPolicyBasic256Sha256.URI,
    security_mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt,
    request_timeout: float = 60.0,
    progress: Optional[Callable[[str], None]] = None,
) -> CrlPushResult:
    """Writes this GDS's current CRL into a device's own TrustList, so a
    device that already trusts our CA (via push_certificate's
    trust_ca_on_device, or a manual trust-list upload) also learns about
    certificates we've since revoked -- closing the gap push mode otherwise
    has versus pull mode, where GetTrustList always hands out a fresh CRL.

    Only the TrustedCrls list is touched (SpecifiedLists =
    TrustListMasks.TrustedCrls): trusted/issuer certificates already on the
    device are read back untouched by the device itself, since Write only
    replaces the lists named in SpecifiedLists -- confirmed by reading the
    device's TrustList back after a push_crl() call during development.
    """

    def report(msg: str) -> None:
        if progress:
            progress(msg)

    policy_cls = _resolve_security_policy(security_policy_uri, security_mode)
    key_path, cert_path = _ensure_push_client_identity(settings)

    report("Building the current CRL ...")
    revoked_serials = [c.serial_number for c in await asyncio.to_thread(db.all_revoked_certificates)]
    crl_pem = await asyncio.to_thread(pki.build_crl, ca, revoked_serials, settings.crl_validity_days)
    crl_der = x509.load_pem_x509_crl(crl_pem.encode()).public_bytes(serialization.Encoding.DER)

    tl = ua.TrustListDataType()
    tl.SpecifiedLists = int(ua.TrustListMasks.TrustedCrls)
    tl.TrustedCertificates = []
    tl.TrustedCrls = [crl_der]
    tl.IssuerCertificates = []
    tl.IssuerCrls = []
    encoded = struct_to_binary(tl)

    client = Client(url=endpoint_url, timeout=request_timeout, watchdog_intervall=max(300.0, request_timeout * 5))
    client.application_uri = PUSH_CLIENT_APPLICATION_URI
    client.set_user(username)
    client.set_password(password)
    await client.set_security(
        policy_cls, certificate=cert_path, private_key=key_path, mode=security_mode,
    )

    report(f"Connecting to {endpoint_url} as {username} ...")
    async with client:
        server_config = client.get_node(SERVER_CONFIGURATION_NODEID)
        cert_groups = await server_config.get_child("0:CertificateGroups")
        default_group = await cert_groups.get_child(DEFAULT_APPLICATION_GROUP)
        trust_list = await default_group.get_child("0:TrustList")

        report("Writing the updated CRL to the device's trust list ...")
        open_method = await trust_list.get_child("0:Open")
        mode = int(ua.OpenFileMode.Write) | int(ua.OpenFileMode.EraseExisting)
        file_handle = await trust_list.call_method(open_method, ua.Variant(mode, ua.VariantType.Byte))

        write_method = await trust_list.get_child("0:Write")
        await trust_list.call_method(
            write_method,
            ua.Variant(file_handle, ua.VariantType.UInt32),
            ua.Variant(encoded, ua.VariantType.ByteString),
        )

        close_and_update = await trust_list.get_child("0:CloseAndUpdate")
        apply_changes_required = await trust_list.call_method(
            close_and_update, ua.Variant(file_handle, ua.VariantType.UInt32),
        )

        if apply_changes_required:
            report("Applying changes on the device ...")
            apply_changes = await server_config.get_child("0:ApplyChanges")
            try:
                await server_config.call_method(apply_changes)
            except Exception:
                report("Device dropped the connection while applying changes (expected).")

    return CrlPushResult(
        revoked_count=len(revoked_serials),
        apply_changes_required=bool(apply_changes_required),
    )


async def push_crl_to_stored_device(
    device: PushDeviceRecord, ca: pki.RootCA, settings: Settings, secret_key: bytes,
) -> tuple[str, str]:
    """Decrypts a stored push device's password and calls push_crl() against
    it, returning (status, message) rather than raising -- shared by the
    device page's manual "Push CRL" button and the automatic sync every
    configured push device gets whenever a certificate is revoked (see
    web/routers/certificates.py), so both report failures the same way
    instead of one of them needing to duplicate this try/except.
    """
    password = secrets_store.decrypt(secret_key, device.password_encrypted)
    try:
        result = await push_crl(
            device.endpoint_url, device.username, password, ca, settings,
            security_policy_uri=device.security_policy_uri,
            security_mode=ua.MessageSecurityMode[device.security_mode],
        )
        message = f"Pushed CRL with {result.revoked_count} revoked certificate(s)."
        return PushCheckStatus.SUCCESS, message
    except Exception as exc:
        return PushCheckStatus.FAILED, f"{type(exc).__name__}: {exc}"


async def push_certificate_to_stored_device(
    device: PushDeviceRecord, ca: pki.RootCA, settings: Settings, secret_key: bytes,
) -> tuple[str, str]:
    """Decrypts a stored push device's password and calls push_certificate()
    against it, returning (status, message) rather than raising -- the
    certificate-push counterpart to push_crl_to_stored_device, shared by the
    device page's manual "Push certificate now" button and the automatic
    re-provisioning loop below.
    """
    password = secrets_store.decrypt(secret_key, device.password_encrypted)
    try:
        result = await push_certificate(
            device.endpoint_url, device.username, password, ca, settings,
            security_policy_uri=device.security_policy_uri,
            security_mode=ua.MessageSecurityMode[device.security_mode],
            regenerate_private_key=device.regenerate_private_key,
            trust_ca_on_device=device.trust_ca_on_device,
        )
        message = (
            f"Issued serial {result.serial_hex} for {result.device_application_uri}, "
            f"valid until {result.not_after}."
        )
        return PushCheckStatus.SUCCESS, message
    except Exception as exc:
        return PushCheckStatus.FAILED, f"{type(exc).__name__}: {exc}"


@dataclass
class DeviceCertStatus:
    reachable: bool
    issued_by_us: bool = False
    not_expired: bool = False
    needs_provisioning: bool = False
    serial_hex: str = ""
    not_after: str = ""
    detail: str = ""


async def check_device_certificate(
    endpoint_url: str, ca: pki.RootCA, settings: Settings, request_timeout: float = 10.0,
) -> DeviceCertStatus:
    """Reads the certificate a device is currently presenting on its OPC UA
    endpoint, on a plain unauthenticated channel -- no credentials needed,
    since this is the same "what have you got" step any client does before
    it knows what security to use, not an admin operation.

    This is what lets the GDS notice a push-mode device that has silently
    reverted to its own factory/self-signed certificate (a factory reset, a
    config wipe) -- something push mode would otherwise never learn on its
    own, since unlike pull mode's GetCertificateStatus, a pushed device never
    calls back to ask "am I still good?". See auto_reprovision_loop().
    """
    client = Client(url=endpoint_url, timeout=request_timeout)
    try:
        await client.connect_socket()
        try:
            await client.send_hello()
            await client.open_secure_channel()
            try:
                endpoints = await client.get_endpoints()
            finally:
                try:
                    await client.close_secure_channel()
                except Exception:
                    pass
        finally:
            client.disconnect_socket()
    except Exception as exc:
        return DeviceCertStatus(reachable=False, detail=f"{type(exc).__name__}: {exc}")

    cert_der = next((bytes(ep.ServerCertificate) for ep in endpoints if ep.ServerCertificate), None)
    if cert_der is None:
        return DeviceCertStatus(reachable=True, needs_provisioning=True, detail="Device presented no certificate.")

    cert = x509.load_der_x509_certificate(cert_der)

    issued_by_us = False
    try:
        ca.certificate.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm,
        )
        issued_by_us = True
    except Exception:
        issued_by_us = False

    now = datetime.now(timezone.utc)
    not_expired = cert.not_valid_after_utc > now
    renewal_due = cert.not_valid_after_utc < now + timedelta(days=settings.renew_before_days)
    needs_provisioning = (not issued_by_us) or (not not_expired) or renewal_due

    if not issued_by_us:
        detail = f"Certificate is not issued by this GDS's CA (issuer: {cert.issuer.rfc4514_string()})."
    elif not not_expired:
        detail = "Certificate has expired."
    elif renewal_due:
        detail = f"Certificate expires {cert.not_valid_after_utc.isoformat()} -- due for renewal."
    else:
        detail = "Certificate is valid and current."

    return DeviceCertStatus(
        reachable=True, issued_by_us=issued_by_us, not_expired=not_expired,
        needs_provisioning=needs_provisioning, serial_hex=format(cert.serial_number, "x"),
        not_after=cert.not_valid_after_utc.isoformat(), detail=detail,
    )


@dataclass
class AutoReprovisionOutcome:
    device_id: str
    device_name: str
    checked: bool
    pushed: bool
    detail: str


async def run_auto_reprovision_check(
    ca: pki.RootCA, settings: Settings, secret_key: bytes,
) -> list[AutoReprovisionOutcome]:
    """One pass over every configured push device: check what certificate
    it's currently presenting, and re-push automatically if it isn't ours,
    is expired, or is due for renewal. Used both by the periodic background
    loop and by the Devices page's manual "Check now" button, so a manual
    run and an automatic one behave identically.
    """
    outcomes = []
    devices = await asyncio.to_thread(db.list_push_devices)
    for device in devices:
        status = await check_device_certificate(device.endpoint_url, ca, settings)
        if not status.reachable:
            outcomes.append(AutoReprovisionOutcome(
                device_id=device.id, device_name=device.name, checked=False, pushed=False,
                detail=f"Unreachable: {status.detail}",
            ))
            continue

        db.log_event("push_device.health_check", f"{device.id} ({device.name}): {status.detail}")

        if not status.needs_provisioning:
            outcomes.append(AutoReprovisionOutcome(
                device_id=device.id, device_name=device.name, checked=True, pushed=False, detail=status.detail,
            ))
            continue

        push_status, message = await push_certificate_to_stored_device(device, ca, settings, secret_key)
        full_message = f"[auto-reprovision, triggered by: {status.detail}] {message}"
        await asyncio.to_thread(db.record_push_device_push, device.id, push_status, full_message)
        outcomes.append(AutoReprovisionOutcome(
            device_id=device.id, device_name=device.name, checked=True,
            pushed=push_status == PushCheckStatus.SUCCESS, detail=full_message,
        ))
    return outcomes


async def auto_reprovision_loop(ca: pki.RootCA, settings: Settings, secret_key: bytes) -> None:
    """Runs run_auto_reprovision_check() forever on settings.push_health_check_interval_seconds,
    as long as settings.push_auto_reprovision_enabled -- started once as a
    background task alongside the OPC UA/web servers (see main.py). Both
    settings are read fresh every iteration, so toggling them from the web
    UI's Settings page takes effect on the next cycle without a restart.
    """
    while True:
        try:
            await asyncio.sleep(settings.push_health_check_interval_seconds)
            if not settings.push_auto_reprovision_enabled:
                continue
            outcomes = await run_auto_reprovision_check(ca, settings, secret_key)
            for outcome in outcomes:
                if outcome.pushed:
                    logger.info("Auto-reprovisioned push device %s (%s): %s",
                                outcome.device_name, outcome.device_id, outcome.detail)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Auto-reprovision loop iteration failed")
