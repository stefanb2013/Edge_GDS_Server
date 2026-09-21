"""Unit test for gds/push_client.py's CSR-signing step, with the OPC UA
client calls mocked out (a live device is exercised via
scripts/push_certificate.py, not here -- see its docstring).
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from asyncua import ua
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from gds import db, pki, push_client
from gds.config import Settings


def _make_test_csr_der(application_uri: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Device")]))
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(application_uri)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


class _FakeMethod:
    def __init__(self, name):
        self.name = name


class _FakeNode:
    """Minimal stand-in for an asyncua Node: enough get_child/call_method
    behavior to drive gds.push_client.push_certificate without a real device.
    """

    def __init__(self):
        self.nodeid = ua.NodeId(1, 2)
        self._children = {}
        self._results = {}

    def add_child(self, qualified_name, node):
        self._children[qualified_name] = node
        return node

    def add_method(self, name, result):
        method = _FakeMethod(name)
        self._children[f"0:{name}"] = method
        self._results[name] = result
        return method

    async def get_child(self, qualified_name):
        return self._children[qualified_name]

    async def call_method(self, method, *args):
        return self._results[method.name]


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path):
    db.init_db(tmp_path / "push_test.db")
    yield


def test_push_certificate_signs_csr_and_records(tmp_path):
    device_uri = "urn:test:pushed-device"
    csr_der = _make_test_csr_der(device_uri)

    settings = Settings(data_dir=tmp_path / "data")
    settings.ensure_dirs()
    ca = pki.load_or_create_ca(settings.ca_dir, "Test CA", "Test Org", "DE", 2048, 365)

    trust_list = _FakeNode()
    trust_list.add_method("AddCertificate", None)

    default_group = _FakeNode()
    default_group.add_child("0:TrustList", trust_list)

    cert_groups = _FakeNode()
    cert_groups.add_child("0:DefaultApplicationGroup", default_group)

    server_config = _FakeNode()
    server_config.add_child("0:CertificateGroups", cert_groups)
    server_config.add_method("CreateSigningRequest", csr_der)
    server_config.add_method("UpdateCertificate", True)
    server_config.add_method("ApplyChanges", None)

    fake_client = MagicMock()
    fake_client.set_user = MagicMock()
    fake_client.set_password = MagicMock()
    fake_client.set_security = AsyncMock()
    fake_client.get_endpoints = AsyncMock(return_value=[MagicMock(Server=MagicMock(ApplicationUri=device_uri))])
    fake_client.get_node = MagicMock(return_value=server_config)
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)

    with patch("gds.push_client.Client", return_value=fake_client):
        result = asyncio.run(
            push_client.push_certificate("opc.tcp://fake-device:4840", "Admin", "admin", ca, settings)
        )

    assert result.device_application_uri == device_uri
    assert result.apply_changes_required is True

    app = db.get_application_by_uri(device_uri)
    assert app is not None
    assert app.status == "approved"

    certs = db.list_certificates(app.id)
    assert len(certs) == 1
    assert certs[0].serial_number == result.serial_hex

    leaf = x509.load_pem_x509_certificate(certs[0].pem.encode())
    ca.certificate.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm,
    )


def test_push_certificate_rejects_mismatched_application_uri(tmp_path):
    """The CSR's SAN claims a different ApplicationUri than the device
    itself reports -- issue_from_csr's trust boundary should refuse this,
    exactly as it does for pull-mode (see tests/test_pki.py).
    """
    csr_der = _make_test_csr_der("urn:test:impersonated-device")

    settings = Settings(data_dir=tmp_path / "data")
    settings.ensure_dirs()
    ca = pki.load_or_create_ca(settings.ca_dir, "Test CA", "Test Org", "DE", 2048, 365)

    server_config = _FakeNode()
    cert_groups = _FakeNode()
    default_group = _FakeNode()
    cert_groups.add_child("0:DefaultApplicationGroup", default_group)
    server_config.add_child("0:CertificateGroups", cert_groups)
    server_config.add_method("CreateSigningRequest", csr_der)

    fake_client = MagicMock()
    fake_client.set_user = MagicMock()
    fake_client.set_password = MagicMock()
    fake_client.set_security = AsyncMock()
    fake_client.get_endpoints = AsyncMock(
        return_value=[MagicMock(Server=MagicMock(ApplicationUri="urn:test:real-device"))]
    )
    fake_client.get_node = MagicMock(return_value=server_config)
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)

    with patch("gds.push_client.Client", return_value=fake_client):
        with pytest.raises(ValueError):
            asyncio.run(
                push_client.push_certificate("opc.tcp://fake-device:4840", "Admin", "admin", ca, settings)
            )


def test_discover_endpoints_sorts_by_security_level_desc():
    from asyncua import ua

    def _fake_endpoint(policy_suffix, mode, level, cert=b""):
        ep = MagicMock()
        ep.EndpointUrl = "opc.tcp://fake-device:4840"
        ep.SecurityPolicyUri = f"http://opcfoundation.org/UA/SecurityPolicy#{policy_suffix}"
        ep.SecurityMode = mode
        ep.SecurityLevel = level
        ep.ServerCertificate = cert
        ep.Server = MagicMock(ApplicationUri="urn:test:device", ApplicationName=MagicMock(Text="Test Device"))
        return ep

    endpoints = [
        _fake_endpoint("None", ua.MessageSecurityMode.None_, 0),
        _fake_endpoint("Basic256Sha256", ua.MessageSecurityMode.SignAndEncrypt, 50),
        _fake_endpoint("Basic256Sha256", ua.MessageSecurityMode.Sign, 30),
    ]

    fake_client = MagicMock()
    fake_client.connect_and_get_server_endpoints = AsyncMock(return_value=endpoints)

    with patch("gds.push_client.Client", return_value=fake_client):
        results = asyncio.run(push_client.discover_endpoints("opc.tcp://fake-device:4840"))

    assert [r.security_level for r in results] == [50, 30, 0]
    assert results[0].security_policy_name == "Basic256Sha256"
    assert results[0].usable_for_push is True
    assert results[2].usable_for_push is False  # None mode isn't usable for push


def test_test_connection_reports_missing_server_configuration():
    settings = Settings(data_dir=__import__("pathlib").Path(__import__("tempfile").mkdtemp()))
    settings.ensure_dirs()

    no_config_node = MagicMock()
    no_config_node.get_child = AsyncMock(side_effect=Exception("no such child"))

    fake_client = MagicMock()
    fake_client.set_user = MagicMock()
    fake_client.set_password = MagicMock()
    fake_client.set_security = AsyncMock()
    fake_client.get_endpoints = AsyncMock(return_value=[MagicMock(Server=MagicMock(ApplicationUri="urn:test:device"))])
    fake_client.get_node = MagicMock(return_value=no_config_node)
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)

    with patch("gds.push_client.Client", return_value=fake_client):
        result = asyncio.run(
            push_client.test_connection("opc.tcp://fake-device:4840", "Admin", "admin", settings)
        )

    assert result.success is False
    assert result.has_server_configuration is False
    assert "does not expose" in result.message


def test_test_connection_success():
    settings = Settings(data_dir=__import__("pathlib").Path(__import__("tempfile").mkdtemp()))
    settings.ensure_dirs()

    config_node = MagicMock()
    config_node.get_child = AsyncMock(return_value=_FakeMethod("CreateSigningRequest"))

    fake_client = MagicMock()
    fake_client.set_user = MagicMock()
    fake_client.set_password = MagicMock()
    fake_client.set_security = AsyncMock()
    fake_client.get_endpoints = AsyncMock(return_value=[MagicMock(Server=MagicMock(ApplicationUri="urn:test:device"))])
    fake_client.get_node = MagicMock(return_value=config_node)
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)

    with patch("gds.push_client.Client", return_value=fake_client):
        result = asyncio.run(
            push_client.test_connection("opc.tcp://fake-device:4840", "Admin", "admin", settings)
        )

    assert result.success is True
    assert result.has_server_configuration is True
    assert result.server_application_uri == "urn:test:device"


def test_test_connection_rejects_none_security_mode():
    settings = Settings(data_dir=__import__("pathlib").Path(__import__("tempfile").mkdtemp()))
    settings.ensure_dirs()

    result = asyncio.run(
        push_client.test_connection(
            "opc.tcp://fake-device:4840", "Admin", "admin", settings,
            security_mode=ua.MessageSecurityMode.None_,
        )
    )
    assert result.success is False
    assert "signed/encrypted" in result.message


def test_push_crl_writes_trust_list_and_reports_revoked_count(tmp_path):
    from asyncua.ua.ua_binary import Buffer, struct_from_binary

    settings = Settings(data_dir=tmp_path / "data")
    settings.ensure_dirs()
    ca = pki.load_or_create_ca(settings.ca_dir, "Test CA", "Test Org", "DE", 2048, 365)

    app = db.create_application("urn:test:revoked-app", "App", 0)
    cert = db.add_certificate(app.id, "abc123", "CN=x", "2020-01-01", "2030-01-01", "PEMDATA")
    db.revoke_certificate(cert.id)

    calls = []

    async def call_method(method, *args):
        calls.append((method.name, args))
        if method.name == "Open":
            return 5
        if method.name == "CloseAndUpdate":
            return False
        return None

    trust_list = MagicMock()
    trust_list.get_child = AsyncMock(side_effect=lambda name: {
        "0:Open": _FakeMethod("Open"),
        "0:Write": _FakeMethod("Write"),
        "0:CloseAndUpdate": _FakeMethod("CloseAndUpdate"),
    }[name])
    trust_list.call_method = AsyncMock(side_effect=call_method)

    default_group = _FakeNode()
    default_group.add_child("0:TrustList", trust_list)
    cert_groups = _FakeNode()
    cert_groups.add_child("0:DefaultApplicationGroup", default_group)
    server_config = _FakeNode()
    server_config.add_child("0:CertificateGroups", cert_groups)

    fake_client = MagicMock()
    fake_client.set_user = MagicMock()
    fake_client.set_password = MagicMock()
    fake_client.set_security = AsyncMock()
    fake_client.get_node = MagicMock(return_value=server_config)
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)

    with patch("gds.push_client.Client", return_value=fake_client):
        result = asyncio.run(
            push_client.push_crl("opc.tcp://fake-device:4840", "Admin", "admin", ca, settings)
        )

    assert result.revoked_count == 1
    assert result.apply_changes_required is False

    open_call = next(c for c in calls if c[0] == "Open")
    mode_variant = open_call[1][0]
    assert mode_variant.Value == (int(ua.OpenFileMode.Write) | int(ua.OpenFileMode.EraseExisting))
    assert mode_variant.VariantType == ua.VariantType.Byte

    write_call = next(c for c in calls if c[0] == "Write")
    assert write_call[1][0].Value == 5  # the file handle Open returned

    written_bytes = bytes(write_call[1][1].Value)
    tl = struct_from_binary(ua.TrustListDataType, Buffer(written_bytes))
    assert tl.SpecifiedLists == int(ua.TrustListMasks.TrustedCrls)
    assert tl.TrustedCertificates == []
    assert len(tl.TrustedCrls) == 1


def test_push_crl_to_stored_device_reports_failure_without_raising(tmp_path):
    from gds import secrets_store
    from gds.models import PushDeviceRecord

    settings = Settings(data_dir=tmp_path / "data")
    settings.ensure_dirs()
    ca = pki.load_or_create_ca(settings.ca_dir, "Test CA", "Test Org", "DE", 2048, 365)
    secret_key = secrets_store.load_or_create_key(settings.pki_dir)

    device = PushDeviceRecord(
        id="dev1", name="Test", endpoint_url="opc.tcp://unreachable:4840",
        security_policy_uri="http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
        security_mode="SignAndEncrypt", username="Admin",
        password_encrypted=secrets_store.encrypt(secret_key, "devicepass"),
    )

    with patch("gds.push_client.Client", side_effect=OSError("connection refused")):
        status, message = asyncio.run(
            push_client.push_crl_to_stored_device(device, ca, settings, secret_key)
        )

    assert status == "failed"
    assert "OSError" in message


def _fake_client_presenting(cert_der: bytes | None):
    fake_client = MagicMock()
    fake_client.connect_socket = AsyncMock()
    fake_client.send_hello = AsyncMock()
    fake_client.open_secure_channel = AsyncMock()
    fake_client.close_secure_channel = AsyncMock()
    fake_client.disconnect_socket = MagicMock()
    endpoint = MagicMock(ServerCertificate=cert_der)
    fake_client.get_endpoints = AsyncMock(return_value=[endpoint])
    return fake_client


def test_check_device_certificate_flags_foreign_certificate(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    settings.ensure_dirs()
    ca = pki.load_or_create_ca(settings.ca_dir, "Test CA", "Test Org", "DE", 2048, 365)

    foreign_key_pem, foreign_cert_pem = pki.generate_self_signed_app_cert(
        application_uri="urn:test:foreign-device", common_name="Foreign Device",
        hostname="localhost", valid_days=30,
    )
    foreign_der = x509.load_pem_x509_certificate(foreign_cert_pem.encode()).public_bytes(serialization.Encoding.DER)

    with patch("gds.push_client.Client", return_value=_fake_client_presenting(foreign_der)):
        status = asyncio.run(push_client.check_device_certificate("opc.tcp://fake-device:4840", ca, settings))

    assert status.reachable is True
    assert status.issued_by_us is False
    assert status.needs_provisioning is True


def test_check_device_certificate_recognizes_valid_current_certificate(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    settings.ensure_dirs()
    ca = pki.load_or_create_ca(settings.ca_dir, "Test CA", "Test Org", "DE", 2048, 365)

    issued = pki.generate_key_pair_and_cert(
        ca, "urn:test:device", "Test Device", [], [], valid_days=365,
    )
    our_der = x509.load_pem_x509_certificate(issued.issued.cert_pem.encode()).public_bytes(serialization.Encoding.DER)

    with patch("gds.push_client.Client", return_value=_fake_client_presenting(our_der)):
        status = asyncio.run(push_client.check_device_certificate("opc.tcp://fake-device:4840", ca, settings))

    assert status.reachable is True
    assert status.issued_by_us is True
    assert status.not_expired is True
    assert status.needs_provisioning is False


def test_check_device_certificate_flags_renewal_due(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    settings.ensure_dirs()
    settings.renew_before_days = 30
    ca = pki.load_or_create_ca(settings.ca_dir, "Test CA", "Test Org", "DE", 2048, 365)

    # Valid for only 5 days -- inside the 30-day renew-before window.
    issued = pki.generate_key_pair_and_cert(
        ca, "urn:test:device", "Test Device", [], [], valid_days=5,
    )
    our_der = x509.load_pem_x509_certificate(issued.issued.cert_pem.encode()).public_bytes(serialization.Encoding.DER)

    with patch("gds.push_client.Client", return_value=_fake_client_presenting(our_der)):
        status = asyncio.run(push_client.check_device_certificate("opc.tcp://fake-device:4840", ca, settings))

    assert status.issued_by_us is True
    assert status.needs_provisioning is True


def test_check_device_certificate_handles_unreachable_device(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    settings.ensure_dirs()
    ca = pki.load_or_create_ca(settings.ca_dir, "Test CA", "Test Org", "DE", 2048, 365)

    fake_client = MagicMock()
    fake_client.connect_socket = AsyncMock(side_effect=OSError("connection refused"))
    fake_client.disconnect_socket = MagicMock()

    with patch("gds.push_client.Client", return_value=fake_client):
        status = asyncio.run(push_client.check_device_certificate("opc.tcp://fake-device:4840", ca, settings))

    assert status.reachable is False
    assert status.needs_provisioning is False


def test_run_auto_reprovision_check_pushes_only_devices_that_need_it(tmp_path):
    from gds import secrets_store
    from gds.push_client import AutoReprovisionOutcome, DeviceCertStatus

    settings = Settings(data_dir=tmp_path / "data")
    settings.ensure_dirs()
    ca = pki.load_or_create_ca(settings.ca_dir, "Test CA", "Test Org", "DE", 2048, 365)
    secret_key = secrets_store.load_or_create_key(settings.pki_dir)

    healthy = db.create_push_device(
        "Healthy", "opc.tcp://healthy:4840",
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", "SignAndEncrypt",
        "Admin", secrets_store.encrypt(secret_key, "pw"),
    )
    needs_push = db.create_push_device(
        "NeedsPush", "opc.tcp://needs-push:4840",
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", "SignAndEncrypt",
        "Admin", secrets_store.encrypt(secret_key, "pw"),
    )
    unreachable = db.create_push_device(
        "Unreachable", "opc.tcp://unreachable:4840",
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", "SignAndEncrypt",
        "Admin", secrets_store.encrypt(secret_key, "pw"),
    )

    async def fake_check(endpoint_url, ca_, settings_, request_timeout=10.0):
        if endpoint_url == "opc.tcp://healthy:4840":
            return DeviceCertStatus(reachable=True, issued_by_us=True, not_expired=True, needs_provisioning=False)
        if endpoint_url == "opc.tcp://needs-push:4840":
            return DeviceCertStatus(reachable=True, issued_by_us=False, needs_provisioning=True, detail="foreign cert")
        return DeviceCertStatus(reachable=False, detail="timeout")

    async def fake_push(device, ca_, settings_, secret_key_):
        return "success", f"pushed to {device.name}"

    with patch("gds.push_client.check_device_certificate", side_effect=fake_check), \
         patch("gds.push_client.push_certificate_to_stored_device", side_effect=fake_push):
        outcomes = asyncio.run(push_client.run_auto_reprovision_check(ca, settings, secret_key))

    by_id = {o.device_id: o for o in outcomes}
    assert by_id[healthy.id].checked is True
    assert by_id[healthy.id].pushed is False
    assert by_id[needs_push.id].pushed is True
    assert by_id[unreachable.id].checked is False
    assert by_id[unreachable.id].pushed is False

    assert db.get_push_device(needs_push.id).last_push_status == "success"
    assert db.get_push_device(healthy.id).last_push_status == "never"
