from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from gds import pki
from gds.config import Settings
from gds.gds_methods import GdsContext
from web.app import ensure_web_tls_certificate


def _ctx(tmp_path, hostname: str) -> GdsContext:
    settings = Settings(data_dir=tmp_path / "data", hostname=hostname)
    settings.ensure_dirs()
    ca = pki.load_or_create_ca(settings.ca_dir, "Test CA", "Test Org", "DE", 2048, 365)
    return GdsContext(ca=ca, settings=settings)


def test_web_tls_cert_is_signed_by_our_ca(tmp_path):
    ctx = _ctx(tmp_path, "localhost")
    key_path, cert_path = ensure_web_tls_certificate(ctx)

    cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
    ctx.ca.certificate.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm,
    )
    key = serialization.load_pem_private_key(open(key_path, "rb").read(), password=None)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()


def test_web_tls_cert_uses_dns_name_for_hostname(tmp_path):
    ctx = _ctx(tmp_path, "plc-gds.local")
    _key_path, cert_path = ensure_web_tls_certificate(ctx)
    cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["plc-gds.local"]
    assert san.get_values_for_type(x509.IPAddress) == []


def test_web_tls_cert_uses_ip_address_for_numeric_hostname(tmp_path):
    ctx = _ctx(tmp_path, "192.168.0.11")
    _key_path, cert_path = ensure_web_tls_certificate(ctx)
    cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == []
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["192.168.0.11"]


def test_web_tls_cert_is_reused_not_regenerated(tmp_path):
    ctx = _ctx(tmp_path, "localhost")
    key_path1, cert_path1 = ensure_web_tls_certificate(ctx)
    cert1_bytes = open(cert_path1, "rb").read()

    key_path2, cert_path2 = ensure_web_tls_certificate(ctx)
    cert2_bytes = open(cert_path2, "rb").read()

    assert key_path1 == key_path2
    assert cert1_bytes == cert2_bytes
