from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from gds import pki


def _make_ca(tmp_path):
    return pki.load_or_create_ca(
        tmp_path / "ca", "Test Root CA", "Test Org", "DE", key_bits=2048, valid_days=365,
    )


def test_load_or_create_ca_is_idempotent(tmp_path):
    ca1 = _make_ca(tmp_path)
    ca2 = _make_ca(tmp_path)
    assert ca1.certificate.serial_number == ca2.certificate.serial_number
    assert ca1.cert_pem == ca2.cert_pem


def test_ca_certificate_is_self_signed_and_a_ca(tmp_path):
    ca = _make_ca(tmp_path)
    ca.certificate.public_key().verify(
        ca.certificate.signature, ca.certificate.tbs_certificate_bytes,
        padding.PKCS1v15(), ca.certificate.signature_hash_algorithm,
    )
    bc = ca.certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True


def _make_csr(application_uri: str, common_name: str = "Test App"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(application_uri)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


def test_issue_from_csr_chains_to_ca(tmp_path):
    ca = _make_ca(tmp_path)
    _, csr_pem = _make_csr("urn:test:app1")
    issued = pki.issue_from_csr(ca, csr_pem, "urn:test:app1", valid_days=30)

    leaf = x509.load_pem_x509_certificate(issued.cert_pem.encode())
    ca.certificate.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm,
    )
    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "urn:test:app1" in san.get_values_for_type(x509.UniformResourceIdentifier)


def test_issue_from_csr_rejects_mismatched_application_uri(tmp_path):
    ca = _make_ca(tmp_path)
    _, csr_pem = _make_csr("urn:test:app-real")
    try:
        pki.issue_from_csr(ca, csr_pem, "urn:test:someone-else", valid_days=30)
        assert False, "expected a ValueError for mismatched ApplicationUri"
    except ValueError:
        pass


def test_generate_key_pair_and_cert_public_keys_match(tmp_path):
    ca = _make_ca(tmp_path)
    pair = pki.generate_key_pair_and_cert(
        ca, "urn:test:app2", "Test App 2", dns_names=["localhost"], ip_addresses=[], valid_days=30,
    )
    key = serialization.load_pem_private_key(pair.private_key_pem.encode(), password=None)
    cert = x509.load_pem_x509_certificate(pair.issued.cert_pem.encode())
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()


def test_build_crl_lists_revoked_serials(tmp_path):
    ca = _make_ca(tmp_path)
    _, csr_pem = _make_csr("urn:test:app3")
    issued = pki.issue_from_csr(ca, csr_pem, "urn:test:app3", valid_days=30)

    crl_pem = pki.build_crl(ca, [issued.serial_hex])
    crl = x509.load_pem_x509_crl(crl_pem.encode())
    revoked_serials = {c.serial_number for c in crl}
    assert int(issued.serial_hex, 16) in revoked_serials


def test_hybrid_encrypt_roundtrip(tmp_path):
    ca = _make_ca(tmp_path)
    _, csr_pem = _make_csr("urn:test:app4")
    key, _ = _make_csr("urn:test:app4")  # discard csr, keep a private key
    issued = pki.issue_from_csr(ca, csr_pem, "urn:test:app4", valid_days=30)

    # Use the CA cert itself as a stand-in "wrapping" cert whose private key we hold (ca.key).
    secret = b"super secret private key material"
    blob = pki.hybrid_encrypt_for_client(secret, ca.cert_pem)
    decrypted = pki.hybrid_decrypt(blob, ca.key)
    assert decrypted == secret
