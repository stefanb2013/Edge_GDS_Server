"""Certificate Authority and PKI helpers.

Everything here is built on `cryptography`. There is no OPC UA-specific code
in this module -- it only knows about X.509/PKCS, and is exercised directly
by tests/test_pki.py.

Deviations from strict OPC UA Part 12 wire formats (documented, deliberate
simplifications -- see README "Known limitations"):

* `GetTrustList` here returns one concatenated PEM bundle (CA cert + CRL +
  any additional trusted/issuer entries) as a ByteString, rather than the
  spec's `TrustListDataType` structure. Any PEM-aware client can still use
  it directly.
* `StartNewKeyPairRequest`'s returned private key is protected with a
  hybrid AES-256-GCM + RSA-OAEP envelope (`hybrid_encrypt_for_client` /
  `hybrid_decrypt`), addressed to a certificate the requester passes in and
  already holds the matching private key for (its existing/bootstrap
  identity) -- instead of the spec's PKCS#12-password-based scheme. Same
  goal (only the requesting application can read its new private key),
  simpler to implement and to test end-to-end.
"""
from __future__ import annotations

import datetime
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


# --------------------------------------------------------------------------
# Root CA
# --------------------------------------------------------------------------

@dataclass
class RootCA:
    key: rsa.RSAPrivateKey
    certificate: x509.Certificate

    @property
    def cert_pem(self) -> str:
        return self.certificate.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def subject_name(self) -> str:
        return self.certificate.subject.rfc4514_string()


def load_or_create_ca(
    ca_dir: Path,
    common_name: str,
    organization: str,
    country: str,
    key_bits: int,
    valid_days: int,
) -> RootCA:
    ca_dir.mkdir(parents=True, exist_ok=True)
    key_path = ca_dir / "ca.key"
    cert_path = ca_dir / "ca.crt"

    if key_path.exists() and cert_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return RootCA(key=key, certificate=cert)

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    cert = builder.sign(key, hashes.SHA256())

    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass  # best-effort on platforms without POSIX permission bits (e.g. Windows)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    return RootCA(key=key, certificate=cert)


def _dns_ip_san_entries(dns_names: list[str], ip_addresses: list[str]) -> list[x509.GeneralName]:
    entries: list[x509.GeneralName] = []
    for name in dns_names:
        entries.append(x509.DNSName(name))
    for ip in ip_addresses:
        try:
            import ipaddress
            entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            continue
    return entries


def _opcua_leaf_extensions(
    builder: x509.CertificateBuilder,
    public_key,
    ca: RootCA,
    san_entries: list[x509.GeneralName],
) -> x509.CertificateBuilder:
    """Apply the extension profile an OPC UA application instance certificate
    is expected to carry (Part 6, 6.2.2): BasicConstraints CA:false, digital
    signature/key encipherment key usage, server+client extended key usage,
    and the given SubjectAltName entries (must include the ApplicationUri as
    a URI entry; see call sites for how each assembles the rest).
    """
    return (
        builder
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            # Part 6, 6.2.2's ApplicationInstanceCertificate profile requires
            # dataEncipherment alongside keyEncipherment -- Basic256Sha256's
            # RSA-OAEP asymmetric step during channel setup covers both key
            # and (small) data payloads, and a real device (a B&R PLC) was
            # observed rejecting UpdateCertificate with
            # BadCertificateUseNotAllowed while this bit was False.
            x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=True,
                data_encipherment=True, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()), critical=False
        )
    )


@dataclass
class IssuedCertificate:
    cert_pem: str
    serial_hex: str
    subject: str
    not_before: str
    not_after: str


def issue_from_csr(
    ca: RootCA,
    csr_pem: str,
    application_uri: str,
    valid_days: int,
    verify_signature: bool = True,
) -> IssuedCertificate:
    """Sign a CSR (StartSigningRequest flow: the application generated its
    own key pair and only asks the CA to sign it). Verifies the CSR's
    signature and, when the CSR itself carries a SAN with a URI entry,
    requires it to match the caller's registered ApplicationUri -- this is
    the actual trust boundary a GDS provides (an application cannot get a
    certificate minted for someone else's identity).

    `verify_signature=False` skips only the self-signature check, never the
    ApplicationUri check above. Needed for gds/push_client.py: a real device
    (a B&R PLC) was observed returning a `CreateSigningRequest` CSR whose
    declared sha1WithRSAEncryption self-signature does not verify --
    everything else about it (subject, public key, SANs) decodes correctly,
    so this looks like a firmware bug in that CSR-signing step rather than a
    malformed key. In the push flow this check is also largely redundant:
    the CSR was fetched live, over an authenticated admin session, from the
    very device that will use the resulting certificate -- the trust
    boundary there is that session, not the CSR's own signature. Pull mode
    (gds/gds_methods.py) never sets this, since a CSR arriving over the
    public GDS registration channel has no such session to fall back on.
    """
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if verify_signature and not csr.is_signature_valid:
        raise ValueError("CSR signature is not valid")

    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        csr_san = list(san_ext.value)
        csr_uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        csr_san = []
        csr_uris = []
    if csr_uris and application_uri not in csr_uris:
        raise ValueError(
            f"CSR SubjectAltName URI {csr_uris!r} does not match registered "
            f"ApplicationUri {application_uri!r}"
        )

    # Preserve every other SAN entry from the CSR as-is (DNSName, IPAddress,
    # RFC822Name, etc.) -- a real device (a B&R PLC) was observed rejecting a
    # reissued certificate with BadCertificateUseNotAllowed when its own
    # CreateSigningRequest CSR's RFC822Name entry was dropped from the SAN we
    # rebuilt, so nothing here is filtered by type. Only the URI entry is
    # replaced, since the ApplicationUri is what the GDS itself is vouching
    # for -- everything else the applicant asked for is carried through
    # unchanged.
    other_san_entries = [e for e in csr_san if not isinstance(e, x509.UniformResourceIdentifier)]
    san_entries = [x509.UniformResourceIdentifier(application_uri), *other_san_entries]

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca.certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
    )
    builder = _opcua_leaf_extensions(builder, csr.public_key(), ca, san_entries)
    cert = builder.sign(ca.key, hashes.SHA256())

    return IssuedCertificate(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        serial_hex=format(cert.serial_number, "x"),
        subject=cert.subject.rfc4514_string(),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
    )


@dataclass
class IssuedKeyPair:
    private_key_pem: str
    issued: IssuedCertificate


def generate_key_pair_and_cert(
    ca: RootCA,
    application_uri: str,
    application_name: str,
    dns_names: list[str],
    ip_addresses: list[str],
    valid_days: int,
    key_bits: int = 2048,
) -> IssuedKeyPair:
    """StartNewKeyPairRequest flow: the GDS generates the key pair itself."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, application_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
    )
    san_entries = [x509.UniformResourceIdentifier(application_uri), *_dns_ip_san_entries(dns_names, ip_addresses)]
    builder = _opcua_leaf_extensions(builder, key.public_key(), ca, san_entries)
    cert = builder.sign(ca.key, hashes.SHA256())

    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()

    return IssuedKeyPair(
        private_key_pem=private_key_pem,
        issued=IssuedCertificate(
            cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
            serial_hex=format(cert.serial_number, "x"),
            subject=cert.subject.rfc4514_string(),
            not_before=cert.not_valid_before_utc.isoformat(),
            not_after=cert.not_valid_after_utc.isoformat(),
        ),
    )


def generate_self_signed_app_cert(
    application_uri: str, common_name: str, hostname: str, valid_days: int, key_bits: int = 2048
):
    """Self-signed application-instance certificate for the GDS's *own* OPC
    UA endpoint (asyncua needs one to offer Sign/SignAndEncrypt security
    policies). Returns (private_key_pem, cert_pem).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(application_uri),
                x509.DNSName(hostname),
            ]),
            critical=False,
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return key_pem, cert.public_bytes(serialization.Encoding.PEM).decode()


# --------------------------------------------------------------------------
# CRL + trust list bundle
# --------------------------------------------------------------------------

def build_crl(ca: RootCA, revoked_serials_hex: list[str], last_update_days_valid: int = 30) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.certificate.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=last_update_days_valid))
    )
    for serial_hex in revoked_serials_hex:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(serial_hex, 16))
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(private_key=ca.key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM).decode()


def trust_list_bundle_pem(
    ca_cert_pem: str,
    crl_pem: str,
    trusted_cert_pems: list[str],
    trusted_crl_pems: list[str],
) -> str:
    """One concatenated PEM bundle: this CA's cert + CRL (the "issuer" side)
    followed by any additional trusted certs/CRLs an admin has uploaded. See
    module docstring for why this isn't the spec's TrustListDataType.
    """
    parts = [ca_cert_pem, crl_pem, *trusted_cert_pems, *trusted_crl_pems]
    return "\n".join(p.strip() + "\n" for p in parts if p.strip())


# --------------------------------------------------------------------------
# Hybrid envelope for handing a freshly generated private key back to the
# requesting application, protected so only that application can read it.
# --------------------------------------------------------------------------

_MAGIC = b"GDS1"


def hybrid_encrypt_for_client(data: bytes, client_cert_pem: str) -> bytes:
    client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode())
    client_pub = client_cert.public_key()
    if not isinstance(client_pub, rsa.RSAPublicKey):
        raise ValueError("client certificate does not carry an RSA public key")

    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, None)
    wrapped_key = client_pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    # MAGIC | u16 wrapped_key_len | wrapped_key | nonce(12) | ciphertext
    return _MAGIC + struct.pack(">H", len(wrapped_key)) + wrapped_key + nonce + ciphertext


def hybrid_decrypt(blob: bytes, client_private_key) -> bytes:
    if blob[:4] != _MAGIC:
        raise ValueError("not a GDS hybrid-encrypted blob")
    offset = 4
    (wrapped_len,) = struct.unpack(">H", blob[offset:offset + 2])
    offset += 2
    wrapped_key = blob[offset:offset + wrapped_len]
    offset += wrapped_len
    nonce = blob[offset:offset + 12]
    offset += 12
    ciphertext = blob[offset:]
    aes_key = client_private_key.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)
