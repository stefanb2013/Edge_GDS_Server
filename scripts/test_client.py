#!/usr/bin/env python3
"""End-to-end demonstration/verification client for the GDS OPC UA endpoint.

Exercises the full workflow a real OPC UA application would go through
against the *real* OPC UA Part 12 information model: register itself, wait
for an admin to approve it (polling, since there's no push), request a
certificate two ways (bring-your-own CSR, and let the GDS generate the key
pair), download the trust list via the standard FileType Open/Read/Close
methods, and verify the returned certificate actually chains to the GDS's
own root CA.

Since this script is itself built on asyncua, it needs the same
`fix_null_extension_object_encodings()` workaround the server applies (see
gds/opcua_server.py's docstring) -- a real GDS client (e.g. a PLC's own
vendor stack) does not, since it never goes through asyncua's buggy dynamic
struct codegen in the first place.

Usage:
    python scripts/test_client.py [opc.tcp://host:port/gds/]

The application starts out "pending" -- log into the web admin UI (default
http://<host>:8443/) and approve "GDS Test Client" before this script's
polling loop will proceed.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # for `from gds import ...` below

from asyncua import Client, ua
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from gds import pki
from gds.opcua_server import fix_null_extension_object_encodings

GDS_NAMESPACE_URI = "http://opcfoundation.org/UA/GDS/"
APPLICATION_URI = "urn:example:gds-test-client"


def make_csr(private_key, application_uri: str, common_name: str) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(application_uri)]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


async def call(directory, gds_idx, name, *args):
    method = await directory.get_child(f"{gds_idx}:{name}")
    return await directory.call_method(method, *args)


async def download_trust_list(client, trust_list_node_id) -> bytes:
    """Standard FileType pull: OpenWithMasks -> repeated Read -> Close."""
    node = client.get_node(trust_list_node_id)
    open_m = await node.get_child("0:OpenWithMasks")
    read_m = await node.get_child("0:Read")
    close_m = await node.get_child("0:Close")
    handle = await node.call_method(open_m, ua.UInt32(15))  # 15 = All
    chunks = []
    try:
        while True:
            chunk = await node.call_method(read_m, ua.UInt32(handle), ua.Int32(8192))
            if not chunk:
                break
            chunks.append(chunk)
            if len(chunk) < 8192:
                break
    finally:
        await node.call_method(close_m, ua.UInt32(handle))
    return b"".join(chunks)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("endpoint", nargs="?", default="opc.tcp://localhost:4840/gds/")
    parser.add_argument("--poll-seconds", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=300, help="give up waiting for approval after N seconds")
    args = parser.parse_args()

    client = Client(url=args.endpoint)
    async with client:
        await client.load_data_type_definitions()
        await fix_null_extension_object_encodings(client)

        gds_idx = await client.get_namespace_index(GDS_NAMESPACE_URI)
        directory = await client.get_objects_node().get_child(f"{gds_idx}:Directory")

        print(f"Registering application {APPLICATION_URI!r} ...")
        record = ua.ApplicationRecordDataType()
        record.ApplicationUri = APPLICATION_URI
        record.ApplicationNames = [ua.LocalizedText("GDS Test Client")]
        record.ApplicationType = ua.ApplicationType.Client
        record.ProductUri = "urn:example:gds-test-client-product"
        record.DiscoveryUrls = []
        record.ServerCapabilities = []
        app_id = await call(directory, gds_idx, "RegisterApplication", record)
        print(f"  -> ApplicationId = {app_id}")

        print("Waiting for a GDS administrator to approve this application in the web UI ...")
        deadline = time.monotonic() + args.timeout
        while True:
            try:
                await call(directory, gds_idx, "GetCertificateGroups", app_id)
                break
            except ua.uaerrors.UaStatusCodeError as exc:
                if time.monotonic() > deadline:
                    print(f"Timed out waiting for approval: {exc}", file=sys.stderr)
                    return 1
                print("  still pending, retrying in a few seconds ...")
                await asyncio.sleep(args.poll_seconds)

        print("Approved. Fetching certificate groups ...")
        groups = await call(directory, gds_idx, "GetCertificateGroups", app_id)
        default_group = groups[0]
        cert_type_id = ua.NodeId(ua.ObjectIds.RsaSha256ApplicationCertificateType, 0)

        print("Requesting a signed certificate from our own CSR ...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr_pem = make_csr(key, APPLICATION_URI, "GDS Test Client")
        request_id = await call(
            directory, gds_idx, "StartSigningRequest", app_id, default_group, cert_type_id, csr_pem,
        )
        cert_bytes, _key_blob, issuer_certs = await call(directory, gds_idx, "FinishRequest", app_id, request_id)

        leaf = x509.load_pem_x509_certificate(cert_bytes)
        issuer = x509.load_pem_x509_certificate(issuer_certs[0])
        issuer.public_key().verify(
            leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm,
        )
        print(f"  -> received certificate serial {leaf.serial_number:x}, verified against issuer CA: OK")

        print("Requesting a GDS-generated key pair too ...")
        request_id2 = await call(
            directory, gds_idx, "StartNewKeyPairRequest", app_id, default_group, cert_type_id,
            "GDS Test Client", ["localhost"], "PEM", "",
        )
        cert2_bytes, key_blob2, _issuers2 = await call(directory, gds_idx, "FinishRequest", app_id, request_id2)
        new_key = serialization.load_pem_private_key(key_blob2, password=None)
        new_cert = x509.load_pem_x509_certificate(cert2_bytes)
        assert new_key.public_key().public_numbers() == new_cert.public_key().public_numbers()
        print("  -> new key pair's public key matches the issued certificate: OK")

        print("Downloading the trust list via the standard FileType Open/Read/Close ...")
        trust_list_id = await call(directory, gds_idx, "GetTrustList", app_id, default_group)
        raw = await download_trust_list(client, trust_list_id)
        from asyncua.ua.ua_binary import struct_from_binary, Buffer
        from asyncua.ua.uaprotocol_auto import TrustListDataType
        trust_list = struct_from_binary(TrustListDataType, Buffer(raw))
        ca_cert = x509.load_der_x509_certificate(trust_list.TrustedCertificates[0])
        print(f"  -> trust list has {len(trust_list.TrustedCertificates)} trusted cert(s); "
              f"CA subject: {ca_cert.subject.rfc4514_string()}")

        update_required = await call(
            directory, gds_idx, "GetCertificateStatus", app_id, default_group, cert_type_id,
        )
        print(f"Current certificate status: UpdateRequired={update_required}")

        print("\nAll checks passed.")
        return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
