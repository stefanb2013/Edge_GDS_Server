#!/usr/bin/env python3
"""Push-mode certificate provisioning: connects to a device's own OPC UA
server and installs a certificate on it via the standard
`ServerConfiguration` object, instead of waiting for the device to pull one
from this GDS itself. See gds/push_client.py for the implementation and the
verified NodeIds/argument shapes this relies on.

Usage:
    python scripts/push_certificate.py opc.tcp://192.168.0.2:4840 \\
        --username Admin --password admin
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # for `from gds import ...` below

from gds import db, pki
from gds.config import settings
from gds.push_client import push_certificate


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("endpoint", help="OPC UA endpoint URL of the target device, e.g. opc.tcp://192.168.0.2:4840")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--no-regenerate-key", action="store_true",
        help="ask the device to sign a CSR from its EXISTING private key instead of generating a new "
             "one (use this for renewal, once it already has a GDS-issued certificate)",
    )
    parser.add_argument(
        "--no-trust-ca", action="store_true",
        help="skip adding the GDS root CA to the device's own trust list",
    )
    parser.add_argument(
        "--timeout", type=float, default=60.0,
        help="OPC UA request timeout in seconds (default 60 -- device-side key generation can be slow)",
    )
    args = parser.parse_args()

    settings.ensure_dirs()
    db.init_db(settings.db_path)
    ca = pki.load_or_create_ca(
        settings.ca_dir, settings.ca_common_name, settings.ca_organization,
        settings.ca_country, settings.ca_key_bits, settings.ca_valid_days,
    )
    print(f"Using GDS root CA: {ca.subject_name}\n")

    try:
        result = await push_certificate(
            args.endpoint, args.username, args.password, ca, settings,
            regenerate_private_key=not args.no_regenerate_key,
            trust_ca_on_device=not args.no_trust_ca,
            request_timeout=args.timeout,
            progress=print,
        )
    except Exception as e:
        print(f"\nPush failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    print("\nPush succeeded.")
    print(f"  Device ApplicationUri: {result.device_application_uri}")
    print(f"  Certificate serial:    {result.serial_hex}")
    print(f"  Subject:               {result.subject}")
    print(f"  Valid until:           {result.not_after}")
    if result.apply_changes_required:
        print("  The device applied the change immediately -- it may have restarted its OPC UA endpoint.")
    print(f"  Recorded in the GDS as application {result.application_id}, certificate {result.certificate_record_id}.")
    print("  Check the web UI's Certificates page to confirm.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
