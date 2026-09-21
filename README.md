# Edge GDS Server

A self-hosted **OPC UA Global Discovery Server (GDS)** — the OPC UA Part 12
workflow implemented by tools like Unified Automation's **UaGDS**: OPC UA
applications register themselves, a human administrator approves them, and
approved applications can then request, renew, and revoke application
instance certificates issued by a built-in Certificate Authority, and pull a
trust list (CA certificate, CRL, and any additional trusted/issuer entries).

Unlike UaGDS, this project also ships a **web admin UI** alongside the real
OPC UA endpoint, and it runs as a single Docker container.

```
 OPC UA clients/servers            Admin's browser
  (register, get certs)              (approve, manage)
        │  opc.tcp :4840                  │  http(s) :8443
        ▼                                 ▼
 ┌───────────────────────┐      ┌────────────────────────┐
 │  asyncua GDS server    │      │  FastAPI web admin UI  │
 │  real OPC UA Part 12   │      │  (Jinja2 templates)    │
 │  Directory object,     │◄────►│                        │
 │  imported from the     │ same └────────────────────────┘
 │  official GDS nodeset  │  DB
 └───────────┬────────────┘
             │
   ┌─────────▼─────────┐        ┌─────────────────────┐
   │   gds/pki.py       │        │   gds/db.py (SQLite) │
   │   Root CA, issue/  │◄──────►│   apps, certs, users,│
   │   revoke, CRL      │        │   trust list entries │
   └────────────────────┘        └─────────────────────┘
             │
   /data (volume): gds.db, pki/ca, pki/issued, pki/server_instance
```

## Quick start (Docker)

```bash
cp .env.example .env      # edit at least GDS_HOSTNAME and the CA subject fields
docker compose up --build
```

On first boot the container:

* generates a root CA under the `gds-data` volume (`/data/pki/ca`),
* creates the initial web admin account (`GDS_ADMIN_USER`, default `admin`) —
  if `GDS_ADMIN_PASSWORD` isn't set, a random password is generated and
  printed **once** to `docker compose logs gds-server`,
* generates a TLS certificate for the web UI signed by that same root CA,
* starts the OPC UA GDS endpoint on `opc.tcp://<host>:4840/gds/` and the web
  UI on `https://<host>:8443/` -- your browser will warn about an untrusted
  certificate until you download and trust the root CA (`/trustlist/ca.crt`,
  reachable without logging in for exactly this reason).

Log into the web UI, and use `python scripts/test_client.py opc.tcp://<host>:4840/gds/`
from a machine with the dev dependencies installed to see the OPC UA side
work end-to-end (it registers a test application, waits for you to approve
it in the UI, then requests and verifies a certificate).

## Local development (without Docker)

```bash
python -m venv .venv
.venv/Scripts/activate   # or `source .venv/bin/activate` on Linux/macOS
pip install -r requirements-dev.txt
python main.py
pytest
```

## The GDS workflow this implements

| Step | OPC UA method on the `Directory` object | Web UI equivalent |
|---|---|---|
| An application registers itself | `RegisterApplication` | shows up under **Applications**, status `pending` |
| An admin reviews and approves it | — | **Applications** → *Approve* / *Reject* |
| Look up registered applications | `FindApplications` | **Applications** list |
| List available certificate groups | `GetCertificateGroups` | — |
| Get a cert signed from your own CSR | `StartSigningRequest` + `FinishRequest` | issued cert appears under **Certificates** |
| Get the GDS to generate your key pair too | `StartNewKeyPairRequest` + `FinishRequest` | same |
| Check your current certificate | `GetCertificateStatus` | **Certificates** |
| Revoke a certificate | `RevokeCertificate` | **Certificates** → *Revoke* |
| Get the CA cert, CRL, and trusted/issuer entries | `GetTrustList` | **Trust List / CA** |
| Deregister | `UnregisterApplication` | **Applications** → *Unregister* |

An application must be **approved** by an admin in the web UI before any
certificate-related method will succeed for it (`StartSigningRequest`,
`StartNewKeyPairRequest`, `GetCertificateStatus`, `GetTrustList`,
`GetCertificateGroups` all return `BadUserAccessDenied` until then) — this
mirrors the manual review step UaGDS's own configuration tool walks you
through.

## Real OPC UA Part 12, not a look-alike

The `Directory` object and everything under it is **imported from the
official `Opc.Ua.Gds.NodeSet2.xml`** (OPC Foundation, MIT-licensed, vendored
under [nodesets/](nodesets/)) rather than hand-built: real NodeIds under the
real `http://opcfoundation.org/UA/GDS/` namespace, real
`ApplicationRecordDataType`/`TrustListDataType` structures on the wire, and
the standard `FileType` Open/OpenWithMasks/Read/Close pull for
`GetTrustList`. Any standards-conformant GDS client — a PLC's built-in
"managed certificate store" pull client included — should be able to browse
to `Objects/Directory` and use it directly; this was verified against a real
B&R PLC in production, not just against `scripts/test_client.py`.

One thing to know if you ever touch `gds/opcua_server.py`: importing the
nodeset hits a real bug in `asyncua` 2.0.1 — its dynamic struct codegen
(`asyncua.common.structures104`) registers `ApplicationRecordDataType` (the
one GDS structure declared only via `DataTypeDefinition`, with no separate
"Default Binary" encoding object) with a **null NodeId** as its binary
encoding id, instead of resolving one. `fix_null_extension_object_encodings()`
in that module works around it by resolving the correct id (the DataType's
own NodeId, per the OPC UA 1.04+ convention) via BrowseName lookup, and is
called on both the server (in `build_address_space`) and by
`scripts/test_client.py` on its own client connection. A real (non-asyncua)
GDS client never hits this — it's purely an asyncua-to-asyncua concern — so
if a future asyncua release fixes it upstream, this workaround becomes a
no-op (it only touches classes it finds still broken) and can eventually be
deleted.

**Still not modeled** (out of v1 scope, unlike everything above which is
real): `RegisterApplication2`/KeyCredentials, certificate groups beyond the
three the nodeset pre-builds (`DefaultApplicationGroup`, `DefaultHttpsGroup`,
`DefaultUserTokenGroup` — all wired to the same underlying CA/trust list for
now), GDS-driven audit events, and acting as a Local Discovery Server
(`RegisterServer2`/`FindServersOnNetwork`) — this is a GDS (application +
certificate registry), not an LDS.

## Configuration

See [.env.example](.env.example) for every environment variable
(`GDS_HOSTNAME`, `GDS_CA_*`, `GDS_ADMIN_USER`/`GDS_ADMIN_PASSWORD`,
`GDS_OPCUA_PORT`/`GDS_HTTP_PORT`, `GDS_DATA_DIR`, `GDS_SESSION_SECRET`).

## Security notes

* The root CA private key and the SQLite database (which holds every issued
  certificate and password hashes) live under `/data` — treat that volume
  like a secrets store: back it up carefully and restrict who can read it.
* Passwords are hashed with PBKDF2-HMAC-SHA256 (260k iterations), not
  bcrypt — see the docstring in `gds/auth.py` for why (a passlib/bcrypt
  version incompatibility, not a security downgrade).
* The web UI's session cookie is signed with `GDS_SESSION_SECRET`; set it
  explicitly in production so admin sessions survive a container restart.
  The UI itself is served over HTTPS with a certificate signed by the GDS's
  own root CA (`web/app.py`'s `ensure_web_tls_certificate`), and the session
  cookie is marked `Secure` accordingly — a login form or session cookie
  going out over plaintext HTTP was a real, fixed issue, not a
  hypothetical one (caught by an OpenVAS scan).
* `StartSigningRequest` validates that a CSR's `ApplicationUri` SAN (when
  present) matches the caller's registered `ApplicationUri` before signing
  — this is the actual trust boundary the CA enforces.

## Project layout

```
gds/              core logic: config, sqlite storage, PKI/CA, OPC UA server + methods
web/              FastAPI admin UI: routers, Jinja2 templates, static assets
nodesets/         vendored official Opc.Ua.Gds.NodeSet2.xml (OPC Foundation, MIT)
scripts/          scripts/test_client.py -- end-to-end OPC UA demo/verification client
tests/            pytest unit tests for gds/pki.py and gds/db.py
main.py           entrypoint: runs the OPC UA server and the web UI together
Dockerfile, docker-compose.yml
Dockerfile.offline   builds from a local wheels/ dir + a pre-loaded base image instead
                     of reaching PyPI/Docker Hub -- for air-gapped hosts; see its header
                     comment for the two-step fetch-elsewhere/build-here recipe
```
