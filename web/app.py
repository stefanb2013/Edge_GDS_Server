from __future__ import annotations

import asyncio
import ipaddress
import secrets
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from gds import auth, db, pki
from gds.models import Role
from gds.gds_methods import GdsContext
from web.deps import require_login, templates
from web.routers import applications, auth as auth_router, ca_settings, certificates, devices, trustlist, users

STATIC_DIR = Path(__file__).parent / "static"


def ensure_web_tls_certificate(ctx: GdsContext) -> tuple[str, str]:
    """The web admin UI's own TLS server certificate -- signed by this GDS's
    own CA (rather than self-signed) so that once an admin downloads and
    trusts that one root CA (see the Trust List page), the web UI is fully
    trusted too, with no separate certificate to distribute. Generated once
    and reused after that, the same pattern as the OPC UA endpoint's own
    instance certificate (gds/opcua_server.py's _ensure_own_instance_certificate).

    Without this, the login form -- and every session cookie after it --
    would go out in plaintext over HTTP, which is exactly the kind of thing
    a GDS (of all things) should not be doing with its own admin credentials.
    """
    d = ctx.settings.web_tls_cert_dir
    d.mkdir(parents=True, exist_ok=True)
    key_path = d / "web_key.pem"
    cert_path = d / "web_cert.pem"

    if not (key_path.exists() and cert_path.exists()):
        hostname = ctx.settings.hostname
        dns_names, ip_addresses = [], []
        try:
            ipaddress.ip_address(hostname)
            ip_addresses = [hostname]
        except ValueError:
            dns_names = [hostname]

        issued = pki.generate_key_pair_and_cert(
            ctx.ca,
            application_uri=f"urn:{hostname}:GDS:WebUI",
            application_name="Edge GDS Server Web UI",
            dns_names=dns_names,
            ip_addresses=ip_addresses,
            valid_days=3650,
        )
        key_path.write_text(issued.private_key_pem)
        cert_path.write_text(issued.issued.cert_pem)

    return str(key_path), str(cert_path)


def create_app(ctx: GdsContext) -> FastAPI:
    app = FastAPI(title="Edge GDS Server", docs_url=None, redoc_url=None)
    app.state.gds_ctx = ctx

    session_secret = ctx.settings.session_secret or secrets.token_urlsafe(32)
    app.add_middleware(SessionMiddleware, secret_key=session_secret, same_site="lax", https_only=True)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(auth_router.router)
    app.include_router(applications.router)
    app.include_router(certificates.router)
    app.include_router(trustlist.router)
    app.include_router(devices.router)
    app.include_router(ca_settings.router)
    app.include_router(users.router)

    @app.get("/")
    async def dashboard(request: Request):
        if (redirect := require_login(request)) is not None:
            return redirect
        counts = await asyncio.to_thread(db.counts)
        recent = await asyncio.to_thread(db.recent_audit_log, 20)
        return templates.TemplateResponse(
            request, "dashboard.html",
            {
                "counts": counts, "recent": recent, "user": request.session.get("user"),
                "opcua_endpoint": ctx.settings.opcua_endpoint.replace("0.0.0.0", ctx.settings.hostname),
                "ca_subject": ctx.ca.subject_name, "active": "dashboard",
            },
        )

    return app


async def ensure_default_admin(settings) -> None:
    """Creates the first admin user on a fresh database. If no password was
    configured, a random one is generated and printed to the logs once --
    there is no hardcoded default credential. Either way, this initial
    account must have its password changed on first login (web/deps.py
    enforces this for any user with must_change_password set) -- the
    printed/configured password is meant to get in the door once, not to
    stay in use.
    """
    if await asyncio.to_thread(db.any_users_exist):
        return
    password = settings.admin_password or auth.generate_password()
    password_hash = auth.hash_password(password)
    await asyncio.to_thread(
        db.create_user, settings.admin_user, password_hash, Role.ADMIN, True,
    )
    if not settings.admin_password:
        print("=" * 72)
        print(f"  Created initial GDS admin account: {settings.admin_user}")
        print(f"  Generated password (shown only this once): {password}")
        print("  Set GDS_ADMIN_PASSWORD to control this instead.")
        print("=" * 72)
