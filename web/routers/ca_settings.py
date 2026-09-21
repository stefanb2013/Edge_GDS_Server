"""Web UI for the GDS-wide certificate policy: how long issued certificates
are valid, how long before expiry they're flagged for renewal, and the CRL's
validity window -- the equivalent of Unified Automation's UaGDS Configuration
Tool's "CA Certificate Settings" / "Issued OPC UA Application Certificate
Settings" panels, adapted to what this GDS actually does at runtime (it has
no cached/scheduled CRL refresh or CA-rotation flow, so those UaGDS fields
aren't reproduced here -- see the fields that _are_ here for what's real).

Also hosts the push-mode auto-reprovisioning controls (enable/disable,
check interval) for gds/push_client.py's background loop -- not part of
UaGDS, but the natural place for it alongside the rest of the GDS's
certificate policy.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from gds import db
from gds.gds_methods import GdsContext
from web.deps import require_login, templates

router = APIRouter()


def _get_ctx(request: Request) -> GdsContext:
    return request.app.state.gds_ctx


@router.get("/settings")
async def settings_page(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    ctx = _get_ctx(request)
    return templates.TemplateResponse(
        request, "settings.html",
        {
            "ca": ctx.ca, "settings": ctx.settings,
            "user": request.session.get("user"), "active": "settings",
        },
    )


@router.post("/settings")
async def update_settings(
    request: Request,
    issued_cert_valid_days: int = Form(...),
    renew_before_days: int = Form(...),
    crl_validity_days: int = Form(...),
):
    if (redirect := require_login(request)) is not None:
        return redirect
    ctx = _get_ctx(request)

    error = None
    if issued_cert_valid_days < 1 or renew_before_days < 1 or crl_validity_days < 1:
        error = "All values must be at least 1 day."
    elif renew_before_days >= issued_cert_valid_days:
        error = "Renew-before-expiry must be shorter than the certificate validity period."

    if error:
        return templates.TemplateResponse(
            request, "settings.html",
            {
                "ca": ctx.ca, "settings": ctx.settings, "error": error,
                "user": request.session.get("user"), "active": "settings",
                # Echo back what the admin typed rather than the still-active values.
                "form_override": {
                    "issued_cert_valid_days": issued_cert_valid_days,
                    "renew_before_days": renew_before_days,
                    "crl_validity_days": crl_validity_days,
                },
            },
            status_code=400,
        )

    ctx.settings.issued_cert_valid_days = issued_cert_valid_days
    ctx.settings.renew_before_days = renew_before_days
    ctx.settings.crl_validity_days = crl_validity_days
    await asyncio.to_thread(db.set_setting, "issued_cert_valid_days", str(issued_cert_valid_days))
    await asyncio.to_thread(db.set_setting, "renew_before_days", str(renew_before_days))
    await asyncio.to_thread(db.set_setting, "crl_validity_days", str(crl_validity_days))

    return RedirectResponse(url="/settings", status_code=303)


@router.post("/settings/push-reprovision")
async def update_push_reprovision_settings(
    request: Request,
    push_auto_reprovision_enabled: bool = Form(False),
    push_health_check_interval_seconds: int = Form(...),
):
    if (redirect := require_login(request)) is not None:
        return redirect
    ctx = _get_ctx(request)

    if push_health_check_interval_seconds < 30:
        return templates.TemplateResponse(
            request, "settings.html",
            {
                "ca": ctx.ca, "settings": ctx.settings,
                "user": request.session.get("user"), "active": "settings",
                "error": "The health-check interval must be at least 30 seconds.",
            },
            status_code=400,
        )

    ctx.settings.push_auto_reprovision_enabled = push_auto_reprovision_enabled
    ctx.settings.push_health_check_interval_seconds = push_health_check_interval_seconds
    await asyncio.to_thread(
        db.set_setting, "push_auto_reprovision_enabled", "1" if push_auto_reprovision_enabled else "0",
    )
    await asyncio.to_thread(
        db.set_setting, "push_health_check_interval_seconds", str(push_health_check_interval_seconds),
    )

    return RedirectResponse(url="/settings", status_code=303)
