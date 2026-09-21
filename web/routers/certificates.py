from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from gds import db, push_client
from web.deps import require_login, templates

router = APIRouter()


def _get_ctx(request: Request):
    return request.app.state.gds_ctx


@router.get("/certificates")
async def list_certificates(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    certs = await asyncio.to_thread(db.list_certificates)
    apps_by_id = {a.id: a for a in await asyncio.to_thread(db.find_applications)}
    return templates.TemplateResponse(
        request, "certificates.html",
        {
            "certs": certs, "apps_by_id": apps_by_id, "user": request.session.get("user"),
            "active": "certificates",
        },
    )


@router.post("/certificates/{cert_id}/revoke")
async def revoke_certificate(request: Request, cert_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    await asyncio.to_thread(db.revoke_certificate, cert_id)

    # Best-effort: pull-mode applications always get a fresh CRL next time
    # they call GetTrustList, but push-mode devices never ask -- so sync the
    # updated CRL out to every configured push device now. A device being
    # offline or unreachable shouldn't block the revoke itself; the failure
    # just shows up as that device's own "Last CRL push" status.
    ctx = _get_ctx(request)
    devices = await asyncio.to_thread(db.list_push_devices)
    for device in devices:
        status, message = await push_client.push_crl_to_stored_device(device, ctx.ca, ctx.settings, ctx.secret_key)
        await asyncio.to_thread(db.record_push_device_crl_push, device.id, status, message)

    return RedirectResponse(url="/certificates", status_code=303)


@router.get("/certificates/{cert_id}/download")
async def download_certificate(request: Request, cert_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    cert = await asyncio.to_thread(db.get_certificate, cert_id)
    if cert is None:
        return RedirectResponse(url="/certificates", status_code=303)
    return PlainTextResponse(
        cert.pem, media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{cert.serial_number}.pem"'},
    )
