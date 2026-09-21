"""Web UI for configuring OPC UA push-mode targets (gds/push_client.py):
browse a server's endpoints, pick one, set credentials, test the connection,
and trigger a push -- all backed by the `push_devices` table so a device
only has to be configured once.
"""
from __future__ import annotations

import asyncio

from asyncua import ua
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from gds import db, push_client, secrets_store
from gds.gds_methods import GdsContext
from gds.models import PushCheckStatus
from web.deps import require_login, templates

router = APIRouter()


def _get_ctx(request: Request) -> GdsContext:
    return request.app.state.gds_ctx


@router.get("/devices")
async def list_devices(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    devices = await asyncio.to_thread(db.list_push_devices)
    return templates.TemplateResponse(
        request, "devices.html",
        {"devices": devices, "user": request.session.get("user"), "active": "devices"},
    )


@router.post("/devices/check-now")
async def check_devices_now(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    ctx = _get_ctx(request)
    await push_client.run_auto_reprovision_check(ctx.ca, ctx.settings, ctx.secret_key)
    return RedirectResponse(url="/devices", status_code=303)


@router.get("/devices/new")
async def new_device_form(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    return templates.TemplateResponse(
        request, "device_new.html",
        {"user": request.session.get("user"), "active": "devices", "endpoints": None},
    )


@router.post("/devices/discover")
async def discover_device_endpoints(request: Request, endpoint_url: str = Form(...)):
    if (redirect := require_login(request)) is not None:
        return redirect
    endpoint_url = endpoint_url.strip()
    ctx = {
        "user": request.session.get("user"), "active": "devices",
        "endpoint_url": endpoint_url, "endpoints": None,
    }
    try:
        endpoints = await push_client.discover_endpoints(endpoint_url)
    except Exception as exc:
        ctx["error"] = f"Could not reach {endpoint_url}: {type(exc).__name__}: {exc}"
        return templates.TemplateResponse(request, "device_new.html", ctx, status_code=400)

    if not endpoints:
        ctx["error"] = f"{endpoint_url} returned no endpoints."
        return templates.TemplateResponse(request, "device_new.html", ctx, status_code=400)

    ctx["endpoints"] = endpoints
    ctx["default_name"] = endpoints[0].server_application_uri or endpoint_url
    return templates.TemplateResponse(request, "device_new.html", ctx)


@router.post("/devices")
async def create_device(
    request: Request,
    name: str = Form(...),
    endpoint_url: str = Form(...),
    security: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    regenerate_private_key: bool = Form(False),
    trust_ca_on_device: bool = Form(False),
):
    if (redirect := require_login(request)) is not None:
        return redirect
    ctx = _get_ctx(request)
    # `security` is "<policy-uri>||<mode-name>", one radio value per
    # discovered endpoint -- see the endpoint picker in device_new.html.
    security_policy_uri, _, security_mode = security.partition("||")
    password_encrypted = secrets_store.encrypt(ctx.secret_key, password)
    device = await asyncio.to_thread(
        db.create_push_device,
        name.strip() or endpoint_url,
        endpoint_url.strip(),
        security_policy_uri,
        security_mode,
        username,
        password_encrypted,
        regenerate_private_key,
        trust_ca_on_device,
    )
    return RedirectResponse(url=f"/devices/{device.id}", status_code=303)


@router.get("/devices/{device_id}")
async def device_detail(request: Request, device_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    device = await asyncio.to_thread(db.get_push_device, device_id)
    if device is None:
        return RedirectResponse(url="/devices", status_code=303)
    policy_choices = [(uri, uri.rsplit("#", 1)[-1]) for uri in push_client.SECURITY_POLICIES]
    return templates.TemplateResponse(
        request, "device_detail.html",
        {
            "device": device, "policy_choices": policy_choices,
            "user": request.session.get("user"), "active": "devices",
        },
    )


@router.post("/devices/{device_id}")
async def update_device(
    request: Request,
    device_id: str,
    name: str = Form(...),
    endpoint_url: str = Form(...),
    security_policy_uri: str = Form(...),
    security_mode: str = Form(...),
    username: str = Form(...),
    password: str = Form(""),
    regenerate_private_key: bool = Form(False),
    trust_ca_on_device: bool = Form(False),
):
    if (redirect := require_login(request)) is not None:
        return redirect
    ctx = _get_ctx(request)
    password_encrypted = secrets_store.encrypt(ctx.secret_key, password) if password else None
    await asyncio.to_thread(
        db.update_push_device,
        device_id, name.strip() or endpoint_url, endpoint_url.strip(), security_policy_uri,
        security_mode, username, regenerate_private_key, trust_ca_on_device, password_encrypted,
    )
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)


@router.post("/devices/{device_id}/delete")
async def delete_device(request: Request, device_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    await asyncio.to_thread(db.delete_push_device, device_id)
    return RedirectResponse(url="/devices", status_code=303)


@router.post("/devices/{device_id}/test")
async def test_device(request: Request, device_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    ctx = _get_ctx(request)
    device = await asyncio.to_thread(db.get_push_device, device_id)
    if device is None:
        return RedirectResponse(url="/devices", status_code=303)

    password = secrets_store.decrypt(ctx.secret_key, device.password_encrypted)
    result = await push_client.test_connection(
        device.endpoint_url, device.username, password, ctx.settings,
        security_policy_uri=device.security_policy_uri,
        security_mode=ua.MessageSecurityMode[device.security_mode],
    )
    status = PushCheckStatus.SUCCESS if result.success else PushCheckStatus.FAILED
    await asyncio.to_thread(db.record_push_device_test, device_id, status, result.message)
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)


@router.post("/devices/{device_id}/push")
async def push_device(request: Request, device_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    ctx = _get_ctx(request)
    device = await asyncio.to_thread(db.get_push_device, device_id)
    if device is None:
        return RedirectResponse(url="/devices", status_code=303)

    status, message = await push_client.push_certificate_to_stored_device(
        device, ctx.ca, ctx.settings, ctx.secret_key,
    )
    await asyncio.to_thread(db.record_push_device_push, device_id, status, message)
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)


@router.post("/devices/{device_id}/push-crl")
async def push_crl_to_device(request: Request, device_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    ctx = _get_ctx(request)
    device = await asyncio.to_thread(db.get_push_device, device_id)
    if device is None:
        return RedirectResponse(url="/devices", status_code=303)

    status, message = await push_client.push_crl_to_stored_device(device, ctx.ca, ctx.settings, ctx.secret_key)
    await asyncio.to_thread(db.record_push_device_crl_push, device_id, status, message)
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)
