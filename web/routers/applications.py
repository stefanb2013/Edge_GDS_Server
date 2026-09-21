from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from gds import db
from gds.models import ApplicationStatus, ApplicationType
from web.deps import require_login, templates

router = APIRouter()

APPLICATION_TYPE_NAMES = {
    ApplicationType.SERVER: "Server",
    ApplicationType.CLIENT: "Client",
    ApplicationType.CLIENT_AND_SERVER: "Client & Server",
    ApplicationType.DISCOVERY_SERVER: "Discovery Server",
}


@router.get("/applications")
async def list_applications(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    apps = await asyncio.to_thread(db.find_applications)
    return templates.TemplateResponse(
        request, "applications.html",
        {
            "apps": apps, "type_names": APPLICATION_TYPE_NAMES, "user": request.session.get("user"),
            "active": "applications",
        },
    )


@router.get("/applications/{app_id}")
async def application_detail(request: Request, app_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    app = await asyncio.to_thread(db.get_application, app_id)
    if app is None:
        return RedirectResponse(url="/applications", status_code=303)
    certs = await asyncio.to_thread(db.list_certificates, app_id)
    return templates.TemplateResponse(
        request, "application_detail.html",
        {
            "app": app, "certs": certs, "type_names": APPLICATION_TYPE_NAMES,
            "user": request.session.get("user"), "active": "applications",
        },
    )


@router.post("/applications/{app_id}/approve")
async def approve_application(request: Request, app_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    await asyncio.to_thread(db.set_application_status, app_id, ApplicationStatus.APPROVED)
    return RedirectResponse(url="/applications", status_code=303)


@router.post("/applications/{app_id}/reject")
async def reject_application(request: Request, app_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    await asyncio.to_thread(db.set_application_status, app_id, ApplicationStatus.REJECTED)
    return RedirectResponse(url="/applications", status_code=303)


@router.post("/applications/{app_id}/delete")
async def delete_application(request: Request, app_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    await asyncio.to_thread(db.delete_application, app_id)
    return RedirectResponse(url="/applications", status_code=303)
