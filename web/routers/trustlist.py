from __future__ import annotations

import asyncio

from cryptography import x509
from fastapi import APIRouter, Form, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse

from gds import db, pki
from web.deps import require_login, templates

router = APIRouter()


def _get_ca(request: Request) -> pki.RootCA:
    return request.app.state.gds_ctx.ca


@router.get("/trustlist")
async def trust_list_page(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    ca = _get_ca(request)
    entries = await asyncio.to_thread(db.list_trust_list_entries)
    revoked_serials = [c.serial_number for c in await asyncio.to_thread(db.all_revoked_certificates)]
    crl_validity_days = request.app.state.gds_ctx.settings.crl_validity_days
    crl_pem = await asyncio.to_thread(pki.build_crl, ca, revoked_serials, crl_validity_days)
    return templates.TemplateResponse(
        request, "trustlist.html",
        {
            "ca_cert_pem": ca.cert_pem,
            "ca_subject": ca.subject_name,
            "crl_pem": crl_pem,
            "entries": entries,
            "user": request.session.get("user"),
            "active": "trustlist",
        },
    )


@router.post("/trustlist/upload")
async def upload_trust_list_entry(request: Request, kind: str = Form(...), label: str = Form(""),
                                   file: UploadFile = None):
    if (redirect := require_login(request)) is not None:
        return redirect
    if file is not None:
        content = (await file.read()).decode(errors="replace")
        # Validate it actually parses as a certificate or CRL before storing it.
        try:
            if "CRL" in kind:
                x509.load_pem_x509_crl(content.encode())
            else:
                x509.load_pem_x509_certificate(content.encode())
        except Exception:
            entries = await asyncio.to_thread(db.list_trust_list_entries)
            ca = _get_ca(request)
            return templates.TemplateResponse(
                request, "trustlist.html",
                {
                    "ca_cert_pem": ca.cert_pem, "ca_subject": ca.subject_name,
                    "crl_pem": "", "entries": entries, "user": request.session.get("user"),
                    "active": "trustlist", "error": "Uploaded file is not a valid PEM certificate/CRL.",
                },
                status_code=400,
            )
        await asyncio.to_thread(db.add_trust_list_entry, kind, label or file.filename or kind, content)
    return RedirectResponse(url="/trustlist", status_code=303)


@router.post("/trustlist/{entry_id}/delete")
async def delete_trust_list_entry(request: Request, entry_id: str):
    if (redirect := require_login(request)) is not None:
        return redirect
    await asyncio.to_thread(db.delete_trust_list_entry, entry_id)
    return RedirectResponse(url="/trustlist", status_code=303)


@router.get("/trustlist/ca.crt")
async def download_ca_cert(request: Request):
    # Deliberately public, unlike every other route here: a root CA
    # certificate is meant to be freely distributed -- it's exactly what an
    # admin needs to fetch and trust *before* the first login, so the web
    # UI's own TLS certificate (signed by this same CA, see
    # web/app.py's ensure_web_tls_certificate) stops showing a browser
    # warning. Nothing sensitive lives in a public certificate.
    ca = _get_ca(request)
    return PlainTextResponse(
        ca.cert_pem, media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="gds-root-ca.crt"'},
    )
