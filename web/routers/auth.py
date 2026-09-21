from __future__ import annotations

import asyncio

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from gds import auth, db
from web.deps import current_user, require_login, templates

router = APIRouter()


@router.get("/login")
async def login_form(request: Request):
    if request.session.get("user"):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    user = await asyncio.to_thread(db.get_user, username)
    if user is None or not auth.verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid username or password"}, status_code=401
        )
    request.session["user"] = user.username
    request.session["role"] = user.role
    request.session["must_change_password"] = user.must_change_password
    return RedirectResponse(url="/", status_code=303)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@router.get("/account/password")
async def change_password_form(request: Request):
    if (redirect := require_login(request)) is not None:
        return redirect
    return templates.TemplateResponse(
        request, "change_password.html",
        {
            "user": current_user(request), "active": "",
            "forced": bool(request.session.get("must_change_password")),
            "error": None,
        },
    )


@router.post("/account/password")
async def change_password_submit(
    request: Request, new_password: str = Form(...), confirm_password: str = Form(...),
):
    if (redirect := require_login(request)) is not None:
        return redirect

    forced = bool(request.session.get("must_change_password"))
    error = None
    if new_password != confirm_password:
        error = "Passwords do not match."
    elif len(new_password) < auth.MIN_PASSWORD_LENGTH:
        error = f"Password must be at least {auth.MIN_PASSWORD_LENGTH} characters."

    if error:
        return templates.TemplateResponse(
            request, "change_password.html",
            {"user": current_user(request), "active": "", "forced": forced, "error": error},
            status_code=400,
        )

    username = current_user(request)
    password_hash = auth.hash_password(new_password)
    await asyncio.to_thread(db.set_user_password, username, password_hash, False)
    request.session["must_change_password"] = False
    return RedirectResponse(url="/", status_code=303)
