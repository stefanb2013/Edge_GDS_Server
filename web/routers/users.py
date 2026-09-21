"""Admin-only user management: create, edit (role / reset password), and
delete web UI accounts. Guarded by web.deps.require_admin rather than the
plain require_login every other router uses.
"""
from __future__ import annotations

import asyncio
import sqlite3

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from gds import auth, db
from gds.models import Role
from web.deps import current_user, require_admin, templates

router = APIRouter()


@router.get("/users")
async def list_users(request: Request):
    if (redirect := require_admin(request)) is not None:
        return redirect
    users = await asyncio.to_thread(db.list_users)
    return templates.TemplateResponse(
        request, "users.html",
        {"users": users, "user": request.session.get("user"), "active": "users"},
    )


@router.get("/users/new")
async def new_user_form(request: Request):
    if (redirect := require_admin(request)) is not None:
        return redirect
    return templates.TemplateResponse(
        request, "user_new.html",
        {"user": request.session.get("user"), "active": "users", "error": None},
    )


@router.post("/users")
async def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(Role.USER),
):
    if (redirect := require_admin(request)) is not None:
        return redirect

    username = username.strip()
    error = None
    if not username:
        error = "Username is required."
    elif len(password) < auth.MIN_PASSWORD_LENGTH:
        error = f"Password must be at least {auth.MIN_PASSWORD_LENGTH} characters."
    elif role not in (Role.ADMIN, Role.USER):
        error = "Invalid role."

    if not error:
        password_hash = auth.hash_password(password)
        try:
            # New accounts always start with must_change_password=True: the
            # admin just picked this password, not the person who'll use it.
            await asyncio.to_thread(db.create_user, username, password_hash, role, True)
        except sqlite3.IntegrityError:
            error = f"A user named '{username}' already exists."

    if error:
        return templates.TemplateResponse(
            request, "user_new.html",
            {"user": request.session.get("user"), "active": "users", "error": error},
            status_code=400,
        )
    return RedirectResponse(url="/users", status_code=303)


@router.get("/users/{username}")
async def user_detail(request: Request, username: str):
    if (redirect := require_admin(request)) is not None:
        return redirect
    target = await asyncio.to_thread(db.get_user, username)
    if target is None:
        return RedirectResponse(url="/users", status_code=303)
    return templates.TemplateResponse(
        request, "user_detail.html",
        {
            "target": target, "is_self": target.username == current_user(request),
            "user": request.session.get("user"), "active": "users", "error": None,
        },
    )


@router.post("/users/{username}/role")
async def update_user_role(request: Request, username: str, role: str = Form(...)):
    if (redirect := require_admin(request)) is not None:
        return redirect
    target = await asyncio.to_thread(db.get_user, username)
    if target is None:
        return RedirectResponse(url="/users", status_code=303)

    error = None
    if role not in (Role.ADMIN, Role.USER):
        error = "Invalid role."
    elif target.role == Role.ADMIN and role != Role.ADMIN and await asyncio.to_thread(db.count_admins) <= 1:
        error = "Can't remove the last remaining admin's admin role."

    if error:
        return templates.TemplateResponse(
            request, "user_detail.html",
            {
                "target": target, "is_self": target.username == current_user(request),
                "user": request.session.get("user"), "active": "users", "error": error,
            },
            status_code=400,
        )

    await asyncio.to_thread(db.set_user_role, username, role)
    if username == current_user(request):
        request.session["role"] = role
    return RedirectResponse(url=f"/users/{username}", status_code=303)


@router.post("/users/{username}/reset-password")
async def reset_user_password(request: Request, username: str, password: str = Form(...)):
    if (redirect := require_admin(request)) is not None:
        return redirect
    target = await asyncio.to_thread(db.get_user, username)
    if target is None:
        return RedirectResponse(url="/users", status_code=303)

    if len(password) < auth.MIN_PASSWORD_LENGTH:
        return templates.TemplateResponse(
            request, "user_detail.html",
            {
                "target": target, "is_self": target.username == current_user(request),
                "user": request.session.get("user"), "active": "users",
                "error": f"Password must be at least {auth.MIN_PASSWORD_LENGTH} characters.",
            },
            status_code=400,
        )

    password_hash = auth.hash_password(password)
    # Force a change on next login: an admin resetting someone's password
    # shouldn't leave them permanently on a password the admin also knows.
    await asyncio.to_thread(db.set_user_password, username, password_hash, True)
    if username == current_user(request):
        request.session["must_change_password"] = True
    return RedirectResponse(url=f"/users/{username}", status_code=303)


@router.post("/users/{username}/delete")
async def delete_user(request: Request, username: str):
    if (redirect := require_admin(request)) is not None:
        return redirect
    target = await asyncio.to_thread(db.get_user, username)
    if target is None:
        return RedirectResponse(url="/users", status_code=303)

    error = None
    if username == current_user(request):
        error = "You can't delete your own account while logged in as it."
    elif target.role == Role.ADMIN and await asyncio.to_thread(db.count_admins) <= 1:
        error = "Can't delete the last remaining admin account."

    if error:
        return templates.TemplateResponse(
            request, "user_detail.html",
            {
                "target": target, "is_self": target.username == current_user(request),
                "user": request.session.get("user"), "active": "users", "error": error,
            },
            status_code=400,
        )

    await asyncio.to_thread(db.delete_user, username)
    return RedirectResponse(url="/users", status_code=303)
