"""Shared helpers for the web admin app: templates and session auth."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from gds.models import Role

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Reachable even while a forced password change is pending -- everything
# else redirects to /account/password until it's done (see require_login).
_ALLOWED_WHILE_PASSWORD_CHANGE_PENDING = {"/account/password", "/logout"}


def current_user(request: Request) -> Optional[str]:
    return request.session.get("user")


def require_login(request: Request) -> Optional[RedirectResponse]:
    """Returns a redirect response if the caller isn't logged in (or must
    change their password first), else None. Call at the top of every
    protected page route:

        if (redirect := require_login(request)) is not None:
            return redirect
    """
    if current_user(request) is None:
        return RedirectResponse(url="/login", status_code=303)
    if (
        request.session.get("must_change_password")
        and request.url.path not in _ALLOWED_WHILE_PASSWORD_CHANGE_PENDING
    ):
        return RedirectResponse(url="/account/password", status_code=303)
    return None


def require_admin(request: Request) -> Optional[RedirectResponse]:
    """Like require_login, but also requires the 'admin' role -- use at the
    top of routes only admins should reach (currently: user management)."""
    redirect = require_login(request)
    if redirect is not None:
        return redirect
    if request.session.get("role") != Role.ADMIN:
        return RedirectResponse(url="/", status_code=303)
    return None
