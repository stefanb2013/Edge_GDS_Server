"""Shared server startup/shutdown, used by both entrypoints:

  main.py            -- plain `python main.py` (dev, and the Docker image)
  windows_service.py -- wrapped as a Windows Service by pywin32

Split out so the Windows service wrapper doesn't have to duplicate startup
logic, and so it has a clean way to ask the server to stop: uvicorn's usual
shutdown path is an OS signal (Ctrl+C / SIGTERM), which a Windows Service
can't rely on the same way -- SvcStop runs on a different thread than the
asyncio event loop, so it needs an asyncio.Event it can signal instead of a
plain "wait for a signal".
"""
from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Optional

import uvicorn

from gds import db, pki, push_client, secrets_store
from gds.config import settings
from gds.gds_methods import GdsContext
from gds.opcua_server import create_server
from web.app import create_app, ensure_default_admin, ensure_web_tls_certificate

logger = logging.getLogger("gds.main")


async def run_server(shutdown_event: Optional[asyncio.Event] = None) -> None:
    """Runs the OPC UA GDS endpoint, the web admin UI, and the push-mode
    auto-reprovision loop until `shutdown_event` is set (if given) or the
    process is otherwise interrupted (Ctrl+C when run directly).
    """
    settings.ensure_dirs()
    db.init_db(settings.db_path)
    db.apply_persisted_settings(settings)

    ca = pki.load_or_create_ca(
        settings.ca_dir,
        settings.ca_common_name,
        settings.ca_organization,
        settings.ca_country,
        settings.ca_key_bits,
        settings.ca_valid_days,
    )
    logger.info("Root CA ready: %s", ca.subject_name)

    if not settings.session_secret:
        settings.session_secret = secrets.token_urlsafe(32)
        logger.warning("GDS_SESSION_SECRET not set; generated a random one (web sessions won't survive a restart)")

    secret_key = secrets_store.load_or_create_key(settings.pki_dir)

    ctx = GdsContext(ca=ca, settings=settings, secret_key=secret_key)

    await ensure_default_admin(settings)

    opcua_server = await create_server(ctx)
    web_app = create_app(ctx)

    web_key_path, web_cert_path = ensure_web_tls_certificate(ctx)

    reprovision_task = asyncio.create_task(
        push_client.auto_reprovision_loop(ctx.ca, ctx.settings, ctx.secret_key)
    )

    uv_config = uvicorn.Config(
        web_app, host="0.0.0.0", port=settings.http_port, log_level="info", access_log=True,
        ssl_keyfile=web_key_path, ssl_certfile=web_cert_path,
    )
    uv_server = uvicorn.Server(uv_config)

    async def _watch_for_shutdown() -> None:
        if shutdown_event is None:
            return
        await shutdown_event.wait()
        logger.info("Shutdown requested -- stopping the web server gracefully.")
        uv_server.should_exit = True

    watcher_task = asyncio.create_task(_watch_for_shutdown())

    logger.info("OPC UA GDS endpoint: %s", settings.opcua_endpoint)
    logger.info("Web admin UI:        https://0.0.0.0:%s/", settings.http_port)
    logger.info(
        "Push-mode auto re-provisioning: %s (every %ss)",
        "enabled" if settings.push_auto_reprovision_enabled else "disabled",
        settings.push_health_check_interval_seconds,
    )

    try:
        async with opcua_server:
            await uv_server.serve()
    finally:
        watcher_task.cancel()
        reprovision_task.cancel()
        for task in (watcher_task, reprovision_task):
            try:
                await task
            except asyncio.CancelledError:
                pass
