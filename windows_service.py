"""Windows Service wrapper for the Edge GDS Server, using pywin32.

Usage (as an installed .exe, run as Administrator):
    EdgeGDSServer.exe install     register the service (Manual start)
    EdgeGDSServer.exe start       start it
    EdgeGDSServer.exe stop        stop it
    EdgeGDSServer.exe remove      unregister it
    EdgeGDSServer.exe debug       run in the foreground, logging to the console
    EdgeGDSServer.exe --startup=auto install   register with Automatic start

pywin32's ServiceFramework expects a synchronous SvcDoRun/SvcStop pair (a
Windows Service is not asyncio-native), so the actual asyncio event loop
runs on a dedicated background thread; SvcStop hands the loop a shutdown
signal via gds.app_runner.run_server's `shutdown_event` rather than relying
on OS signals, which a service can't count on receiving the way a console
process does.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import threading

import servicemanager
import win32event
import win32service
import win32serviceutil

from gds.app_runner import run_server

logger = logging.getLogger("gds.windows_service")


class EdgeGDSService(win32serviceutil.ServiceFramework):
    _svc_name_ = "EdgeGDSServer"
    _svc_display_name_ = "Edge GDS Server"
    _svc_description_ = (
        "OPC UA Global Discovery Server: issues, pushes, and revokes application "
        "certificates for OPC UA servers and clients (pull and push mode)."
    )

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._shutdown_event: asyncio.Event | None = None
        self._thread: threading.Thread | None = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self._loop is not None and self._shutdown_event is not None:
            self._loop.call_soon_threadsafe(self._shutdown_event.set)
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        self._run_asyncio_loop()
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ""),
        )

    def _run_asyncio_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._shutdown_event = asyncio.Event()
        try:
            self._loop.run_until_complete(run_server(shutdown_event=self._shutdown_event))
        except Exception:
            logger.exception("Edge GDS Server crashed")
            servicemanager.LogErrorMsg(f"Edge GDS Server crashed: {sys.exc_info()[1]}")
        finally:
            self._loop.close()


def _configure_logging_for_service() -> None:
    """SvcDoRun has no console; log to a file next to the .exe (or the repo
    root in dev) instead, so `debug`/service failures are diagnosable."""
    from pathlib import Path
    log_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).parent
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        filename=str(log_dir / "edge-gds-server.log"),
    )


if __name__ == "__main__":
    _configure_logging_for_service()
    if len(sys.argv) == 1:
        # Launched by the Service Control Manager itself (no CLI args) --
        # this is the actual "running as a service" path.
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(EdgeGDSService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # install / start / stop / remove / debug, run interactively by an admin.
        win32serviceutil.HandleCommandLine(EdgeGDSService)
