"""Entrypoint: runs the OPC UA GDS endpoint and the web admin UI together in
one process/event loop. Used directly (`python main.py`) for local dev and
as the Docker image's CMD.
"""
from __future__ import annotations

import asyncio
import logging

from gds.app_runner import run_server

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


if __name__ == "__main__":
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        pass
