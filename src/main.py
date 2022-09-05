"""
WebRTC-SIP Gateway - Main Entry Point

Initializes and orchestrates all gateway components:
  - WebSocket signaling server for WebRTC clients
  - SIP User Agent for communicating with SIP infrastructure
  - RTP media relay for bridging media streams
  - REST API for monitoring and management
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import socket
import sys
from pathlib import Path
from typing import Any

import structlog
import yaml

from src.api.app import create_api_app
from src.gateway.registration import RegistrationManager
from src.gateway.router import CallRouter
from src.media.rtp_relay import RTPRelay
from src.signaling.session_manager import SessionManager
from src.signaling.sip_client import SIPClient
from src.signaling.ws_server import WebSocketServer

logger = structlog.get_logger(__name__)


def load_config(config_path: str) -> dict[str, Any]:
    """Load and validate gateway configuration from YAML file.

    Supports environment variable substitution using ${VAR_NAME} syntax.
    """
    path = Path(config_path)
    if not path.exists():
        logger.error("Configuration file not found", path=config_path)
        sys.exit(1)

    with open(path) as f:
        raw = f.read()

    # Substitute environment variables
    import os
    import re

    def _env_replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, match.group(0))

    raw = re.sub(r"\$\{(\w+)}", _env_replace, raw)
    config: dict[str, Any] = yaml.safe_load(raw)

    logger.info("Configuration loaded", path=config_path)
    return config


def detect_public_ip() -> str:
    """Detect the public-facing IP address of this host.

    Uses a UDP socket trick to find the preferred outbound IP without
    actually sending traffic.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return str(ip)
    except OSError:
        return "127.0.0.1"


class Gateway:
    """Main gateway orchestrator that manages all subsystems."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._shutdown_event = asyncio.Event()

        # Resolve public IP
        gw_cfg = config.get("gateway", {})
        public_ip = gw_cfg.get("public_ip", "auto")
        if public_ip == "auto":
            public_ip = detect_public_ip()
        self.public_ip = public_ip
        logger.info("Public IP resolved", ip=self.public_ip)

        # Initialize subsystems
        self.session_manager = SessionManager(
            max_sessions=config.get("sessions", {}).get("max_sessions", 200),
            setup_timeout=config.get("sessions", {}).get("setup_timeout", 30),
            idle_timeout=config.get("sessions", {}).get("idle_timeout", 3600),
        )

        self.rtp_relay = RTPRelay(
            public_ip=self.public_ip,
            port_min=config.get("media", {}).get("rtp_port_min", 10000),
            port_max=config.get("media", {}).get("rtp_port_max", 10100),
            rtp_timeout=config.get("media", {}).get("rtp_timeout", 60),
        )

        self.sip_client = SIPClient(
            config=config.get("sip", {}),
            public_ip=self.public_ip,
            session_manager=self.session_manager,
            rtp_relay=self.rtp_relay,
        )

        self.call_router = CallRouter(
            config=config.get("routing", {}),
            sip_client=self.sip_client,
            session_manager=self.session_manager,
        )

        self.registration_manager = RegistrationManager(
            sip_client=self.sip_client,
            trunks=config.get("trunks", []),
        )

        self.ws_server = WebSocketServer(
            config=config.get("websocket", {}),
            session_manager=self.session_manager,
            call_router=self.call_router,
        )

    async def start(self) -> None:
        """Start all gateway subsystems."""
        logger.info("Starting WebRTC-SIP Gateway", version="1.0.0")

        # Start RTP relay (allocates port pool)
        await self.rtp_relay.start()
        logger.info("RTP relay started",
                     port_range=f"{self.rtp_relay.port_min}-{self.rtp_relay.port_max}")

        # Start SIP client (binds UDP/TCP socket)
        await self.sip_client.start()
        sip_cfg = self.config.get("sip", {})
        logger.info("SIP client started",
                     host=sip_cfg.get("listen_host", "0.0.0.0"),
                     port=sip_cfg.get("listen_port", 5060))

        # Start registration for configured trunks
        await self.registration_manager.start()

        # Start WebSocket server (includes REST API)
        api_app = create_api_app(
            session_manager=self.session_manager,
            registration_manager=self.registration_manager,
            rtp_relay=self.rtp_relay,
            config=self.config,
        )
        await self.ws_server.start(api_app=api_app)
        ws_cfg = self.config.get("websocket", {})
        logger.info("WebSocket server started",
                     host=ws_cfg.get("host", "0.0.0.0"),
                     port=ws_cfg.get("port", 8765))

        # Start session cleanup task
        asyncio.create_task(self.session_manager.cleanup_loop())

        logger.info("Gateway fully operational",
                     public_ip=self.public_ip,
                     max_sessions=self.config.get("sessions", {}).get("max_sessions", 200))

    async def stop(self) -> None:
        """Gracefully shut down all subsystems."""
        logger.info("Initiating graceful shutdown")

        await self.ws_server.stop()
        await self.registration_manager.stop()
        await self.sip_client.stop()
        await self.rtp_relay.stop()
        await self.session_manager.terminate_all()

        logger.info("Gateway shutdown complete")

    async def run(self) -> None:
        """Run the gateway until shutdown signal is received."""
        await self.start()
        await self._shutdown_event.wait()
        await self.stop()

    def request_shutdown(self) -> None:
        """Signal the gateway to begin shutdown."""
        self._shutdown_event.set()


def main() -> None:
    """CLI entry point for the WebRTC-SIP Gateway."""
    parser = argparse.ArgumentParser(
        description="WebRTC to SIP Gateway",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.main --config config/gateway.yaml
  python -m src.main --config config/gateway.yaml --log-level DEBUG
        """,
    )
    parser.add_argument(
        "--config", "-c",
        default="config/gateway.yaml",
        help="Path to gateway configuration file (default: config/gateway.yaml)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override log level from configuration",
    )
    args = parser.parse_args()

    # Configure structured logging
    config = load_config(args.config)

    log_level = args.log_level or config.get("logging", {}).get("level", "INFO")
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(structlog, log_level, structlog.INFO)
        ),
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer()
            if config.get("logging", {}).get("format") != "json"
            else structlog.processors.JSONRenderer(),
        ],
    )

    gateway = Gateway(config)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Register signal handlers for graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, gateway.request_shutdown)

    try:
        loop.run_until_complete(gateway.run())
    except KeyboardInterrupt:
        loop.run_until_complete(gateway.stop())
    finally:
        loop.close()
        logger.info("Process exiting")


if __name__ == "__main__":
    main()
