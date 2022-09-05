"""
WebSocket Signaling Server for WebRTC Clients

Provides the signaling channel between browser-based WebRTC clients and the
gateway. Implements a JSON-based signaling protocol for:
  - Client registration and authentication
  - SDP offer/answer exchange
  - ICE candidate trickle
  - Call control (initiate, accept, reject, hangup)
  - Presence and status notifications

The WebSocket server is built on aiohttp and integrates with the FastAPI
REST API under the same HTTP server.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import aiohttp
import aiohttp.web
import structlog

from src.gateway.router import CallRouter
from src.signaling.session_manager import SessionManager, SessionState

logger = structlog.get_logger(__name__)


@dataclass
class WebRTCClient:
    """Represents a connected WebRTC client."""

    client_id: str
    ws: aiohttp.web.WebSocketResponse
    display_name: str = ""
    sip_uri: str = ""
    registered: bool = False
    connected_at: float = field(default_factory=time.time)
    last_ping: float = field(default_factory=time.time)
    active_sessions: list[str] = field(default_factory=list)

    @property
    def info(self) -> dict[str, Any]:
        """Return client metadata for API responses."""
        return {
            "client_id": self.client_id,
            "display_name": self.display_name,
            "sip_uri": self.sip_uri,
            "registered": self.registered,
            "connected_at": self.connected_at,
            "active_sessions": len(self.active_sessions),
        }


class WebSocketServer:
    """WebSocket signaling server for WebRTC client communication.

    Handles the signaling plane between WebRTC browsers and the gateway,
    translating JSON signaling messages into SIP operations via the
    CallRouter and SessionManager.
    """

    def __init__(
        self,
        config: dict[str, Any],
        session_manager: SessionManager,
        call_router: CallRouter,
    ) -> None:
        self.host = config.get("host", "0.0.0.0")
        self.port = config.get("port", 8765)
        self.ws_path = config.get("path", "/ws")
        self.max_connections = config.get("max_connections", 500)
        self.ping_interval = config.get("ping_interval", 30)
        self.connection_timeout = config.get("connection_timeout", 60)

        self.session_manager = session_manager
        self.call_router = call_router

        # Connected clients indexed by client_id
        self.clients: dict[str, WebRTCClient] = {}
        self._app: aiohttp.web.Application | None = None
        self._runner: aiohttp.web.AppRunner | None = None
        self._site: aiohttp.web.TCPSite | None = None
        self._ping_task: asyncio.Task[None] | None = None

    @property
    def connected_count(self) -> int:
        """Number of currently connected clients."""
        return len(self.clients)

    async def start(self, api_app: Any = None) -> None:
        """Start the WebSocket server with optional FastAPI integration."""
        self._app = aiohttp.web.Application()
        self._app.router.add_get(self.ws_path, self._handle_websocket)

        # Serve static web client files
        self._app.router.add_static("/web", "web", show_index=True)

        # Mount FastAPI app under /api if provided
        if api_app is not None:
            from aiohttp.web import middleware

            # Add FastAPI routes through a sub-application approach
            # We'll integrate FastAPI via its ASGI interface
            self._setup_api_routes(api_app)

        self._runner = aiohttp.web.AppRunner(self._app)
        await self._runner.setup()
        self._site = aiohttp.web.TCPSite(self._runner, self.host, self.port)
        await self._site.start()

        # Start keepalive ping task
        self._ping_task = asyncio.create_task(self._ping_loop())

        logger.info("WebSocket server listening",
                     host=self.host, port=self.port, path=self.ws_path)

    def _setup_api_routes(self, api_app: Any) -> None:
        """Register REST API routes from the FastAPI app into aiohttp."""
        assert self._app is not None

        # Import routes and register them directly on aiohttp
        from src.api.routes import setup_aiohttp_routes
        setup_aiohttp_routes(self._app, api_app)

    async def stop(self) -> None:
        """Gracefully shut down the WebSocket server."""
        if self._ping_task:
            self._ping_task.cancel()
            try:
                await self._ping_task
            except asyncio.CancelledError:
                pass

        # Close all client connections
        for client in list(self.clients.values()):
            await self._send_message(client, {
                "type": "server_shutdown",
                "message": "Gateway is shutting down",
            })
            await client.ws.close(
                code=aiohttp.WSCloseCode.GOING_AWAY,
                message=b"Server shutting down",
            )

        if self._site:
            await self._site.stop()
        if self._runner:
            await self._runner.cleanup()

        logger.info("WebSocket server stopped")

    async def _handle_websocket(
        self, request: aiohttp.web.Request
    ) -> aiohttp.web.WebSocketResponse:
        """Handle incoming WebSocket connections from WebRTC clients."""
        if len(self.clients) >= self.max_connections:
            logger.warning("Max connections reached, rejecting client")
            return aiohttp.web.WebSocketResponse(
                status=503, reason="Server at capacity"
            )

        ws = aiohttp.web.WebSocketResponse(
            heartbeat=self.ping_interval,
            max_msg_size=64 * 1024,  # 64KB max message
        )
        await ws.prepare(request)

        client_id = str(uuid.uuid4())
        client = WebRTCClient(client_id=client_id, ws=ws)
        self.clients[client_id] = client

        logger.info("WebRTC client connected",
                     client_id=client_id,
                     remote=request.remote)

        # Send welcome message with assigned client ID
        await self._send_message(client, {
            "type": "welcome",
            "client_id": client_id,
            "server_version": "1.0.0",
        })

        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await self._handle_message(client, msg.data)
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error("WebSocket error",
                                 client_id=client_id,
                                 error=ws.exception())
                elif msg.type == aiohttp.WSMsgType.CLOSE:
                    break
        except asyncio.CancelledError:
            pass
        finally:
            await self._handle_disconnect(client)

        return ws

    async def _handle_message(self, client: WebRTCClient, raw: str) -> None:
        """Parse and dispatch a signaling message from a WebRTC client."""
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            await self._send_error(client, "INVALID_JSON", "Malformed JSON message")
            return

        msg_type = message.get("type")
        if not msg_type:
            await self._send_error(client, "MISSING_TYPE", "Message must include 'type'")
            return

        log = logger.bind(client_id=client.client_id, msg_type=msg_type)

        handler_map = {
            "register": self._handle_register,
            "call": self._handle_call_initiate,
            "answer": self._handle_call_answer,
            "reject": self._handle_call_reject,
            "hangup": self._handle_hangup,
            "sdp_offer": self._handle_sdp_offer,
            "sdp_answer": self._handle_sdp_answer,
            "ice_candidate": self._handle_ice_candidate,
            "dtmf": self._handle_dtmf,
            "hold": self._handle_hold,
            "unhold": self._handle_unhold,
        }

        handler = handler_map.get(msg_type)
        if handler is None:
            log.warning("Unknown message type")
            await self._send_error(client, "UNKNOWN_TYPE", f"Unknown message type: {msg_type}")
            return

        try:
            await handler(client, message)
        except Exception:
            log.exception("Error handling message")
            await self._send_error(
                client, "INTERNAL_ERROR", "Internal server error processing message"
            )

    async def _handle_register(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Handle client registration with display name and SIP URI."""
        display_name = message.get("display_name", "")
        sip_uri = message.get("sip_uri", "")
        auth_token = message.get("auth_token")

        # In production, validate auth_token against your identity provider
        # For now, accept all registrations
        client.display_name = display_name
        client.sip_uri = sip_uri
        client.registered = True

        logger.info("Client registered",
                     client_id=client.client_id,
                     display_name=display_name,
                     sip_uri=sip_uri)

        await self._send_message(client, {
            "type": "registered",
            "client_id": client.client_id,
            "sip_uri": sip_uri,
        })

    async def _handle_call_initiate(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Handle outbound call initiation from WebRTC client to SIP."""
        if not client.registered:
            await self._send_error(client, "NOT_REGISTERED", "Must register before making calls")
            return

        destination = message.get("destination", "")
        sdp_offer = message.get("sdp")

        if not destination:
            await self._send_error(client, "MISSING_DESTINATION", "Call requires 'destination'")
            return
        if not sdp_offer:
            await self._send_error(client, "MISSING_SDP", "Call requires 'sdp' offer")
            return

        logger.info("Call initiation requested",
                     client_id=client.client_id,
                     destination=destination)

        # Route the call through the call router
        result = await self.call_router.route_outbound(
            client_id=client.client_id,
            caller_uri=client.sip_uri,
            destination=destination,
            sdp_offer=sdp_offer,
        )

        if result.get("success"):
            session_id = result["session_id"]
            client.active_sessions.append(session_id)
            await self._send_message(client, {
                "type": "call_proceeding",
                "session_id": session_id,
                "destination": result.get("normalized_destination", destination),
            })
        else:
            await self._send_error(
                client,
                result.get("error_code", "ROUTE_FAILED"),
                result.get("error_message", "Failed to route call"),
            )

    async def _handle_call_answer(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Handle WebRTC client answering an inbound call from SIP."""
        session_id = message.get("session_id", "")
        sdp_answer = message.get("sdp")

        if not session_id or not sdp_answer:
            await self._send_error(
                client, "MISSING_PARAMS", "Answer requires 'session_id' and 'sdp'"
            )
            return

        session = self.session_manager.get_session(session_id)
        if not session:
            await self._send_error(client, "SESSION_NOT_FOUND", "Session does not exist")
            return

        logger.info("Call answered by WebRTC client",
                     client_id=client.client_id, session_id=session_id)

        # Forward SDP answer to SIP side via call router
        await self.call_router.handle_webrtc_answer(session_id, sdp_answer)
        client.active_sessions.append(session_id)

    async def _handle_call_reject(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Handle WebRTC client rejecting an inbound call."""
        session_id = message.get("session_id", "")
        reason = message.get("reason", "Busy Here")

        session = self.session_manager.get_session(session_id)
        if not session:
            await self._send_error(client, "SESSION_NOT_FOUND", "Session does not exist")
            return

        logger.info("Call rejected by WebRTC client",
                     client_id=client.client_id,
                     session_id=session_id,
                     reason=reason)

        await self.call_router.handle_webrtc_reject(session_id, reason)

    async def _handle_hangup(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Handle call termination from WebRTC client."""
        session_id = message.get("session_id", "")

        session = self.session_manager.get_session(session_id)
        if not session:
            await self._send_error(client, "SESSION_NOT_FOUND", "Session does not exist")
            return

        logger.info("Hangup requested", client_id=client.client_id, session_id=session_id)

        await self.call_router.handle_hangup(session_id, "webrtc")
        if session_id in client.active_sessions:
            client.active_sessions.remove(session_id)

    async def _handle_sdp_offer(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Handle re-INVITE SDP offer for session modification."""
        session_id = message.get("session_id", "")
        sdp = message.get("sdp", "")

        if not session_id or not sdp:
            await self._send_error(
                client, "MISSING_PARAMS", "SDP offer requires 'session_id' and 'sdp'"
            )
            return

        await self.call_router.handle_sdp_reoffer(session_id, sdp, "webrtc")

    async def _handle_sdp_answer(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Handle SDP answer for a re-INVITE from the SIP side."""
        session_id = message.get("session_id", "")
        sdp = message.get("sdp", "")

        if not session_id or not sdp:
            await self._send_error(
                client, "MISSING_PARAMS", "SDP answer requires 'session_id' and 'sdp'"
            )
            return

        await self.call_router.handle_sdp_reanswer(session_id, sdp, "webrtc")

    async def _handle_ice_candidate(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Handle trickle ICE candidate from WebRTC client.

        In a gateway scenario with ICE-lite, we typically gather our own
        candidates and relay the client's candidates for connectivity checks.
        """
        session_id = message.get("session_id", "")
        candidate = message.get("candidate")
        sdp_mid = message.get("sdpMid", "")
        sdp_mline_index = message.get("sdpMLineIndex", 0)

        if not session_id:
            await self._send_error(
                client, "MISSING_PARAMS", "ICE candidate requires 'session_id'"
            )
            return

        logger.debug("ICE candidate received",
                      client_id=client.client_id,
                      session_id=session_id,
                      candidate=candidate)

        # Process candidate through the session's ICE handler
        session = self.session_manager.get_session(session_id)
        if session and candidate:
            await self.session_manager.add_ice_candidate(
                session_id=session_id,
                candidate=candidate,
                sdp_mid=sdp_mid,
                sdp_mline_index=sdp_mline_index,
            )

    async def _handle_dtmf(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Handle DTMF digit from WebRTC client (out-of-band via signaling).

        Converts to RFC 4733 telephone-event on the SIP/RTP side.
        """
        session_id = message.get("session_id", "")
        digit = message.get("digit", "")
        duration = message.get("duration", 160)  # Default 160ms

        if not session_id or not digit:
            await self._send_error(
                client, "MISSING_PARAMS", "DTMF requires 'session_id' and 'digit'"
            )
            return

        valid_dtmf = set("0123456789*#ABCD")
        if digit.upper() not in valid_dtmf:
            await self._send_error(client, "INVALID_DTMF", f"Invalid DTMF digit: {digit}")
            return

        logger.info("DTMF digit", client_id=client.client_id,
                     session_id=session_id, digit=digit)

        await self.call_router.handle_dtmf(session_id, digit.upper(), duration)

    async def _handle_hold(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Handle call hold request from WebRTC client."""
        session_id = message.get("session_id", "")
        if not session_id:
            await self._send_error(client, "MISSING_PARAMS", "Hold requires 'session_id'")
            return

        await self.call_router.handle_hold(session_id, "webrtc")
        await self._send_message(client, {"type": "held", "session_id": session_id})

    async def _handle_unhold(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Handle call unhold (resume) request from WebRTC client."""
        session_id = message.get("session_id", "")
        if not session_id:
            await self._send_error(client, "MISSING_PARAMS", "Unhold requires 'session_id'")
            return

        await self.call_router.handle_unhold(session_id, "webrtc")
        await self._send_message(client, {"type": "unheld", "session_id": session_id})

    async def _handle_disconnect(self, client: WebRTCClient) -> None:
        """Clean up when a WebRTC client disconnects."""
        logger.info("WebRTC client disconnected", client_id=client.client_id)

        # Terminate all active sessions for this client
        for session_id in list(client.active_sessions):
            try:
                await self.call_router.handle_hangup(session_id, "webrtc")
            except Exception:
                logger.exception("Error terminating session on disconnect",
                                 session_id=session_id)

        self.clients.pop(client.client_id, None)

    async def notify_client(
        self, client_id: str, message: dict[str, Any]
    ) -> None:
        """Send a notification to a specific WebRTC client.

        Used by the SIP side to send events (incoming call, ringing,
        answer, hangup) to the WebRTC client.
        """
        client = self.clients.get(client_id)
        if client:
            await self._send_message(client, message)
        else:
            logger.warning("Client not found for notification",
                           client_id=client_id, msg_type=message.get("type"))

    async def _send_message(
        self, client: WebRTCClient, message: dict[str, Any]
    ) -> None:
        """Send a JSON message to a WebRTC client."""
        try:
            await client.ws.send_json(message)
        except (ConnectionError, ConnectionResetError):
            logger.warning("Failed to send message to client",
                           client_id=client.client_id)

    async def _send_error(
        self, client: WebRTCClient, code: str, message: str
    ) -> None:
        """Send an error response to a WebRTC client."""
        await self._send_message(client, {
            "type": "error",
            "error_code": code,
            "error_message": message,
        })

    async def _ping_loop(self) -> None:
        """Periodically ping connected clients to detect stale connections."""
        while True:
            await asyncio.sleep(self.ping_interval)
            now = time.time()
            stale_clients = []

            for client_id, client in self.clients.items():
                if now - client.last_ping > self.connection_timeout:
                    stale_clients.append(client_id)
                else:
                    try:
                        await client.ws.ping()
                        client.last_ping = now
                    except (ConnectionError, ConnectionResetError):
                        stale_clients.append(client_id)

            for client_id in stale_clients:
                client = self.clients.get(client_id)
                if client:
                    logger.info("Removing stale client", client_id=client_id)
                    await self._handle_disconnect(client)
