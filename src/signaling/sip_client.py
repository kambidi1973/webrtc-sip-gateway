"""
SIP User Agent Client

Implements a SIP User Agent (UAC/UAS) for communicating with SIP infrastructure.
Handles core SIP methods:
  - REGISTER: Register WebRTC users with SIP registrars
  - INVITE:   Initiate and receive calls with SDP offer/answer
  - ACK:      Confirm final responses to INVITE
  - BYE:      Terminate established sessions
  - CANCEL:   Cancel pending INVITE transactions
  - OPTIONS:  Keepalive and capability queries

Implements SIP digest authentication (RFC 2617), proper Via/Contact header
management, and dialog state tracking per RFC 3261.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog

from src.media.rtp_relay import RTPRelay
from src.sdp.translator import SDPTranslator
from src.signaling.session_manager import SessionManager, SessionState

logger = structlog.get_logger(__name__)


@dataclass
class SIPTransaction:
    """Tracks a SIP transaction (request + responses)."""

    transaction_id: str
    method: str
    branch: str
    call_id: str
    from_tag: str
    to_tag: str = ""
    cseq: int = 1
    state: str = "trying"  # trying, proceeding, completed, terminated
    created_at: float = field(default_factory=time.time)
    request: str = ""
    last_response_code: int = 0
    retransmit_task: asyncio.Task[None] | None = None


@dataclass
class SIPDialog:
    """Represents an established SIP dialog (RFC 3261 Section 12)."""

    dialog_id: str
    call_id: str
    local_tag: str
    remote_tag: str
    local_uri: str
    remote_uri: str
    remote_target: str  # Contact URI from the remote party
    local_cseq: int = 1
    remote_cseq: int = 0
    route_set: list[str] = field(default_factory=list)
    state: str = "early"  # early, confirmed, terminated
    session_id: str = ""  # Link to SessionManager session


class SIPClient:
    """SIP User Agent for gateway-to-SIP-network communication.

    Manages SIP signaling over UDP transport, including transaction
    tracking, dialog management, and digest authentication.
    """

    def __init__(
        self,
        config: dict[str, Any],
        public_ip: str,
        session_manager: SessionManager,
        rtp_relay: RTPRelay,
    ) -> None:
        self.listen_host = config.get("listen_host", "0.0.0.0")
        self.listen_port = config.get("listen_port", 5060)
        self.transport = config.get("transport", "udp")
        self.domain = config.get("domain", "gateway.local")
        self.user_agent = config.get("user_agent", "WebRTC-SIP-Gateway/1.0")
        self.public_ip = public_ip

        # SIP timers per RFC 3261
        timers = config.get("timers", {})
        self.timer_t1 = timers.get("t1", 0.5)
        self.timer_t2 = timers.get("t2", 4.0)
        self.timer_b = timers.get("timer_b", 32.0)

        self.session_manager = session_manager
        self.rtp_relay = rtp_relay
        self.sdp_translator = SDPTranslator()

        # State tracking
        self.transactions: dict[str, SIPTransaction] = {}
        self.dialogs: dict[str, SIPDialog] = {}
        self._transport_handle: asyncio.DatagramTransport | None = None
        self._protocol: SIPProtocol | None = None
        self._cseq_counter: int = 1

        # Authentication nonce cache (realm -> {nonce, username, password})
        self._auth_cache: dict[str, dict[str, str]] = {}

    async def start(self) -> None:
        """Start the SIP transport (UDP socket)."""
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SIPProtocol(self),
            local_addr=(self.listen_host, self.listen_port),
        )
        self._transport_handle = transport
        self._protocol = protocol
        logger.info("SIP client started",
                     host=self.listen_host, port=self.listen_port,
                     transport=self.transport)

    async def stop(self) -> None:
        """Stop the SIP transport and clean up transactions."""
        # Cancel all pending retransmissions
        for txn in self.transactions.values():
            if txn.retransmit_task:
                txn.retransmit_task.cancel()

        if self._transport_handle:
            self._transport_handle.close()

        logger.info("SIP client stopped")

    # -------------------------------------------------------------------------
    # SIP Message Construction
    # -------------------------------------------------------------------------

    def _generate_branch(self) -> str:
        """Generate a unique branch parameter (RFC 3261 magic cookie + random)."""
        return f"z9hG4bK-{uuid.uuid4().hex[:16]}"

    def _generate_tag(self) -> str:
        """Generate a random tag for From/To headers."""
        return uuid.uuid4().hex[:8]

    def _generate_call_id(self) -> str:
        """Generate a globally unique Call-ID."""
        return f"{uuid.uuid4().hex}@{self.public_ip}"

    def _next_cseq(self) -> int:
        """Get the next CSeq number."""
        self._cseq_counter += 1
        return self._cseq_counter

    def _build_via(self, branch: str) -> str:
        """Build Via header with public IP and branch parameter."""
        return (
            f"SIP/2.0/UDP {self.public_ip}:{self.listen_port}"
            f";branch={branch};rport"
        )

    def _build_contact(self, user: str = "gateway") -> str:
        """Build Contact header with public IP."""
        return f"<sip:{user}@{self.public_ip}:{self.listen_port};transport={self.transport}>"

    def build_request(
        self,
        method: str,
        request_uri: str,
        call_id: str,
        from_uri: str,
        to_uri: str,
        from_tag: str,
        to_tag: str = "",
        cseq: int | None = None,
        body: str = "",
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[str, str]:
        """Construct a SIP request message.

        Returns:
            Tuple of (branch_id, complete_sip_message).
        """
        branch = self._generate_branch()
        if cseq is None:
            cseq = self._next_cseq()

        to_header = f"<{to_uri}>"
        if to_tag:
            to_header += f";tag={to_tag}"

        headers = [
            f"{method} {request_uri} SIP/2.0",
            f"Via: {self._build_via(branch)}",
            f"Max-Forwards: 70",
            f"From: <{from_uri}>;tag={from_tag}",
            f"To: {to_header}",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq} {method}",
            f"Contact: {self._build_contact()}",
            f"User-Agent: {self.user_agent}",
            f"Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, INFO, UPDATE",
            f"Supported: timer, 100rel",
        ]

        if extra_headers:
            for name, value in extra_headers.items():
                headers.append(f"{name}: {value}")

        if body:
            headers.append(f"Content-Type: application/sdp")
            headers.append(f"Content-Length: {len(body)}")
        else:
            headers.append("Content-Length: 0")

        message = "\r\n".join(headers) + "\r\n\r\n"
        if body:
            message += body

        return branch, message

    def build_response(
        self,
        status_code: int,
        reason: str,
        request_headers: dict[str, str],
        body: str = "",
        extra_headers: dict[str, str] | None = None,
    ) -> str:
        """Build a SIP response message from the original request headers."""
        headers = [
            f"SIP/2.0 {status_code} {reason}",
            f"Via: {request_headers.get('Via', '')}",
            f"From: {request_headers.get('From', '')}",
            f"To: {request_headers.get('To', '')}",
            f"Call-ID: {request_headers.get('Call-ID', '')}",
            f"CSeq: {request_headers.get('CSeq', '')}",
            f"Contact: {self._build_contact()}",
            f"User-Agent: {self.user_agent}",
        ]

        if extra_headers:
            for name, value in extra_headers.items():
                headers.append(f"{name}: {value}")

        if body:
            headers.append("Content-Type: application/sdp")
            headers.append(f"Content-Length: {len(body)}")
        else:
            headers.append("Content-Length: 0")

        message = "\r\n".join(headers) + "\r\n\r\n"
        if body:
            message += body

        return message

    # -------------------------------------------------------------------------
    # SIP Method Implementations
    # -------------------------------------------------------------------------

    async def send_invite(
        self,
        from_uri: str,
        to_uri: str,
        sdp_body: str,
        trunk_host: str,
        trunk_port: int = 5060,
    ) -> dict[str, Any]:
        """Send a SIP INVITE to initiate a call.

        Args:
            from_uri:   Caller's SIP URI
            to_uri:     Callee's SIP URI (request URI)
            sdp_body:   SDP offer (already translated from WebRTC format)
            trunk_host: SIP trunk host to send INVITE to
            trunk_port: SIP trunk port

        Returns:
            Dict with call_id, from_tag, branch for tracking.
        """
        call_id = self._generate_call_id()
        from_tag = self._generate_tag()
        cseq = self._next_cseq()

        branch, message = self.build_request(
            method="INVITE",
            request_uri=to_uri,
            call_id=call_id,
            from_uri=from_uri,
            to_uri=to_uri,
            from_tag=from_tag,
            cseq=cseq,
            body=sdp_body,
        )

        # Create transaction
        txn = SIPTransaction(
            transaction_id=branch,
            method="INVITE",
            branch=branch,
            call_id=call_id,
            from_tag=from_tag,
            cseq=cseq,
            request=message,
        )
        self.transactions[branch] = txn

        # Send the INVITE
        self._send_raw(message, (trunk_host, trunk_port))

        # Start INVITE retransmission timer (Timer A per RFC 3261 17.1.1.2)
        txn.retransmit_task = asyncio.create_task(
            self._invite_retransmit(txn, (trunk_host, trunk_port))
        )

        logger.info("INVITE sent",
                     call_id=call_id, from_uri=from_uri,
                     to_uri=to_uri, trunk=trunk_host)

        return {
            "call_id": call_id,
            "from_tag": from_tag,
            "branch": branch,
            "cseq": cseq,
        }

    async def send_bye(self, dialog: SIPDialog) -> None:
        """Send a BYE to terminate an established dialog."""
        cseq = self._next_cseq()
        dialog.local_cseq = cseq

        branch, message = self.build_request(
            method="BYE",
            request_uri=dialog.remote_target,
            call_id=dialog.call_id,
            from_uri=dialog.local_uri,
            to_uri=dialog.remote_uri,
            from_tag=dialog.local_tag,
            to_tag=dialog.remote_tag,
            cseq=cseq,
        )

        # Extract host/port from remote target
        target_host, target_port = self._parse_uri_host_port(dialog.remote_target)
        self._send_raw(message, (target_host, target_port))

        dialog.state = "terminated"
        logger.info("BYE sent", call_id=dialog.call_id, target=dialog.remote_target)

    async def send_register(
        self,
        registrar: str,
        registrar_port: int,
        username: str,
        domain: str,
        expires: int = 3600,
        auth_header: str | None = None,
    ) -> dict[str, Any]:
        """Send a SIP REGISTER request.

        Args:
            registrar:      Registrar hostname/IP
            registrar_port: Registrar port
            username:       SIP username
            domain:         SIP domain
            expires:        Registration expiry in seconds
            auth_header:    Pre-computed Authorization header (for re-REGISTER)

        Returns:
            Dict with transaction tracking info.
        """
        call_id = self._generate_call_id()
        from_tag = self._generate_tag()
        from_uri = f"sip:{username}@{domain}"
        request_uri = f"sip:{domain}"
        cseq = self._next_cseq()

        extra_headers: dict[str, str] = {"Expires": str(expires)}
        if auth_header:
            extra_headers["Authorization"] = auth_header

        branch, message = self.build_request(
            method="REGISTER",
            request_uri=request_uri,
            call_id=call_id,
            from_uri=from_uri,
            to_uri=from_uri,
            from_tag=from_tag,
            cseq=cseq,
            extra_headers=extra_headers,
        )

        txn = SIPTransaction(
            transaction_id=branch,
            method="REGISTER",
            branch=branch,
            call_id=call_id,
            from_tag=from_tag,
            cseq=cseq,
            request=message,
        )
        self.transactions[branch] = txn

        self._send_raw(message, (registrar, registrar_port))

        logger.info("REGISTER sent",
                     username=username, domain=domain,
                     registrar=registrar, expires=expires)

        return {
            "call_id": call_id,
            "from_tag": from_tag,
            "branch": branch,
            "cseq": cseq,
        }

    async def send_options(
        self, target_host: str, target_port: int = 5060
    ) -> None:
        """Send a SIP OPTIONS for keepalive/capability query."""
        call_id = self._generate_call_id()
        from_tag = self._generate_tag()
        from_uri = f"sip:gateway@{self.public_ip}"
        to_uri = f"sip:{target_host}"

        branch, message = self.build_request(
            method="OPTIONS",
            request_uri=to_uri,
            call_id=call_id,
            from_uri=from_uri,
            to_uri=to_uri,
            from_tag=from_tag,
        )

        self._send_raw(message, (target_host, target_port))

    async def send_cancel(self, txn: SIPTransaction, target: tuple[str, int]) -> None:
        """Send a CANCEL for a pending INVITE transaction."""
        branch, message = self.build_request(
            method="CANCEL",
            request_uri="",  # Same as original INVITE
            call_id=txn.call_id,
            from_uri="",
            to_uri="",
            from_tag=txn.from_tag,
            cseq=txn.cseq,
        )

        self._send_raw(message, target)
        txn.state = "terminated"

        if txn.retransmit_task:
            txn.retransmit_task.cancel()

        logger.info("CANCEL sent", call_id=txn.call_id)

    # -------------------------------------------------------------------------
    # SIP Authentication (Digest)
    # -------------------------------------------------------------------------

    def compute_digest_response(
        self,
        username: str,
        password: str,
        realm: str,
        nonce: str,
        method: str,
        uri: str,
        algorithm: str = "MD5",
        qop: str = "",
        nc: str = "00000001",
        cnonce: str | None = None,
    ) -> str:
        """Compute SIP Digest authentication response per RFC 2617.

        Args:
            username: SIP authentication username
            password: SIP authentication password
            realm:    Authentication realm from WWW-Authenticate
            nonce:    Server nonce from WWW-Authenticate
            method:   SIP method (REGISTER, INVITE, etc.)
            uri:      Request URI
            algorithm: Hash algorithm (MD5 or MD5-sess)
            qop:      Quality of protection
            nc:       Nonce count (hex)
            cnonce:   Client nonce

        Returns:
            Complete Authorization header value.
        """
        if cnonce is None:
            cnonce = uuid.uuid4().hex[:16]

        def _h(data: str) -> str:
            return hashlib.md5(data.encode()).hexdigest()

        # HA1 = H(username:realm:password)
        ha1 = _h(f"{username}:{realm}:{password}")
        if algorithm.upper() == "MD5-SESS":
            ha1 = _h(f"{ha1}:{nonce}:{cnonce}")

        # HA2 = H(method:uri)
        ha2 = _h(f"{method}:{uri}")

        # Response
        if qop in ("auth", "auth-int"):
            response = _h(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        else:
            response = _h(f"{ha1}:{nonce}:{ha2}")

        # Build Authorization header value
        auth_parts = [
            f'Digest username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
            f'response="{response}"',
            f'algorithm={algorithm}',
        ]
        if qop:
            auth_parts.extend([
                f'qop={qop}',
                f'nc={nc}',
                f'cnonce="{cnonce}"',
            ])

        return ", ".join(auth_parts)

    # -------------------------------------------------------------------------
    # Incoming SIP Message Handling
    # -------------------------------------------------------------------------

    async def handle_received_message(
        self, data: bytes, addr: tuple[str, int]
    ) -> None:
        """Process an incoming SIP message from the network."""
        try:
            message = data.decode("utf-8", errors="replace")
        except Exception:
            logger.error("Failed to decode SIP message", remote=addr)
            return

        lines = message.split("\r\n")
        if not lines:
            return

        first_line = lines[0].strip()

        if first_line.startswith("SIP/2.0"):
            # This is a response
            await self._handle_response(message, first_line, addr)
        else:
            # This is a request
            await self._handle_request(message, first_line, addr)

    async def _handle_response(
        self, message: str, status_line: str, addr: tuple[str, int]
    ) -> None:
        """Handle an incoming SIP response."""
        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            return

        try:
            status_code = int(parts[1])
        except ValueError:
            return

        reason = parts[2] if len(parts) > 2 else ""
        headers = self._parse_headers(message)
        via = headers.get("Via", "")
        cseq_header = headers.get("CSeq", "")
        call_id = headers.get("Call-ID", "")

        # Extract branch from Via to find transaction
        branch = self._extract_branch(via)
        txn = self.transactions.get(branch)

        log = logger.bind(status_code=status_code, reason=reason,
                          call_id=call_id, branch=branch)

        if not txn:
            log.warning("Response for unknown transaction")
            return

        txn.last_response_code = status_code

        cseq_parts = cseq_header.split()
        method = cseq_parts[1] if len(cseq_parts) > 1 else txn.method

        if method == "REGISTER":
            await self._handle_register_response(txn, status_code, headers, addr)
        elif method == "INVITE":
            await self._handle_invite_response(txn, status_code, headers, message, addr)
        elif method == "BYE":
            txn.state = "terminated"
            log.info("BYE response received")
        elif method == "OPTIONS":
            txn.state = "terminated"

    async def _handle_register_response(
        self,
        txn: SIPTransaction,
        status_code: int,
        headers: dict[str, str],
        addr: tuple[str, int],
    ) -> None:
        """Process response to a REGISTER request."""
        if status_code == 200:
            txn.state = "completed"
            expires = headers.get("Expires", "3600")
            logger.info("Registration successful",
                        call_id=txn.call_id, expires=expires)
        elif status_code == 401:
            # Authentication required - extract challenge
            www_auth = headers.get("WWW-Authenticate", "")
            logger.info("Registration requires authentication",
                        call_id=txn.call_id)
            # The RegistrationManager will handle re-registration with auth
            txn.state = "completed"
        elif status_code == 407:
            proxy_auth = headers.get("Proxy-Authenticate", "")
            logger.info("Proxy authentication required", call_id=txn.call_id)
            txn.state = "completed"
        else:
            logger.warning("Registration failed",
                           call_id=txn.call_id, status=status_code)
            txn.state = "terminated"

    async def _handle_invite_response(
        self,
        txn: SIPTransaction,
        status_code: int,
        headers: dict[str, str],
        message: str,
        addr: tuple[str, int],
    ) -> None:
        """Process response to an INVITE request."""
        log = logger.bind(call_id=txn.call_id, status=status_code)

        if status_code == 100:
            # Trying - stop retransmissions
            txn.state = "proceeding"
            if txn.retransmit_task:
                txn.retransmit_task.cancel()
                txn.retransmit_task = None
            log.info("INVITE 100 Trying")

        elif status_code == 180 or status_code == 183:
            # Ringing or Session Progress
            txn.state = "proceeding"
            to_tag = self._extract_tag(headers.get("To", ""))
            txn.to_tag = to_tag

            # Update session state
            session = self._find_session_by_call_id(txn.call_id)
            if session:
                await self.session_manager.update_state(
                    session, SessionState.RINGING
                )
            log.info("INVITE ringing", status=status_code)

        elif status_code == 200:
            # OK - call answered
            txn.state = "completed"
            if txn.retransmit_task:
                txn.retransmit_task.cancel()
                txn.retransmit_task = None

            to_tag = self._extract_tag(headers.get("To", ""))
            txn.to_tag = to_tag

            # Create dialog
            contact = headers.get("Contact", "")
            remote_target = self._extract_uri_from_header(contact)
            dialog = SIPDialog(
                dialog_id=f"{txn.call_id}:{txn.from_tag}:{to_tag}",
                call_id=txn.call_id,
                local_tag=txn.from_tag,
                remote_tag=to_tag,
                local_uri=self._extract_uri_from_header(headers.get("From", "")),
                remote_uri=self._extract_uri_from_header(headers.get("To", "")),
                remote_target=remote_target or f"sip:{addr[0]}:{addr[1]}",
                local_cseq=txn.cseq,
                state="confirmed",
            )
            self.dialogs[dialog.dialog_id] = dialog

            # Send ACK
            await self._send_ack(txn, dialog, addr)

            # Extract SDP answer and update session
            sdp_body = self._extract_body(message)
            session = self._find_session_by_call_id(txn.call_id)
            if session:
                dialog.session_id = session
                await self.session_manager.update_state(
                    session, SessionState.CONNECTED
                )
                # Translate SIP SDP answer to WebRTC format
                if sdp_body:
                    webrtc_sdp = self.sdp_translator.sip_to_webrtc(sdp_body)
                    await self.session_manager.set_remote_sdp(session, webrtc_sdp)

            log.info("INVITE 200 OK - dialog established",
                     dialog_id=dialog.dialog_id)

        elif status_code == 401 or status_code == 407:
            # Authentication challenge
            txn.state = "completed"
            log.info("INVITE authentication required")

        elif status_code >= 300:
            # Error response
            txn.state = "terminated"
            if txn.retransmit_task:
                txn.retransmit_task.cancel()
                txn.retransmit_task = None

            session = self._find_session_by_call_id(txn.call_id)
            if session:
                await self.session_manager.update_state(
                    session, SessionState.TERMINATED
                )

            log.warning("INVITE rejected", status=status_code)

    async def _handle_request(
        self, message: str, request_line: str, addr: tuple[str, int]
    ) -> None:
        """Handle an incoming SIP request."""
        parts = request_line.split()
        if len(parts) < 3:
            return

        method = parts[0]
        request_uri = parts[1]
        headers = self._parse_headers(message)

        log = logger.bind(method=method, call_id=headers.get("Call-ID", ""),
                          remote=f"{addr[0]}:{addr[1]}")

        if method == "INVITE":
            await self._handle_incoming_invite(headers, message, addr)
        elif method == "BYE":
            await self._handle_incoming_bye(headers, addr)
        elif method == "ACK":
            log.debug("ACK received")
        elif method == "CANCEL":
            await self._handle_incoming_cancel(headers, addr)
        elif method == "OPTIONS":
            await self._handle_incoming_options(headers, addr)
        elif method == "INFO":
            await self._handle_incoming_info(headers, message, addr)
        else:
            # Method not allowed
            response = self.build_response(405, "Method Not Allowed", headers)
            self._send_raw(response, addr)
            log.warning("Unsupported SIP method")

    async def _handle_incoming_invite(
        self,
        headers: dict[str, str],
        message: str,
        addr: tuple[str, int],
    ) -> None:
        """Handle an incoming INVITE (SIP -> WebRTC direction)."""
        call_id = headers.get("Call-ID", "")
        from_uri = self._extract_uri_from_header(headers.get("From", ""))
        to_uri = self._extract_uri_from_header(headers.get("To", ""))
        sdp_body = self._extract_body(message)

        logger.info("Incoming INVITE", call_id=call_id,
                     from_uri=from_uri, to_uri=to_uri)

        # Send 100 Trying immediately
        trying_resp = self.build_response(100, "Trying", headers)
        self._send_raw(trying_resp, addr)

        # Send 180 Ringing
        to_tag = self._generate_tag()
        headers_with_tag = dict(headers)
        to_val = headers.get("To", "")
        if ";tag=" not in to_val:
            headers_with_tag["To"] = f"{to_val};tag={to_tag}"
        ringing_resp = self.build_response(180, "Ringing", headers_with_tag)
        self._send_raw(ringing_resp, addr)

        # Create session for this inbound call
        session_id = await self.session_manager.create_session(
            direction="inbound",
            caller_uri=from_uri,
            callee_uri=to_uri,
            call_id=call_id,
        )

        # Translate SDP for WebRTC client
        if sdp_body:
            webrtc_sdp = self.sdp_translator.sip_to_webrtc(sdp_body)
            await self.session_manager.set_remote_sdp(session_id, webrtc_sdp)

        logger.info("Inbound call session created",
                     session_id=session_id, call_id=call_id)

    async def _handle_incoming_bye(
        self,
        headers: dict[str, str],
        addr: tuple[str, int],
    ) -> None:
        """Handle an incoming BYE request."""
        call_id = headers.get("Call-ID", "")

        # Send 200 OK for BYE
        response = self.build_response(200, "OK", headers)
        self._send_raw(response, addr)

        # Find and terminate the dialog
        for dialog_id, dialog in list(self.dialogs.items()):
            if dialog.call_id == call_id:
                dialog.state = "terminated"
                if dialog.session_id:
                    await self.session_manager.update_state(
                        dialog.session_id, SessionState.TERMINATED
                    )
                del self.dialogs[dialog_id]
                break

        logger.info("BYE received, session terminated", call_id=call_id)

    async def _handle_incoming_cancel(
        self,
        headers: dict[str, str],
        addr: tuple[str, int],
    ) -> None:
        """Handle an incoming CANCEL request."""
        call_id = headers.get("Call-ID", "")

        # Send 200 OK for CANCEL
        response = self.build_response(200, "OK", headers)
        self._send_raw(response, addr)

        # Then send 487 Request Terminated for the original INVITE
        logger.info("CANCEL received", call_id=call_id)

    async def _handle_incoming_options(
        self,
        headers: dict[str, str],
        addr: tuple[str, int],
    ) -> None:
        """Handle OPTIONS request (keepalive/capability query)."""
        extra = {
            "Allow": "INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, INFO, UPDATE",
            "Accept": "application/sdp",
        }
        response = self.build_response(200, "OK", headers, extra_headers=extra)
        self._send_raw(response, addr)

    async def _handle_incoming_info(
        self,
        headers: dict[str, str],
        message: str,
        addr: tuple[str, int],
    ) -> None:
        """Handle INFO request (e.g., SIP INFO DTMF)."""
        response = self.build_response(200, "OK", headers)
        self._send_raw(response, addr)

        # Check for DTMF in INFO body
        body = self._extract_body(message)
        if body and "Signal=" in body:
            # Parse DTMF signal from SIP INFO
            for line in body.split("\n"):
                if line.startswith("Signal="):
                    digit = line.split("=")[1].strip()
                    logger.info("DTMF via SIP INFO", digit=digit)

    async def _send_ack(
        self,
        txn: SIPTransaction,
        dialog: SIPDialog,
        addr: tuple[str, int],
    ) -> None:
        """Send ACK for a 200 OK to INVITE."""
        branch, message = self.build_request(
            method="ACK",
            request_uri=dialog.remote_target,
            call_id=dialog.call_id,
            from_uri=dialog.local_uri,
            to_uri=dialog.remote_uri,
            from_tag=dialog.local_tag,
            to_tag=dialog.remote_tag,
            cseq=txn.cseq,
        )
        self._send_raw(message, addr)

    # -------------------------------------------------------------------------
    # Retransmission (RFC 3261 Section 17.1.1.2)
    # -------------------------------------------------------------------------

    async def _invite_retransmit(
        self, txn: SIPTransaction, addr: tuple[str, int]
    ) -> None:
        """INVITE retransmission with exponential backoff (Timer A)."""
        interval = self.timer_t1
        elapsed = 0.0

        while txn.state == "trying" and elapsed < self.timer_b:
            await asyncio.sleep(interval)
            elapsed += interval

            if txn.state != "trying":
                break

            self._send_raw(txn.request, addr)
            logger.debug("INVITE retransmit", call_id=txn.call_id,
                         interval=interval)
            interval = min(interval * 2, self.timer_t2)

        if txn.state == "trying":
            txn.state = "terminated"
            logger.warning("INVITE transaction timed out", call_id=txn.call_id)

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def _send_raw(self, message: str, addr: tuple[str, int]) -> None:
        """Send raw SIP message bytes to a network address."""
        if self._transport_handle:
            self._transport_handle.sendto(message.encode("utf-8"), addr)

    def _parse_headers(self, message: str) -> dict[str, str]:
        """Parse SIP message headers into a dictionary."""
        headers: dict[str, str] = {}
        header_section = message.split("\r\n\r\n")[0]
        lines = header_section.split("\r\n")

        for line in lines[1:]:  # Skip request/status line
            if ":" in line:
                name, _, value = line.partition(":")
                headers[name.strip()] = value.strip()

        return headers

    def _extract_branch(self, via: str) -> str:
        """Extract branch parameter from Via header."""
        for part in via.split(";"):
            part = part.strip()
            if part.startswith("branch="):
                return part.split("=", 1)[1]
        return ""

    def _extract_tag(self, header: str) -> str:
        """Extract tag parameter from From/To header."""
        for part in header.split(";"):
            part = part.strip()
            if part.startswith("tag="):
                return part.split("=", 1)[1]
        return ""

    def _extract_uri_from_header(self, header: str) -> str:
        """Extract SIP URI from a header value (between < and >)."""
        start = header.find("<")
        end = header.find(">")
        if start >= 0 and end > start:
            return header[start + 1:end]
        return header.strip()

    def _extract_body(self, message: str) -> str:
        """Extract message body from a SIP message."""
        parts = message.split("\r\n\r\n", 1)
        return parts[1] if len(parts) > 1 else ""

    def _parse_uri_host_port(self, uri: str) -> tuple[str, int]:
        """Extract host and port from a SIP URI."""
        # sip:user@host:port;params
        uri = uri.replace("sip:", "").replace("sips:", "")
        if "@" in uri:
            uri = uri.split("@")[1]
        # Remove parameters
        uri = uri.split(";")[0]
        if ":" in uri:
            host, port_str = uri.split(":", 1)
            try:
                return host, int(port_str)
            except ValueError:
                return host, 5060
        return uri, 5060

    def _find_session_by_call_id(self, call_id: str) -> str | None:
        """Find a session ID by its SIP Call-ID."""
        return self.session_manager.find_by_call_id(call_id)

    def get_dialog_by_session(self, session_id: str) -> SIPDialog | None:
        """Find a SIP dialog by its linked session ID."""
        for dialog in self.dialogs.values():
            if dialog.session_id == session_id:
                return dialog
        return None


class SIPProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol handler for SIP message transport."""

    def __init__(self, sip_client: SIPClient) -> None:
        self.sip_client = sip_client
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.create_task(
            self.sip_client.handle_received_message(data, addr)
        )

    def error_received(self, exc: Exception) -> None:
        logger.error("SIP transport error", error=str(exc))

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.error("SIP transport connection lost", error=str(exc))
