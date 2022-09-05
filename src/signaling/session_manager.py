"""
Session Manager - Maps WebRTC sessions to SIP dialogs.

Maintains the full lifecycle of a bridged call session from initial offer
through established media to termination.  Each session tracks:
  - WebRTC client endpoint (client_id, SDP, ICE candidates)
  - SIP dialog endpoint (Call-ID, dialog-id, remote SDP)
  - Session state machine (RFC 3261 dialog states + gateway-specific states)
  - RTP relay port allocations
  - Timing metadata for CDR generation
"""

from __future__ import annotations

import asyncio
import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class SessionState(enum.Enum):
    """State machine for a bridged WebRTC-SIP session."""

    INITIATING = "initiating"       # Session created, awaiting SDP exchange
    OFFERING = "offering"           # SDP offer sent to remote side
    ANSWERING = "answering"         # SDP answer received, awaiting ACK
    RINGING = "ringing"             # Remote side is ringing (180)
    CONNECTED = "connected"         # Media established in both directions
    HOLDING = "holding"             # One side has put the call on hold
    HELD = "held"                   # Call is on hold
    UPDATING = "updating"           # Re-INVITE / session modification in progress
    TERMINATING = "terminating"     # BYE sent, waiting for confirmation
    TERMINATED = "terminated"       # Session fully torn down

    @classmethod
    def active_states(cls) -> set[SessionState]:
        """Return the set of states that represent an active session."""
        return {
            cls.INITIATING, cls.OFFERING, cls.ANSWERING,
            cls.RINGING, cls.CONNECTED, cls.HOLDING,
            cls.HELD, cls.UPDATING, cls.TERMINATING,
        }


# Valid state transitions
_VALID_TRANSITIONS: dict[SessionState, set[SessionState]] = {
    SessionState.INITIATING: {
        SessionState.OFFERING, SessionState.RINGING, SessionState.TERMINATED,
    },
    SessionState.OFFERING: {
        SessionState.ANSWERING, SessionState.RINGING, SessionState.TERMINATED,
    },
    SessionState.ANSWERING: {
        SessionState.CONNECTED, SessionState.TERMINATED,
    },
    SessionState.RINGING: {
        SessionState.ANSWERING, SessionState.CONNECTED, SessionState.TERMINATED,
    },
    SessionState.CONNECTED: {
        SessionState.HOLDING, SessionState.UPDATING,
        SessionState.TERMINATING, SessionState.TERMINATED,
    },
    SessionState.HOLDING: {
        SessionState.HELD, SessionState.TERMINATED,
    },
    SessionState.HELD: {
        SessionState.CONNECTED, SessionState.UPDATING, SessionState.TERMINATED,
    },
    SessionState.UPDATING: {
        SessionState.CONNECTED, SessionState.TERMINATED,
    },
    SessionState.TERMINATING: {
        SessionState.TERMINATED,
    },
    SessionState.TERMINATED: set(),
}


@dataclass
class ICECandidate:
    """An ICE candidate received from a WebRTC client."""

    candidate: str
    sdp_mid: str
    sdp_mline_index: int
    received_at: float = field(default_factory=time.time)


@dataclass
class Session:
    """Represents a single bridged WebRTC <-> SIP call session."""

    session_id: str
    direction: str                          # "inbound" (SIP->WebRTC) or "outbound" (WebRTC->SIP)
    state: SessionState = SessionState.INITIATING

    # WebRTC side
    client_id: str = ""
    webrtc_sdp_offer: str = ""
    webrtc_sdp_answer: str = ""
    ice_candidates: list[ICECandidate] = field(default_factory=list)

    # SIP side
    call_id: str = ""
    sip_dialog_id: str = ""
    caller_uri: str = ""
    callee_uri: str = ""
    sip_sdp_offer: str = ""
    sip_sdp_answer: str = ""

    # Media
    rtp_port_webrtc: int = 0                # RTP port facing the WebRTC side
    rtp_port_sip: int = 0                   # RTP port facing the SIP side

    # Negotiated codec
    negotiated_codec: str = ""
    negotiated_payload_type: int = 0

    # Timing (for CDR / analytics)
    created_at: float = field(default_factory=time.time)
    ringing_at: float = 0.0
    connected_at: float = 0.0
    terminated_at: float = 0.0
    termination_reason: str = ""

    # Metadata
    trunk_name: str = ""
    normalized_destination: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """Call duration in seconds (connected to terminated)."""
        if self.connected_at and self.terminated_at:
            return self.terminated_at - self.connected_at
        if self.connected_at:
            return time.time() - self.connected_at
        return 0.0

    @property
    def setup_time(self) -> float:
        """Call setup time in seconds (created to connected)."""
        if self.connected_at:
            return self.connected_at - self.created_at
        return 0.0

    @property
    def info(self) -> dict[str, Any]:
        """Return session metadata suitable for API responses."""
        return {
            "session_id": self.session_id,
            "direction": self.direction,
            "state": self.state.value,
            "caller_uri": self.caller_uri,
            "callee_uri": self.callee_uri,
            "call_id": self.call_id,
            "trunk_name": self.trunk_name,
            "negotiated_codec": self.negotiated_codec,
            "duration": round(self.duration, 2),
            "setup_time": round(self.setup_time, 2),
            "created_at": self.created_at,
            "connected_at": self.connected_at,
            "terminated_at": self.terminated_at,
            "termination_reason": self.termination_reason,
        }


class SessionManager:
    """Manages the lifecycle of bridged WebRTC-SIP call sessions.

    Thread-safe session creation, state transitions, and cleanup.
    Provides lookup by session_id, call_id, and client_id.
    """

    def __init__(
        self,
        max_sessions: int = 200,
        setup_timeout: float = 30.0,
        idle_timeout: float = 3600.0,
    ) -> None:
        self.max_sessions = max_sessions
        self.setup_timeout = setup_timeout
        self.idle_timeout = idle_timeout

        self._sessions: dict[str, Session] = {}
        self._call_id_index: dict[str, str] = {}   # call_id -> session_id
        self._client_index: dict[str, list[str]] = {}  # client_id -> [session_ids]
        self._lock = asyncio.Lock()

    @property
    def active_count(self) -> int:
        """Number of active (non-terminated) sessions."""
        return sum(
            1 for s in self._sessions.values()
            if s.state in SessionState.active_states()
        )

    @property
    def total_count(self) -> int:
        """Total sessions including terminated."""
        return len(self._sessions)

    async def create_session(
        self,
        direction: str,
        caller_uri: str = "",
        callee_uri: str = "",
        call_id: str = "",
        client_id: str = "",
    ) -> str:
        """Create a new bridged session.

        Args:
            direction:  "inbound" or "outbound"
            caller_uri: SIP URI of the caller
            callee_uri: SIP URI of the callee
            call_id:    SIP Call-ID (may be empty for outbound before INVITE)
            client_id:  WebRTC client identifier

        Returns:
            The session_id of the newly created session.

        Raises:
            RuntimeError: If the maximum session limit has been reached.
        """
        async with self._lock:
            if self.active_count >= self.max_sessions:
                raise RuntimeError(
                    f"Maximum concurrent sessions reached ({self.max_sessions})"
                )

            session_id = str(uuid.uuid4())
            session = Session(
                session_id=session_id,
                direction=direction,
                caller_uri=caller_uri,
                callee_uri=callee_uri,
                call_id=call_id,
                client_id=client_id,
            )

            self._sessions[session_id] = session

            if call_id:
                self._call_id_index[call_id] = session_id

            if client_id:
                self._client_index.setdefault(client_id, []).append(session_id)

            logger.info(
                "Session created",
                session_id=session_id,
                direction=direction,
                caller=caller_uri,
                callee=callee_uri,
            )
            return session_id

    async def update_state(
        self, session_id: str, new_state: SessionState
    ) -> None:
        """Transition a session to a new state with validation.

        Args:
            session_id: Target session.
            new_state:  Desired new state.

        Raises:
            ValueError: If the transition is not permitted.
            KeyError:   If the session does not exist.
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"Session not found: {session_id}")

        old_state = session.state

        if new_state not in _VALID_TRANSITIONS.get(old_state, set()):
            # Allow forcing to TERMINATED from any state
            if new_state != SessionState.TERMINATED:
                raise ValueError(
                    f"Invalid state transition: {old_state.value} -> {new_state.value}"
                )

        session.state = new_state

        # Update timestamps
        if new_state == SessionState.RINGING:
            session.ringing_at = time.time()
        elif new_state == SessionState.CONNECTED:
            session.connected_at = time.time()
        elif new_state == SessionState.TERMINATED:
            session.terminated_at = time.time()

        logger.info(
            "Session state changed",
            session_id=session_id,
            old_state=old_state.value,
            new_state=new_state.value,
        )

    def get_session(self, session_id: str) -> Session | None:
        """Retrieve a session by its ID."""
        return self._sessions.get(session_id)

    def find_by_call_id(self, call_id: str) -> str | None:
        """Find a session_id by its SIP Call-ID."""
        return self._call_id_index.get(call_id)

    def find_by_client(self, client_id: str) -> list[Session]:
        """Find all sessions for a given WebRTC client."""
        session_ids = self._client_index.get(client_id, [])
        return [
            self._sessions[sid]
            for sid in session_ids
            if sid in self._sessions
        ]

    def get_all_sessions(self) -> list[Session]:
        """Return all sessions (active and terminated)."""
        return list(self._sessions.values())

    def get_active_sessions(self) -> list[Session]:
        """Return only active (non-terminated) sessions."""
        return [
            s for s in self._sessions.values()
            if s.state in SessionState.active_states()
        ]

    async def set_call_id(self, session_id: str, call_id: str) -> None:
        """Associate a SIP Call-ID with an existing session."""
        session = self._sessions.get(session_id)
        if session:
            session.call_id = call_id
            self._call_id_index[call_id] = session_id

    async def set_local_sdp(self, session_id: str, sdp: str) -> None:
        """Store the local SDP (offer or answer depending on direction)."""
        session = self._sessions.get(session_id)
        if session:
            if session.direction == "outbound":
                session.webrtc_sdp_offer = sdp
            else:
                session.sip_sdp_offer = sdp

    async def set_remote_sdp(self, session_id: str, sdp: str) -> None:
        """Store the remote SDP (answer or offer depending on direction)."""
        session = self._sessions.get(session_id)
        if session:
            if session.direction == "outbound":
                session.sip_sdp_answer = sdp
            else:
                session.webrtc_sdp_answer = sdp

    async def set_rtp_ports(
        self, session_id: str, webrtc_port: int, sip_port: int
    ) -> None:
        """Store the allocated RTP relay ports for a session."""
        session = self._sessions.get(session_id)
        if session:
            session.rtp_port_webrtc = webrtc_port
            session.rtp_port_sip = sip_port

    async def add_ice_candidate(
        self,
        session_id: str,
        candidate: str,
        sdp_mid: str = "",
        sdp_mline_index: int = 0,
    ) -> None:
        """Add an ICE candidate received from the WebRTC client."""
        session = self._sessions.get(session_id)
        if session:
            ice = ICECandidate(
                candidate=candidate,
                sdp_mid=sdp_mid,
                sdp_mline_index=sdp_mline_index,
            )
            session.ice_candidates.append(ice)
            logger.debug(
                "ICE candidate added",
                session_id=session_id,
                candidate=candidate[:60],
            )

    async def terminate_session(
        self, session_id: str, reason: str = "normal"
    ) -> None:
        """Terminate a session and record the reason."""
        session = self._sessions.get(session_id)
        if session and session.state != SessionState.TERMINATED:
            session.termination_reason = reason
            await self.update_state(session_id, SessionState.TERMINATED)

    async def terminate_all(self) -> None:
        """Terminate all active sessions (used during shutdown)."""
        for session in self.get_active_sessions():
            await self.terminate_session(
                session.session_id, reason="gateway_shutdown"
            )
        logger.info("All sessions terminated", count=len(self._sessions))

    async def cleanup_loop(self) -> None:
        """Background task to clean up stale and timed-out sessions.

        Runs continuously, checking every 10 seconds for:
          - Sessions stuck in INITIATING/OFFERING beyond setup_timeout
          - Connected sessions idle beyond idle_timeout
          - Terminated sessions older than 5 minutes (housekeeping)
        """
        try:
            while True:
                await asyncio.sleep(10)
                now = time.time()
                stale_ids: list[str] = []

                for sid, session in list(self._sessions.items()):
                    # Setup timeout
                    if (
                        session.state
                        in {SessionState.INITIATING, SessionState.OFFERING, SessionState.RINGING}
                        and (now - session.created_at) > self.setup_timeout
                    ):
                        logger.warning("Session setup timeout", session_id=sid)
                        await self.terminate_session(sid, "setup_timeout")

                    # Idle timeout for connected sessions
                    elif (
                        session.state == SessionState.CONNECTED
                        and (now - session.connected_at) > self.idle_timeout
                    ):
                        logger.warning("Session idle timeout", session_id=sid)
                        await self.terminate_session(sid, "idle_timeout")

                    # Housekeeping: remove terminated sessions after 5 minutes
                    elif (
                        session.state == SessionState.TERMINATED
                        and session.terminated_at
                        and (now - session.terminated_at) > 300
                    ):
                        stale_ids.append(sid)

                # Remove stale terminated sessions from memory
                for sid in stale_ids:
                    session = self._sessions.pop(sid, None)
                    if session:
                        self._call_id_index.pop(session.call_id, None)
                        client_list = self._client_index.get(session.client_id, [])
                        if sid in client_list:
                            client_list.remove(sid)

                if stale_ids:
                    logger.debug("Cleaned up stale sessions", count=len(stale_ids))

        except asyncio.CancelledError:
            logger.debug("Session cleanup loop cancelled")
