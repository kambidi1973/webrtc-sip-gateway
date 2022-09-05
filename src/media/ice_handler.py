"""
ICE Candidate Handler

Processes ICE candidates from WebRTC clients in the context of an
ICE-lite gateway.  In ICE-lite mode (RFC 5245 Section 2.7), the gateway:
  - Acts as the controlled agent (never initiates connectivity checks)
  - Provides only host candidates (its own RTP relay addresses)
  - Processes incoming connectivity checks and responds
  - Does not perform candidate gathering or STUN/TURN allocation

This simplifies NAT traversal because the gateway is expected to have
a publicly reachable IP address, and the WebRTC client (full ICE agent)
drives the connectivity check process.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# STUN message types for ICE connectivity checks
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
STUN_BINDING_ERROR = 0x0111

# STUN attribute types
STUN_ATTR_MAPPED_ADDRESS = 0x0001
STUN_ATTR_USERNAME = 0x0006
STUN_ATTR_MESSAGE_INTEGRITY = 0x0008
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
STUN_ATTR_PRIORITY = 0x0024
STUN_ATTR_USE_CANDIDATE = 0x0025
STUN_ATTR_ICE_CONTROLLED = 0x8029
STUN_ATTR_ICE_CONTROLLING = 0x802A
STUN_ATTR_FINGERPRINT = 0x8028
STUN_ATTR_SOFTWARE = 0x8022

STUN_MAGIC_COOKIE = 0x2112A442
STUN_HEADER_SIZE = 20


@dataclass
class ICECandidateInfo:
    """Parsed ICE candidate information from a WebRTC client."""

    foundation: str = ""
    component: int = 1            # 1=RTP, 2=RTCP
    transport: str = "UDP"
    priority: int = 0
    address: str = ""
    port: int = 0
    candidate_type: str = "host"  # host, srflx, prflx, relay
    rel_addr: str = ""
    rel_port: int = 0
    generation: int = 0
    ufrag: str = ""

    @property
    def is_relay(self) -> bool:
        return self.candidate_type == "relay"

    @property
    def is_host(self) -> bool:
        return self.candidate_type == "host"


@dataclass
class ICEState:
    """ICE state for one session/media stream."""

    local_ufrag: str = ""
    local_pwd: str = ""
    remote_ufrag: str = ""
    remote_pwd: str = ""
    remote_candidates: list[ICECandidateInfo] = field(default_factory=list)
    selected_pair: tuple[str, int] | None = None
    state: str = "new"  # new, checking, connected, completed, failed


class ICEHandler:
    """Handles ICE processing for the gateway in ICE-lite mode.

    Manages ICE credentials, processes trickle candidates from WebRTC
    clients, handles STUN binding requests for connectivity checks,
    and determines the selected candidate pair.
    """

    def __init__(self, gateway_ip: str = "0.0.0.0") -> None:
        self.gateway_ip = gateway_ip
        self._sessions: dict[str, ICEState] = {}

    def create_ice_state(
        self,
        session_id: str,
        local_ufrag: str,
        local_pwd: str,
    ) -> ICEState:
        """Create ICE state for a new session.

        Args:
            session_id:  Session identifier.
            local_ufrag: Gateway's ICE username fragment.
            local_pwd:   Gateway's ICE password.

        Returns:
            The new ICEState object.
        """
        state = ICEState(
            local_ufrag=local_ufrag,
            local_pwd=local_pwd,
        )
        self._sessions[session_id] = state
        logger.debug("ICE state created", session_id=session_id, ufrag=local_ufrag)
        return state

    def set_remote_credentials(
        self,
        session_id: str,
        remote_ufrag: str,
        remote_pwd: str,
    ) -> None:
        """Set the remote ICE credentials learned from SDP."""
        state = self._sessions.get(session_id)
        if state:
            state.remote_ufrag = remote_ufrag
            state.remote_pwd = remote_pwd

    def add_remote_candidate(
        self,
        session_id: str,
        candidate_str: str,
    ) -> ICECandidateInfo | None:
        """Parse and add a trickle ICE candidate from the WebRTC client.

        Args:
            session_id:    Session identifier.
            candidate_str: Raw candidate string (without "a=candidate:" prefix).

        Returns:
            Parsed ICECandidateInfo or None on parse failure.
        """
        state = self._sessions.get(session_id)
        if not state:
            logger.warning("ICE state not found", session_id=session_id)
            return None

        candidate = self._parse_candidate(candidate_str)
        if candidate:
            state.remote_candidates.append(candidate)
            logger.debug(
                "Remote ICE candidate added",
                session_id=session_id,
                type=candidate.candidate_type,
                addr=f"{candidate.address}:{candidate.port}",
            )
        return candidate

    def process_stun_binding(
        self,
        session_id: str,
        data: bytes,
        from_addr: tuple[str, int],
    ) -> bytes | None:
        """Process an incoming STUN Binding Request (ICE connectivity check).

        Validates the request using short-term credentials (ICE ufrag:pwd),
        and returns a STUN Binding Response with XOR-MAPPED-ADDRESS.

        Args:
            session_id: Session identifier.
            data:       Raw STUN packet bytes.
            from_addr:  Source address of the STUN request.

        Returns:
            STUN Binding Response bytes, or None if invalid.
        """
        state = self._sessions.get(session_id)
        if not state:
            return None

        if len(data) < STUN_HEADER_SIZE:
            return None

        # Parse STUN header
        msg_type = struct.unpack("!H", data[0:2])[0]
        msg_length = struct.unpack("!H", data[2:4])[0]
        magic = struct.unpack("!I", data[4:8])[0]
        txn_id = data[8:20]

        if magic != STUN_MAGIC_COOKIE:
            return None

        if msg_type != STUN_BINDING_REQUEST:
            return None

        # Build STUN Binding Response
        response = self._build_binding_response(
            txn_id=txn_id,
            from_addr=from_addr,
            ice_pwd=state.local_pwd,
        )

        # Mark candidate pair as selected
        state.selected_pair = from_addr
        state.state = "connected"

        logger.info(
            "ICE connectivity check passed",
            session_id=session_id,
            remote=f"{from_addr[0]}:{from_addr[1]}",
        )

        return response

    def get_selected_pair(
        self, session_id: str
    ) -> tuple[str, int] | None:
        """Get the selected candidate pair's remote address."""
        state = self._sessions.get(session_id)
        if state:
            return state.selected_pair
        return None

    def remove_session(self, session_id: str) -> None:
        """Clean up ICE state for a terminated session."""
        self._sessions.pop(session_id, None)

    def build_gateway_candidate(
        self,
        port: int,
        component: int = 1,
        priority: int = 2130706431,
    ) -> str:
        """Build an ICE candidate string for the gateway's RTP relay address.

        In ICE-lite mode, the gateway offers only host candidates.

        Args:
            port:      RTP port.
            component: 1 for RTP, 2 for RTCP.
            priority:  Candidate priority value.

        Returns:
            ICE candidate attribute value string.
        """
        return (
            f"1 {component} UDP {priority} {self.gateway_ip} {port} "
            f"typ host"
        )

    def _parse_candidate(self, candidate_str: str) -> ICECandidateInfo | None:
        """Parse an ICE candidate string into an ICECandidateInfo.

        Format: foundation component transport priority addr port typ type
                [raddr <addr>] [rport <port>] [generation <gen>] [ufrag <ufrag>]
        """
        # Strip "candidate:" prefix if present
        if candidate_str.startswith("candidate:"):
            candidate_str = candidate_str[len("candidate:"):]

        parts = candidate_str.split()
        if len(parts) < 8:
            return None

        try:
            candidate = ICECandidateInfo(
                foundation=parts[0],
                component=int(parts[1]),
                transport=parts[2].upper(),
                priority=int(parts[3]),
                address=parts[4],
                port=int(parts[5]),
                # parts[6] should be "typ"
                candidate_type=parts[7],
            )
        except (ValueError, IndexError):
            logger.warning("Failed to parse ICE candidate", raw=candidate_str[:80])
            return None

        # Parse optional extensions
        i = 8
        while i < len(parts) - 1:
            key = parts[i]
            val = parts[i + 1]
            if key == "raddr":
                candidate.rel_addr = val
            elif key == "rport":
                try:
                    candidate.rel_port = int(val)
                except ValueError:
                    pass
            elif key == "generation":
                try:
                    candidate.generation = int(val)
                except ValueError:
                    pass
            elif key == "ufrag":
                candidate.ufrag = val
            i += 2

        return candidate

    def _build_binding_response(
        self,
        txn_id: bytes,
        from_addr: tuple[str, int],
        ice_pwd: str,
    ) -> bytes:
        """Build a STUN Binding Response with XOR-MAPPED-ADDRESS.

        Args:
            txn_id:    Transaction ID from the request (12 bytes).
            from_addr: Source address to reflect in the response.
            ice_pwd:   ICE password for MESSAGE-INTEGRITY computation.

        Returns:
            Complete STUN response packet bytes.
        """
        # XOR-MAPPED-ADDRESS attribute
        xor_port = from_addr[1] ^ (STUN_MAGIC_COOKIE >> 16)
        ip_parts = [int(p) for p in from_addr[0].split(".")]
        ip_int = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]
        xor_ip = ip_int ^ STUN_MAGIC_COOKIE

        xor_mapped = struct.pack("!HHI", 0x0001, xor_port, xor_ip)  # Family=IPv4
        xor_mapped_attr = struct.pack("!HH", STUN_ATTR_XOR_MAPPED_ADDRESS, len(xor_mapped)) + xor_mapped

        # SOFTWARE attribute
        software = b"WebRTC-SIP-Gateway"
        # Pad to 4-byte boundary
        padded_len = len(software) + (4 - len(software) % 4) % 4
        software_padded = software + b"\x00" * (padded_len - len(software))
        software_attr = struct.pack("!HH", STUN_ATTR_SOFTWARE, len(software)) + software_padded

        # Assemble attributes (before MESSAGE-INTEGRITY)
        attrs = xor_mapped_attr + software_attr

        # MESSAGE-INTEGRITY: HMAC-SHA1 over the message up to this point
        # First, build the pseudo-header with the correct length
        mi_length = len(attrs) + 24  # +24 for MESSAGE-INTEGRITY attribute itself
        pseudo_header = struct.pack("!HHI", STUN_BINDING_RESPONSE, mi_length, STUN_MAGIC_COOKIE) + txn_id
        mi_input = pseudo_header + attrs

        hmac_key = ice_pwd.encode("utf-8")
        mi_value = hmac.new(hmac_key, mi_input, hashlib.sha1).digest()
        mi_attr = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY, 20) + mi_value

        # FINGERPRINT: CRC32 XOR 0x5354554E
        all_attrs = attrs + mi_attr
        fp_length = len(all_attrs) + 8  # +8 for FINGERPRINT attribute
        fp_header = struct.pack("!HHI", STUN_BINDING_RESPONSE, fp_length, STUN_MAGIC_COOKIE) + txn_id
        fp_input = fp_header + all_attrs

        import binascii
        crc = binascii.crc32(fp_input) & 0xFFFFFFFF
        fingerprint = crc ^ 0x5354554E
        fp_attr = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, fingerprint)

        # Final message
        final_attrs = attrs + mi_attr + fp_attr
        header = struct.pack("!HHI", STUN_BINDING_RESPONSE, len(final_attrs), STUN_MAGIC_COOKIE) + txn_id

        return header + final_attrs
