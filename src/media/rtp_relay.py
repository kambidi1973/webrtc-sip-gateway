"""
RTP Media Relay

Forwards RTP packets between a WebRTC endpoint and a SIP endpoint, acting
as a back-to-back RTP user agent.  Each bridged call gets two allocated
UDP ports: one facing the WebRTC/SRTP side and one facing the SIP/RTP side.

Responsibilities:
  - Port pool management (allocate/release from configured range)
  - Packet forwarding with SSRC rewriting
  - RTP header parsing for statistics and SSRC tracking
  - Inactivity detection (RTP timeout)
  - DTMF relay via RFC 4733 telephone-event packets
"""

from __future__ import annotations

import asyncio
import struct
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# RTP header constants
RTP_VERSION = 2
RTP_HEADER_MIN_SIZE = 12


@dataclass
class RTPHeader:
    """Parsed RTP packet header (RFC 3550)."""

    version: int = 2
    padding: bool = False
    extension: bool = False
    csrc_count: int = 0
    marker: bool = False
    payload_type: int = 0
    sequence_number: int = 0
    timestamp: int = 0
    ssrc: int = 0
    csrc: list[int] = field(default_factory=list)
    header_size: int = 12


def parse_rtp_header(data: bytes) -> RTPHeader | None:
    """Parse the fixed RTP header from a packet.

    Returns None if the packet is too short or has an invalid version.
    """
    if len(data) < RTP_HEADER_MIN_SIZE:
        return None

    byte0 = data[0]
    byte1 = data[1]

    version = (byte0 >> 6) & 0x03
    if version != RTP_VERSION:
        return None

    padding = bool((byte0 >> 5) & 0x01)
    extension = bool((byte0 >> 4) & 0x01)
    csrc_count = byte0 & 0x0F
    marker = bool((byte1 >> 7) & 0x01)
    payload_type = byte1 & 0x7F

    sequence_number = struct.unpack("!H", data[2:4])[0]
    timestamp = struct.unpack("!I", data[4:8])[0]
    ssrc = struct.unpack("!I", data[8:12])[0]

    header_size = 12 + csrc_count * 4
    csrc_list: list[int] = []
    for i in range(csrc_count):
        offset = 12 + i * 4
        if offset + 4 <= len(data):
            csrc_list.append(struct.unpack("!I", data[offset:offset + 4])[0])

    return RTPHeader(
        version=version,
        padding=padding,
        extension=extension,
        csrc_count=csrc_count,
        marker=marker,
        payload_type=payload_type,
        sequence_number=sequence_number,
        timestamp=timestamp,
        ssrc=ssrc,
        csrc=csrc_list,
        header_size=header_size,
    )


def rewrite_ssrc(data: bytes, new_ssrc: int) -> bytes:
    """Rewrite the SSRC field in an RTP packet.

    Args:
        data:     Original RTP packet bytes.
        new_ssrc: New SSRC value to insert.

    Returns:
        Modified packet with the new SSRC.
    """
    if len(data) < RTP_HEADER_MIN_SIZE:
        return data
    return data[:8] + struct.pack("!I", new_ssrc) + data[12:]


@dataclass
class RelayPort:
    """A pair of UDP ports allocated for one direction of a bridged call."""

    port: int
    transport: asyncio.DatagramTransport | None = None
    protocol: RTPProtocol | None = None
    remote_addr: tuple[str, int] | None = None
    ssrc_local: int = 0
    ssrc_remote: int = 0
    last_packet_time: float = field(default_factory=time.time)
    packets_received: int = 0
    packets_sent: int = 0
    bytes_received: int = 0
    bytes_sent: int = 0


@dataclass
class RelaySession:
    """A bidirectional RTP relay between two endpoints."""

    session_id: str
    webrtc_side: RelayPort
    sip_side: RelayPort
    created_at: float = field(default_factory=time.time)
    active: bool = True


class RTPProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol for receiving RTP packets."""

    def __init__(
        self,
        relay: RTPRelay,
        session_id: str,
        side: str,  # "webrtc" or "sip"
    ) -> None:
        self.relay = relay
        self.session_id = session_id
        self.side = side
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Forward received RTP to the other side of the relay."""
        asyncio.create_task(
            self.relay.forward_packet(self.session_id, self.side, data, addr)
        )

    def error_received(self, exc: Exception) -> None:
        logger.error(
            "RTP transport error",
            session_id=self.session_id,
            side=self.side,
            error=str(exc),
        )

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.warning(
                "RTP transport lost",
                session_id=self.session_id,
                side=self.side,
                error=str(exc),
            )


class RTPRelay:
    """Manages RTP relay sessions for bridged WebRTC-SIP calls.

    Allocates UDP port pairs from a configured range and forwards
    RTP packets between WebRTC and SIP endpoints with optional
    SSRC rewriting.
    """

    def __init__(
        self,
        public_ip: str = "0.0.0.0",
        port_min: int = 10000,
        port_max: int = 10100,
        rtp_timeout: float = 60.0,
    ) -> None:
        self.public_ip = public_ip
        self.port_min = port_min
        self.port_max = port_max
        self.rtp_timeout = rtp_timeout

        # Port pool: even-numbered ports (odd = RTCP by convention)
        self._available_ports: list[int] = [
            p for p in range(port_min, port_max, 2)
        ]
        self._sessions: dict[str, RelaySession] = {}
        self._timeout_task: asyncio.Task[None] | None = None

    @property
    def available_ports(self) -> int:
        """Number of port pairs still available."""
        return len(self._available_ports)

    @property
    def active_sessions(self) -> int:
        """Number of active relay sessions."""
        return sum(1 for s in self._sessions.values() if s.active)

    async def start(self) -> None:
        """Initialize the RTP relay and start the timeout checker."""
        logger.info(
            "RTP relay starting",
            port_range=f"{self.port_min}-{self.port_max}",
            available_ports=len(self._available_ports),
        )
        self._timeout_task = asyncio.create_task(self._check_timeouts())

    async def stop(self) -> None:
        """Stop all relay sessions and release resources."""
        if self._timeout_task:
            self._timeout_task.cancel()
            try:
                await self._timeout_task
            except asyncio.CancelledError:
                pass

        for session_id in list(self._sessions.keys()):
            await self.release_session(session_id)

        logger.info("RTP relay stopped")

    async def allocate_session(self, session_id: str) -> tuple[int, int]:
        """Allocate a port pair for a new relay session.

        Args:
            session_id: The session to allocate ports for.

        Returns:
            Tuple of (webrtc_port, sip_port).

        Raises:
            RuntimeError: If no ports are available.
        """
        if len(self._available_ports) < 2:
            raise RuntimeError("No RTP ports available")

        webrtc_port = self._available_ports.pop(0)
        sip_port = self._available_ports.pop(0)

        import random
        webrtc_ssrc = random.randint(0x10000000, 0x7FFFFFFF)
        sip_ssrc = random.randint(0x10000000, 0x7FFFFFFF)

        relay = RelaySession(
            session_id=session_id,
            webrtc_side=RelayPort(port=webrtc_port, ssrc_local=webrtc_ssrc),
            sip_side=RelayPort(port=sip_port, ssrc_local=sip_ssrc),
        )

        # Create UDP endpoints
        loop = asyncio.get_running_loop()

        # WebRTC-facing port
        wt, wp = await loop.create_datagram_endpoint(
            lambda: RTPProtocol(self, session_id, "webrtc"),
            local_addr=("0.0.0.0", webrtc_port),
        )
        relay.webrtc_side.transport = wt  # type: ignore[assignment]
        relay.webrtc_side.protocol = wp  # type: ignore[assignment]

        # SIP-facing port
        st, sp = await loop.create_datagram_endpoint(
            lambda: RTPProtocol(self, session_id, "sip"),
            local_addr=("0.0.0.0", sip_port),
        )
        relay.sip_side.transport = st  # type: ignore[assignment]
        relay.sip_side.protocol = sp  # type: ignore[assignment]

        self._sessions[session_id] = relay

        logger.info(
            "RTP relay allocated",
            session_id=session_id,
            webrtc_port=webrtc_port,
            sip_port=sip_port,
        )
        return webrtc_port, sip_port

    async def release_session(self, session_id: str) -> None:
        """Release a relay session and return ports to the pool."""
        relay = self._sessions.pop(session_id, None)
        if not relay:
            return

        relay.active = False

        # Close transports
        if relay.webrtc_side.transport:
            relay.webrtc_side.transport.close()
        if relay.sip_side.transport:
            relay.sip_side.transport.close()

        # Return ports to pool
        self._available_ports.append(relay.webrtc_side.port)
        self._available_ports.append(relay.sip_side.port)
        self._available_ports.sort()

        logger.info(
            "RTP relay released",
            session_id=session_id,
            packets_webrtc=relay.webrtc_side.packets_received,
            packets_sip=relay.sip_side.packets_received,
        )

    def set_remote_addr(
        self, session_id: str, side: str, addr: tuple[str, int]
    ) -> None:
        """Set the remote address for one side of the relay.

        Called once the remote endpoint's IP:port is known from SDP.

        Args:
            session_id: The relay session.
            side:       "webrtc" or "sip".
            addr:       Remote (host, port) tuple.
        """
        relay = self._sessions.get(session_id)
        if not relay:
            return

        if side == "webrtc":
            relay.webrtc_side.remote_addr = addr
        else:
            relay.sip_side.remote_addr = addr

        logger.debug(
            "RTP remote address set",
            session_id=session_id,
            side=side,
            remote=f"{addr[0]}:{addr[1]}",
        )

    async def forward_packet(
        self,
        session_id: str,
        from_side: str,
        data: bytes,
        addr: tuple[str, int],
    ) -> None:
        """Forward an RTP packet from one side to the other.

        Also performs SSRC rewriting and updates statistics.
        """
        relay = self._sessions.get(session_id)
        if not relay or not relay.active:
            return

        header = parse_rtp_header(data)
        if header is None:
            return  # Not a valid RTP packet

        now = time.time()

        if from_side == "webrtc":
            # Packet from WebRTC -> forward to SIP
            source = relay.webrtc_side
            dest = relay.sip_side

            # Learn the WebRTC client's address from the first packet
            if source.remote_addr is None:
                source.remote_addr = addr

            source.ssrc_remote = header.ssrc
        else:
            # Packet from SIP -> forward to WebRTC
            source = relay.sip_side
            dest = relay.webrtc_side

            if source.remote_addr is None:
                source.remote_addr = addr

            source.ssrc_remote = header.ssrc

        # Update source stats
        source.last_packet_time = now
        source.packets_received += 1
        source.bytes_received += len(data)

        # Rewrite SSRC to our local SSRC for the destination
        forwarded = rewrite_ssrc(data, dest.ssrc_local)

        # Forward to destination
        if dest.remote_addr and dest.transport:
            dest.transport.sendto(forwarded, dest.remote_addr)
            dest.packets_sent += 1
            dest.bytes_sent += len(forwarded)

    async def send_dtmf(
        self,
        session_id: str,
        digit: str,
        duration_ms: int = 160,
        side: str = "sip",
    ) -> None:
        """Send an RFC 4733 DTMF tone to one side of the relay.

        Generates the three standard telephone-event RTP packets:
        start, continuation, and three end packets.

        Args:
            session_id:  Target relay session.
            digit:       DTMF digit character.
            duration_ms: Tone duration in milliseconds.
            side:        Which side to send to ("sip" or "webrtc").
        """
        from src.sdp.codec import CodecNegotiator

        relay = self._sessions.get(session_id)
        if not relay:
            return

        event_code = CodecNegotiator.map_dtmf_digit(digit)
        if event_code < 0:
            logger.warning("Invalid DTMF digit", digit=digit)
            return

        dest = relay.sip_side if side == "sip" else relay.webrtc_side
        if not dest.remote_addr or not dest.transport:
            return

        # Build RTP packets with telephone-event payload type (101)
        telephone_event_pt = 101
        clock_rate = 8000
        samples_per_ms = clock_rate // 1000
        total_duration = duration_ms * samples_per_ms

        # We send packets at 20ms intervals
        packets_to_send = max(duration_ms // 20, 1)

        import random
        seq = random.randint(0, 65535)
        ts = random.randint(0, 0xFFFFFFFF)

        for i in range(packets_to_send):
            current_duration = min((i + 1) * 20 * samples_per_ms, total_duration)
            payload = CodecNegotiator.build_rfc4733_payload(
                event=event_code,
                end=False,
                volume=10,
                duration=current_duration,
            )
            rtp_packet = self._build_rtp_packet(
                pt=telephone_event_pt,
                seq=seq + i,
                timestamp=ts,
                ssrc=dest.ssrc_local,
                payload=payload,
                marker=(i == 0),
            )
            dest.transport.sendto(rtp_packet, dest.remote_addr)
            await asyncio.sleep(0.02)  # 20ms pacing

        # Send three end-of-event packets (per RFC 4733)
        for j in range(3):
            payload = CodecNegotiator.build_rfc4733_payload(
                event=event_code,
                end=True,
                volume=10,
                duration=total_duration,
            )
            rtp_packet = self._build_rtp_packet(
                pt=telephone_event_pt,
                seq=seq + packets_to_send + j,
                timestamp=ts,
                ssrc=dest.ssrc_local,
                payload=payload,
                marker=False,
            )
            dest.transport.sendto(rtp_packet, dest.remote_addr)

        logger.info(
            "DTMF sent via RTP",
            session_id=session_id,
            digit=digit,
            duration_ms=duration_ms,
        )

    def get_session_stats(self, session_id: str) -> dict[str, Any] | None:
        """Get relay statistics for a session."""
        relay = self._sessions.get(session_id)
        if not relay:
            return None

        return {
            "session_id": session_id,
            "active": relay.active,
            "webrtc": {
                "port": relay.webrtc_side.port,
                "remote_addr": (
                    f"{relay.webrtc_side.remote_addr[0]}:{relay.webrtc_side.remote_addr[1]}"
                    if relay.webrtc_side.remote_addr else None
                ),
                "packets_rx": relay.webrtc_side.packets_received,
                "packets_tx": relay.webrtc_side.packets_sent,
                "bytes_rx": relay.webrtc_side.bytes_received,
                "bytes_tx": relay.webrtc_side.bytes_sent,
            },
            "sip": {
                "port": relay.sip_side.port,
                "remote_addr": (
                    f"{relay.sip_side.remote_addr[0]}:{relay.sip_side.remote_addr[1]}"
                    if relay.sip_side.remote_addr else None
                ),
                "packets_rx": relay.sip_side.packets_received,
                "packets_tx": relay.sip_side.packets_sent,
                "bytes_rx": relay.sip_side.bytes_received,
                "bytes_tx": relay.sip_side.bytes_sent,
            },
        }

    @staticmethod
    def _build_rtp_packet(
        pt: int,
        seq: int,
        timestamp: int,
        ssrc: int,
        payload: bytes,
        marker: bool = False,
    ) -> bytes:
        """Build a minimal RTP packet from components."""
        byte0 = (RTP_VERSION << 6)  # V=2, P=0, X=0, CC=0
        byte1 = pt & 0x7F
        if marker:
            byte1 |= 0x80

        header = struct.pack(
            "!BBHII",
            byte0,
            byte1,
            seq & 0xFFFF,
            timestamp & 0xFFFFFFFF,
            ssrc & 0xFFFFFFFF,
        )
        return header + payload

    async def _check_timeouts(self) -> None:
        """Background task to detect inactive relay sessions."""
        try:
            while True:
                await asyncio.sleep(10)
                now = time.time()

                for session_id, relay in list(self._sessions.items()):
                    if not relay.active:
                        continue

                    # Check both sides for inactivity
                    webrtc_idle = now - relay.webrtc_side.last_packet_time
                    sip_idle = now - relay.sip_side.last_packet_time

                    if (
                        webrtc_idle > self.rtp_timeout
                        and sip_idle > self.rtp_timeout
                    ):
                        logger.warning(
                            "RTP timeout - no media",
                            session_id=session_id,
                            webrtc_idle=f"{webrtc_idle:.0f}s",
                            sip_idle=f"{sip_idle:.0f}s",
                        )
                        relay.active = False

        except asyncio.CancelledError:
            pass
