"""
Codec Negotiation Engine

Implements SDP offer/answer codec negotiation per RFC 3264, with specific
handling for:
  - Standard telephony codecs: G.711 (PCMU/PCMA), G.722, G.729
  - WebRTC codecs: Opus (RFC 7587)
  - DTMF: telephone-event (RFC 4733)
  - Payload type mapping between WebRTC dynamic PTs and SIP conventions

The negotiation engine respects codec preference ordering and handles
asymmetric codec support between WebRTC and SIP endpoints.

Payload Type Conventions (RFC 3551):
  PT 0  = PCMU/8000   (G.711 mu-law)
  PT 8  = PCMA/8000   (G.711 A-law)
  PT 9  = G722/8000   (G.722 wideband - note: SDP clock rate is 8000 per RFC)
  PT 18 = G729/8000   (G.729)
  Dynamic (96-127) = Opus, telephone-event, etc.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from src.sdp.parser import SDPMediaCodec, SDPMediaDescription, SDPParser, SDPSession

logger = structlog.get_logger(__name__)


@dataclass
class CodecDefinition:
    """Static definition of a supported codec."""

    name: str
    clock_rate: int
    channels: int = 1
    static_pt: int | None = None       # None = must use dynamic PT
    default_dynamic_pt: int = 96        # Preferred dynamic PT if no static
    fmtp: str = ""                      # Default fmtp parameters
    priority: int = 0                   # Lower = higher priority


# Canonical codec definitions
CODEC_PCMU = CodecDefinition(
    name="PCMU", clock_rate=8000, static_pt=0, priority=30,
)
CODEC_PCMA = CodecDefinition(
    name="PCMA", clock_rate=8000, static_pt=8, priority=40,
)
CODEC_G722 = CodecDefinition(
    name="G722", clock_rate=8000, static_pt=9, priority=20,
)
CODEC_G729 = CodecDefinition(
    name="G729", clock_rate=8000, static_pt=18, priority=50,
)
CODEC_OPUS = CodecDefinition(
    name="opus",
    clock_rate=48000,
    channels=2,
    default_dynamic_pt=111,
    fmtp="minptime=10;useinbandfec=1",
    priority=10,
)
CODEC_TELEPHONE_EVENT = CodecDefinition(
    name="telephone-event",
    clock_rate=8000,
    default_dynamic_pt=101,
    fmtp="0-16",
    priority=100,
)
CODEC_TELEPHONE_EVENT_48K = CodecDefinition(
    name="telephone-event",
    clock_rate=48000,
    default_dynamic_pt=110,
    fmtp="0-16",
    priority=101,
)

# Master codec registry
_CODEC_REGISTRY: dict[str, CodecDefinition] = {
    "pcmu": CODEC_PCMU,
    "pcma": CODEC_PCMA,
    "g722": CODEC_G722,
    "g729": CODEC_G729,
    "opus": CODEC_OPUS,
    "telephone-event": CODEC_TELEPHONE_EVENT,
}


@dataclass
class NegotiatedCodec:
    """Result of codec negotiation between two endpoints."""

    name: str
    payload_type_local: int
    payload_type_remote: int
    clock_rate: int
    channels: int = 1
    fmtp: str = ""


@dataclass
class NegotiationResult:
    """Complete codec negotiation result."""

    audio_codecs: list[NegotiatedCodec] = field(default_factory=list)
    telephone_event: NegotiatedCodec | None = None
    success: bool = False
    error: str = ""

    @property
    def primary_codec(self) -> NegotiatedCodec | None:
        """The first (highest priority) negotiated audio codec."""
        return self.audio_codecs[0] if self.audio_codecs else None


class CodecNegotiator:
    """Negotiates codecs between WebRTC and SIP endpoints.

    Implements RFC 3264 offer/answer model for codec selection.
    Handles payload type mapping between endpoints that may use
    different dynamic PT assignments for the same codec.
    """

    def __init__(
        self,
        preferred_codecs: list[str] | None = None,
        enable_opus: bool = True,
        enable_dtmf: bool = True,
        dtmf_mode: str = "rfc4733",
    ) -> None:
        """Initialize the codec negotiator.

        Args:
            preferred_codecs: Ordered list of codec names (highest priority first).
            enable_opus:      Allow Opus codec in negotiation.
            enable_dtmf:      Include telephone-event for DTMF.
            dtmf_mode:        DTMF mode: "rfc4733", "inband", or "sip_info".
        """
        if preferred_codecs is None:
            preferred_codecs = ["opus", "G722", "PCMU", "PCMA"]

        self.preferred_codecs = [c.lower() for c in preferred_codecs]
        self.enable_opus = enable_opus
        self.enable_dtmf = enable_dtmf and dtmf_mode == "rfc4733"
        self.dtmf_mode = dtmf_mode

    def negotiate(
        self,
        offer_sdp: str,
        answer_capabilities: list[str] | None = None,
    ) -> NegotiationResult:
        """Negotiate codecs from an SDP offer against local capabilities.

        The offer comes from one side (WebRTC or SIP), and we determine
        which codecs to accept in the answer based on our preferences.

        Args:
            offer_sdp:            Raw SDP offer text.
            answer_capabilities:  Codec names we support (defaults to preferred list).

        Returns:
            NegotiationResult with matched codecs.
        """
        parser = SDPParser()
        session = parser.parse(offer_sdp)
        result = NegotiationResult()

        audio = session.audio_media
        if not audio:
            result.error = "No audio media description in offer"
            return result

        if answer_capabilities is None:
            answer_capabilities = self.preferred_codecs

        caps_lower = {c.lower() for c in answer_capabilities}

        # Match codecs from the offer against our capabilities
        matched: list[tuple[int, NegotiatedCodec]] = []
        telephone_event: NegotiatedCodec | None = None

        for codec in audio.codecs:
            codec_name_lower = codec.name_normalized

            if codec_name_lower == "telephone-event":
                if self.enable_dtmf:
                    te_def = _CODEC_REGISTRY.get("telephone-event", CODEC_TELEPHONE_EVENT)
                    local_pt = te_def.default_dynamic_pt
                    telephone_event = NegotiatedCodec(
                        name="telephone-event",
                        payload_type_local=local_pt,
                        payload_type_remote=codec.payload_type,
                        clock_rate=codec.clock_rate,
                        fmtp=codec.fmtp_params or "0-16",
                    )
                continue

            if codec_name_lower not in caps_lower:
                continue

            if codec_name_lower == "opus" and not self.enable_opus:
                continue

            # Determine local payload type
            codec_def = _CODEC_REGISTRY.get(codec_name_lower)
            if codec_def and codec_def.static_pt is not None:
                local_pt = codec_def.static_pt
            elif codec_def:
                local_pt = codec_def.default_dynamic_pt
            else:
                local_pt = codec.payload_type

            # Priority from our preference order
            try:
                priority = self.preferred_codecs.index(codec_name_lower)
            except ValueError:
                priority = 999

            neg = NegotiatedCodec(
                name=codec.encoding_name,
                payload_type_local=local_pt,
                payload_type_remote=codec.payload_type,
                clock_rate=codec.clock_rate,
                channels=codec.channels,
                fmtp=codec.fmtp_params,
            )
            matched.append((priority, neg))

        # Sort by our preference order
        matched.sort(key=lambda x: x[0])
        result.audio_codecs = [m[1] for m in matched]
        result.telephone_event = telephone_event
        result.success = len(result.audio_codecs) > 0

        if not result.success:
            result.error = "No common codecs between offer and answer capabilities"

        logger.info(
            "Codec negotiation complete",
            matched=[c.name for c in result.audio_codecs],
            telephone_event=telephone_event is not None,
            success=result.success,
        )

        return result

    def build_answer_sdp(
        self,
        offer_sdp: str,
        negotiation: NegotiationResult,
        gateway_ip: str,
        rtp_port: int,
    ) -> str:
        """Build an SDP answer from negotiation results.

        Creates a minimal SDP answer that includes only the negotiated
        codecs in the gateway's preferred order.

        Args:
            offer_sdp:    Original SDP offer.
            negotiation:  Result from negotiate().
            gateway_ip:   Gateway's IP for c= and o= lines.
            rtp_port:     RTP port allocated for this session.

        Returns:
            SDP answer text.
        """
        parser = SDPParser()
        offer = parser.parse(offer_sdp)

        # Build answer session
        import time as _time

        answer = SDPSession(
            version=0,
            origin_username="webrtc-gw",
            origin_session_id=str(int(_time.time())),
            origin_session_version="1",
            origin_net_type="IN",
            origin_addr_type="IP4",
            origin_address=gateway_ip,
            session_name="WebRTC-SIP-Gateway",
            connection=gateway_ip,
            timing="0 0",
        )

        # Build audio media line
        formats: list[int] = []
        codecs: list[SDPMediaCodec] = []

        for neg_codec in negotiation.audio_codecs:
            formats.append(neg_codec.payload_type_local)
            codecs.append(SDPMediaCodec(
                payload_type=neg_codec.payload_type_local,
                encoding_name=neg_codec.name,
                clock_rate=neg_codec.clock_rate,
                channels=neg_codec.channels,
                fmtp_params=neg_codec.fmtp,
            ))

        if negotiation.telephone_event:
            te = negotiation.telephone_event
            formats.append(te.payload_type_local)
            codecs.append(SDPMediaCodec(
                payload_type=te.payload_type_local,
                encoding_name="telephone-event",
                clock_rate=te.clock_rate,
                fmtp_params=te.fmtp,
            ))

        audio_media = SDPMediaDescription(
            media_type="audio",
            port=rtp_port,
            protocol=offer.audio_media.protocol if offer.audio_media else "RTP/AVP",
            formats=formats,
            connection=gateway_ip,
            codecs=codecs,
            direction="sendrecv",
        )

        answer.media.append(audio_media)

        return parser.serialize(answer)

    def create_offer(
        self,
        gateway_ip: str,
        rtp_port: int,
        profile: str = "RTP/AVP",
        codecs_to_offer: list[str] | None = None,
    ) -> str:
        """Create an SDP offer from scratch with the gateway's codec preferences.

        Used when the gateway originates a call to a SIP endpoint.

        Args:
            gateway_ip:       Gateway IP for connection info.
            rtp_port:         Allocated RTP port.
            profile:          Media profile (RTP/AVP or RTP/SAVP).
            codecs_to_offer:  Codec names to include (defaults to preferences).

        Returns:
            SDP offer text.
        """
        import time as _time
        parser = SDPParser()

        if codecs_to_offer is None:
            codecs_to_offer = self.preferred_codecs

        session = SDPSession(
            version=0,
            origin_username="webrtc-gw",
            origin_session_id=str(int(_time.time())),
            origin_session_version="1",
            origin_net_type="IN",
            origin_addr_type="IP4",
            origin_address=gateway_ip,
            session_name="WebRTC-SIP-Gateway",
            connection=gateway_ip,
            timing="0 0",
        )

        formats: list[int] = []
        codecs_list: list[SDPMediaCodec] = []

        for codec_name in codecs_to_offer:
            codec_def = _CODEC_REGISTRY.get(codec_name.lower())
            if not codec_def:
                continue

            pt = codec_def.static_pt if codec_def.static_pt is not None else codec_def.default_dynamic_pt
            formats.append(pt)
            codecs_list.append(SDPMediaCodec(
                payload_type=pt,
                encoding_name=codec_def.name,
                clock_rate=codec_def.clock_rate,
                channels=codec_def.channels,
                fmtp_params=codec_def.fmtp,
            ))

        # Always add telephone-event if DTMF enabled
        if self.enable_dtmf:
            te = CODEC_TELEPHONE_EVENT
            formats.append(te.default_dynamic_pt)
            codecs_list.append(SDPMediaCodec(
                payload_type=te.default_dynamic_pt,
                encoding_name=te.name,
                clock_rate=te.clock_rate,
                fmtp_params=te.fmtp,
            ))

        audio_media = SDPMediaDescription(
            media_type="audio",
            port=rtp_port,
            protocol=profile,
            formats=formats,
            connection=gateway_ip,
            codecs=codecs_list,
            direction="sendrecv",
        )

        session.media.append(audio_media)
        return parser.serialize(session)

    @staticmethod
    def map_dtmf_digit(digit: str) -> int:
        """Map a DTMF digit to its RFC 4733 event code.

        Args:
            digit: DTMF character (0-9, *, #, A-D).

        Returns:
            RFC 4733 event code (0-15).
        """
        dtmf_map = {
            "0": 0, "1": 1, "2": 2, "3": 3, "4": 4,
            "5": 5, "6": 6, "7": 7, "8": 8, "9": 9,
            "*": 10, "#": 11,
            "A": 12, "B": 13, "C": 14, "D": 15,
        }
        return dtmf_map.get(digit.upper(), -1)

    @staticmethod
    def build_rfc4733_payload(
        event: int,
        end: bool = False,
        volume: int = 10,
        duration: int = 160,
    ) -> bytes:
        """Build an RFC 4733 telephone-event RTP payload.

        Payload format (4 bytes):
          Byte 0:    Event code (0-15)
          Byte 1:    E(1 bit) | R(1 bit) | Volume(6 bits)
          Bytes 2-3: Duration (16 bits, in timestamp units)

        Args:
            event:    DTMF event code (0-15).
            end:      Whether this is the end-of-event packet.
            volume:   Power level in dBm0 (0-63, default 10).
            duration: Duration in timestamp units.

        Returns:
            4-byte RFC 4733 payload.
        """
        byte0 = event & 0xFF
        byte1 = (volume & 0x3F)
        if end:
            byte1 |= 0x80  # Set End bit
        dur_hi = (duration >> 8) & 0xFF
        dur_lo = duration & 0xFF
        return bytes([byte0, byte1, dur_hi, dur_lo])
