"""
SDP Translator - WebRTC SDP <-> SIP SDP Conversion

WebRTC and SIP use different SDP conventions.  This module handles the
translation between the two worlds:

WebRTC SDP characteristics:
  - Uses UDP/TLS/RTP/SAVPF or RTP/SAVPF profile (mandatory DTLS-SRTP)
  - Contains ICE attributes (ice-ufrag, ice-pwd, candidates)
  - Contains DTLS fingerprint and setup attributes
  - Uses BUNDLE grouping for multiplexing media over a single transport
  - Includes rtcp-mux, rtcp-rsize
  - Opus codec with WebRTC-specific fmtp parameters
  - extmap for header extensions (abs-send-time, transport-cc, etc.)

SIP SDP characteristics:
  - Typically uses RTP/AVP or RTP/SAVP profile
  - No ICE attributes (unless the SIP endpoint supports ICE)
  - No DTLS fingerprint
  - Separate ports per media stream (no BUNDLE)
  - G.711 (PCMU/PCMA), G.722, and telephone-event are most common
  - Simpler attribute set

Translation direction:
  - webrtc_to_sip():  Strip WebRTC-specific attributes, translate profile
  - sip_to_webrtc():  Add ICE-lite attributes, DTLS fingerprint, translate profile
"""

from __future__ import annotations

import random
import time
from typing import Any

import structlog

from src.sdp.parser import SDPMediaDescription, SDPParser, SDPSession

logger = structlog.get_logger(__name__)

# WebRTC-specific attributes to strip when converting to SIP
_WEBRTC_ONLY_ATTRS = {
    "ice-ufrag", "ice-pwd", "ice-options", "ice-lite",
    "fingerprint", "setup",
    "rtcp-mux", "rtcp-rsize",
    "ssrc", "ssrc-group",
    "msid", "msid-semantic",
    "extmap",
    "candidate",
}

# WebRTC-specific media-level attributes to remove
_WEBRTC_MEDIA_ATTRS = {
    "msid", "rid", "simulcast", "imageattr",
}

# Profile mapping
_WEBRTC_PROFILES = {"UDP/TLS/RTP/SAVPF", "RTP/SAVPF", "UDP/TLS/RTP/SAVP"}
_SIP_PROFILE_DEFAULT = "RTP/AVP"
_SIP_PROFILE_SRTP = "RTP/SAVP"
_WEBRTC_PROFILE_DEFAULT = "UDP/TLS/RTP/SAVPF"


class SDPTranslator:
    """Translates SDP between WebRTC and SIP formats.

    Handles the impedance mismatch between WebRTC's DTLS-SRTP/ICE/BUNDLE
    model and traditional SIP's simpler RTP/AVP model.
    """

    def __init__(
        self,
        gateway_ip: str = "0.0.0.0",
        rtp_port: int = 10000,
        use_srtp: bool = False,
        ice_lite: bool = True,
    ) -> None:
        self._parser = SDPParser()
        self.gateway_ip = gateway_ip
        self.rtp_port = rtp_port
        self.use_srtp = use_srtp
        self.ice_lite = ice_lite
        self._session_counter = int(time.time())

    def webrtc_to_sip(
        self,
        webrtc_sdp: str,
        gateway_ip: str | None = None,
        rtp_port: int | None = None,
    ) -> str:
        """Translate a WebRTC SDP to a SIP-compatible SDP.

        Strips ICE, DTLS, BUNDLE, and other WebRTC-specific attributes.
        Rewrites the media profile from SAVPF to AVP (or SAVP if SRTP enabled).
        Replaces connection address with gateway's RTP relay address.

        Args:
            webrtc_sdp: Raw SDP from the WebRTC client.
            gateway_ip: Override the gateway IP for c= and o= lines.
            rtp_port:   Override the RTP port for m= line.

        Returns:
            SIP-compatible SDP string.
        """
        ip = gateway_ip or self.gateway_ip
        port = rtp_port or self.rtp_port
        session = self._parser.parse(webrtc_sdp)

        # Rewrite origin with gateway address
        self._session_counter += 1
        session.origin_username = "webrtc-gw"
        session.origin_address = ip
        session.origin_session_id = str(self._session_counter)
        session.origin_session_version = str(self._session_counter)

        # Set session-level connection
        session.connection = ip

        # Strip session-level WebRTC attributes
        session.ice_ufrag = ""
        session.ice_pwd = ""
        session.ice_options = ""
        session.ice_lite = False
        session.fingerprint = ""
        session.setup = ""
        session.group = ""
        session.msid_semantic = ""

        # Remove WebRTC-specific session attributes
        for attr in list(session.attributes.keys()):
            if attr in _WEBRTC_ONLY_ATTRS or attr in _WEBRTC_MEDIA_ATTRS:
                del session.attributes[attr]

        # Process each media description
        sip_profile = _SIP_PROFILE_SRTP if self.use_srtp else _SIP_PROFILE_DEFAULT

        for i, media in enumerate(session.media):
            # Translate media profile
            if media.protocol in _WEBRTC_PROFILES:
                media.protocol = sip_profile

            # Set RTP port (increment by 2 for each additional media stream)
            media.port = port + (i * 2)
            media.connection = ip

            # Strip ICE attributes
            media.ice_ufrag = ""
            media.ice_pwd = ""
            media.ice_options = ""
            media.candidates = []

            # Strip DTLS attributes
            media.fingerprint = ""
            media.setup = ""

            # Strip rtcp-mux (SIP typically uses separate RTCP port)
            media.rtcp_mux = False
            media.rtcp_rsize = False
            media.rtcp = f"{media.port + 1} IN IP4 {ip}"

            # Strip WebRTC-specific media attributes
            media.ssrc = []
            media.ssrc_group = ""
            media.ext_maps = []
            media.mid = ""

            # Remove WebRTC-only attributes from the attribute bag
            for attr in list(media.attributes.keys()):
                if attr in _WEBRTC_MEDIA_ATTRS or attr in _WEBRTC_ONLY_ATTRS:
                    del media.attributes[attr]

            # Strip rtcp-fb for codecs (SIP endpoints rarely support these)
            for codec in media.codecs:
                codec.rtcp_feedback = []

        return self._parser.serialize(session)

    def sip_to_webrtc(
        self,
        sip_sdp: str,
        gateway_ip: str | None = None,
        ice_ufrag: str | None = None,
        ice_pwd: str | None = None,
        fingerprint: str | None = None,
    ) -> str:
        """Translate a SIP SDP to a WebRTC-compatible SDP.

        Adds ICE-lite attributes, DTLS fingerprint, BUNDLE grouping,
        and translates the media profile to SAVPF.

        Args:
            sip_sdp:     Raw SDP from the SIP endpoint.
            gateway_ip:  Override gateway IP for ICE candidate.
            ice_ufrag:   ICE username fragment (generated if not provided).
            ice_pwd:     ICE password (generated if not provided).
            fingerprint: DTLS fingerprint (placeholder if not provided).

        Returns:
            WebRTC-compatible SDP string.
        """
        ip = gateway_ip or self.gateway_ip
        session = self._parser.parse(sip_sdp)

        # Generate ICE credentials if not provided
        if not ice_ufrag:
            ice_ufrag = self._generate_ice_ufrag()
        if not ice_pwd:
            ice_pwd = self._generate_ice_pwd()
        if not fingerprint:
            fingerprint = self._generate_placeholder_fingerprint()

        # Rewrite origin
        self._session_counter += 1
        session.origin_username = "webrtc-gw"
        session.origin_address = ip
        session.origin_session_id = str(self._session_counter)
        session.origin_session_version = str(self._session_counter)

        session.connection = ip

        # Set session-level ICE and DTLS attributes
        if self.ice_lite:
            session.ice_lite = True
        session.ice_ufrag = ice_ufrag
        session.ice_pwd = ice_pwd
        session.ice_options = "trickle"
        session.fingerprint = fingerprint
        session.setup = "actpass"

        # Build BUNDLE group from media mids
        mids: list[str] = []
        for i, media in enumerate(session.media):
            mid = media.mid or str(i)
            media.mid = mid
            mids.append(mid)

        if mids:
            session.group = "BUNDLE " + " ".join(mids)

        session.msid_semantic = " WMS *"

        # Process each media description
        for i, media in enumerate(session.media):
            # Translate to WebRTC profile
            if media.protocol in {_SIP_PROFILE_DEFAULT, _SIP_PROFILE_SRTP, "RTP/SAVP"}:
                media.protocol = _WEBRTC_PROFILE_DEFAULT

            media.connection = ip

            # Add media-level ICE attributes
            media.ice_ufrag = ice_ufrag
            media.ice_pwd = ice_pwd

            # Add DTLS attributes
            media.fingerprint = fingerprint
            media.setup = "actpass"

            # Enable rtcp-mux (required for WebRTC)
            media.rtcp_mux = True
            media.rtcp_rsize = True

            # Add ICE candidate for the gateway's RTP relay address
            from src.sdp.parser import SDPCandidate
            candidate = SDPCandidate(
                foundation="1",
                component=1,
                transport="UDP",
                priority=2130706431,
                address=ip,
                port=media.port,
                candidate_type="host",
            )
            media.candidates = [candidate]

        return self._parser.serialize(session)

    def extract_codecs(self, sdp_text: str) -> list[dict[str, Any]]:
        """Extract codec information from an SDP for negotiation.

        Returns a list of dicts with codec details from the audio media.
        """
        session = self._parser.parse(sdp_text)
        codecs: list[dict[str, Any]] = []

        audio = session.audio_media
        if not audio:
            return codecs

        for codec in audio.codecs:
            codecs.append({
                "payload_type": codec.payload_type,
                "encoding_name": codec.encoding_name,
                "clock_rate": codec.clock_rate,
                "channels": codec.channels,
                "fmtp": codec.fmtp_params,
            })

        return codecs

    def rewrite_connection(
        self, sdp_text: str, new_ip: str, new_port: int
    ) -> str:
        """Rewrite connection address and port in an SDP.

        Used when the RTP relay allocates specific ports for a session.
        """
        session = self._parser.parse(sdp_text)
        session.connection = new_ip

        for media in session.media:
            media.connection = new_ip
            media.port = new_port

        return self._parser.serialize(session)

    @staticmethod
    def _generate_ice_ufrag() -> str:
        """Generate a random ICE username fragment."""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return "".join(random.choices(chars, k=16))

    @staticmethod
    def _generate_ice_pwd() -> str:
        """Generate a random ICE password."""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
        return "".join(random.choices(chars, k=24))

    @staticmethod
    def _generate_placeholder_fingerprint() -> str:
        """Generate a placeholder DTLS fingerprint.

        In production, this would come from the actual DTLS certificate.
        """
        octets = [f"{random.randint(0, 255):02X}" for _ in range(32)]
        return "sha-256 " + ":".join(octets)
