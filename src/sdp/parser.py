"""
Full SDP Parser - RFC 4566

Parses Session Description Protocol messages into structured Python objects.
Supports all standard SDP fields and common WebRTC/SIP extensions including:
  - ICE attributes (ice-ufrag, ice-pwd, ice-options, candidate)
  - DTLS attributes (fingerprint, setup)
  - RTP/RTCP attributes (rtpmap, fmtp, rtcp-fb, ssrc, ssrc-group)
  - Media-level grouping (BUNDLE, mid)
  - Codec parameters and telephone-event

Reference: RFC 4566 (SDP), RFC 3264 (Offer/Answer), RFC 5245 (ICE),
           RFC 5764 (DTLS-SRTP), RFC 8866 (SDP revised)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SDPCandidate:
    """Parsed ICE candidate from SDP a=candidate line."""

    foundation: str = ""
    component: int = 1
    transport: str = "UDP"
    priority: int = 0
    address: str = ""
    port: int = 0
    candidate_type: str = "host"  # host, srflx, prflx, relay
    rel_addr: str = ""
    rel_port: int = 0
    extensions: dict[str, str] = field(default_factory=dict)

    @property
    def raw(self) -> str:
        """Reconstruct the candidate attribute value."""
        base = (
            f"{self.foundation} {self.component} {self.transport} "
            f"{self.priority} {self.address} {self.port} typ {self.candidate_type}"
        )
        if self.rel_addr:
            base += f" raddr {self.rel_addr} rport {self.rel_port}"
        for key, val in self.extensions.items():
            base += f" {key} {val}"
        return base


@dataclass
class SDPMediaCodec:
    """A codec described by rtpmap and optional fmtp."""

    payload_type: int = 0
    encoding_name: str = ""
    clock_rate: int = 0
    channels: int = 1
    fmtp_params: str = ""
    rtcp_feedback: list[str] = field(default_factory=list)

    @property
    def rtpmap_line(self) -> str:
        """Generate the a=rtpmap: line value."""
        base = f"{self.payload_type} {self.encoding_name}/{self.clock_rate}"
        if self.channels > 1:
            base += f"/{self.channels}"
        return base

    @property
    def name_normalized(self) -> str:
        """Normalized codec name for comparison (lowercase)."""
        return self.encoding_name.lower()


@dataclass
class SDPMediaDescription:
    """A single m= line and its associated attributes."""

    media_type: str = "audio"               # audio, video, application
    port: int = 0
    protocol: str = "RTP/AVP"               # RTP/AVP, RTP/SAVP, RTP/SAVPF, UDP/TLS/RTP/SAVPF
    formats: list[int] = field(default_factory=list)  # Payload type numbers
    connection: str = ""                     # c= line (IP address)

    # Codec details
    codecs: list[SDPMediaCodec] = field(default_factory=list)

    # Direction
    direction: str = "sendrecv"             # sendrecv, sendonly, recvonly, inactive

    # ICE attributes
    ice_ufrag: str = ""
    ice_pwd: str = ""
    ice_options: str = ""
    candidates: list[SDPCandidate] = field(default_factory=list)

    # DTLS attributes
    fingerprint: str = ""
    setup: str = ""                         # actpass, active, passive

    # RTCP
    rtcp: str = ""
    rtcp_mux: bool = False
    rtcp_rsize: bool = False

    # Grouping / identification
    mid: str = ""

    # SSRC
    ssrc: list[dict[str, str]] = field(default_factory=list)
    ssrc_group: str = ""

    # Extended attributes (key -> list of values)
    ext_maps: list[str] = field(default_factory=list)
    attributes: dict[str, list[str]] = field(default_factory=dict)

    # Bandwidth
    bandwidth: str = ""

    def get_codec(self, payload_type: int) -> SDPMediaCodec | None:
        """Find a codec by payload type."""
        for codec in self.codecs:
            if codec.payload_type == payload_type:
                return codec
        return None

    def get_codec_by_name(self, name: str) -> SDPMediaCodec | None:
        """Find a codec by encoding name (case-insensitive)."""
        name_lower = name.lower()
        for codec in self.codecs:
            if codec.name_normalized == name_lower:
                return codec
        return None


@dataclass
class SDPSession:
    """Complete parsed SDP session description."""

    # Session-level fields (RFC 4566 Section 5)
    version: int = 0                        # v=
    origin_username: str = "-"              # o= <username>
    origin_session_id: str = ""             # o= <sess-id>
    origin_session_version: str = ""        # o= <sess-version>
    origin_net_type: str = "IN"             # o= <nettype>
    origin_addr_type: str = "IP4"           # o= <addrtype>
    origin_address: str = "0.0.0.0"         # o= <unicast-address>
    session_name: str = "-"                 # s=
    session_info: str = ""                  # i= (optional)
    uri: str = ""                           # u= (optional)
    email: str = ""                         # e= (optional)
    phone: str = ""                         # p= (optional)
    connection: str = ""                    # c= (session-level)
    bandwidth: str = ""                     # b= (optional)
    timing: str = "0 0"                     # t=
    repeat: str = ""                        # r= (optional)

    # Session-level attributes
    ice_ufrag: str = ""
    ice_pwd: str = ""
    ice_options: str = ""
    ice_lite: bool = False
    fingerprint: str = ""
    setup: str = ""
    group: str = ""                         # a=group:BUNDLE
    msid_semantic: str = ""

    # Media descriptions
    media: list[SDPMediaDescription] = field(default_factory=list)

    # Raw attributes not captured elsewhere
    attributes: dict[str, list[str]] = field(default_factory=dict)

    @property
    def origin_line(self) -> str:
        """Reconstruct the o= line."""
        return (
            f"{self.origin_username} {self.origin_session_id} "
            f"{self.origin_session_version} {self.origin_net_type} "
            f"{self.origin_addr_type} {self.origin_address}"
        )

    @property
    def audio_media(self) -> SDPMediaDescription | None:
        """Return the first audio media description, or None."""
        for m in self.media:
            if m.media_type == "audio":
                return m
        return None

    @property
    def video_media(self) -> SDPMediaDescription | None:
        """Return the first video media description, or None."""
        for m in self.media:
            if m.media_type == "video":
                return m
        return None


class SDPParser:
    """Parses raw SDP text into structured SDPSession objects.

    Implements a line-by-line parser following RFC 4566 grammar.
    All SDP lines have the form <type>=<value> where <type> is a
    single character.
    """

    def parse(self, sdp_text: str) -> SDPSession:
        """Parse an SDP string into an SDPSession object.

        Args:
            sdp_text: Raw SDP text (lines separated by \\r\\n or \\n).

        Returns:
            Parsed SDPSession with all session and media-level attributes.
        """
        session = SDPSession()
        current_media: SDPMediaDescription | None = None

        lines = sdp_text.replace("\r\n", "\n").strip().split("\n")

        for line in lines:
            line = line.strip()
            if len(line) < 2 or line[1] != "=":
                continue

            line_type = line[0]
            value = line[2:]

            if line_type == "v":
                session.version = int(value)
            elif line_type == "o":
                self._parse_origin(session, value)
            elif line_type == "s":
                session.session_name = value
            elif line_type == "i":
                if current_media is None:
                    session.session_info = value
            elif line_type == "u":
                session.uri = value
            elif line_type == "e":
                session.email = value
            elif line_type == "p":
                session.phone = value
            elif line_type == "c":
                conn = self._parse_connection(value)
                if current_media is not None:
                    current_media.connection = conn
                else:
                    session.connection = conn
            elif line_type == "b":
                if current_media is not None:
                    current_media.bandwidth = value
                else:
                    session.bandwidth = value
            elif line_type == "t":
                session.timing = value
            elif line_type == "r":
                session.repeat = value
            elif line_type == "m":
                current_media = self._parse_media_line(value)
                session.media.append(current_media)
            elif line_type == "a":
                if current_media is not None:
                    self._parse_media_attribute(current_media, value)
                else:
                    self._parse_session_attribute(session, value)

        return session

    def _parse_origin(self, session: SDPSession, value: str) -> None:
        """Parse the o= line: <username> <sess-id> <sess-version> <nettype> <addrtype> <addr>."""
        parts = value.split()
        if len(parts) >= 6:
            session.origin_username = parts[0]
            session.origin_session_id = parts[1]
            session.origin_session_version = parts[2]
            session.origin_net_type = parts[3]
            session.origin_addr_type = parts[4]
            session.origin_address = parts[5]

    def _parse_connection(self, value: str) -> str:
        """Parse c= line and return the address. Format: IN IP4 <addr>."""
        parts = value.split()
        if len(parts) >= 3:
            return parts[2]
        return value

    def _parse_media_line(self, value: str) -> SDPMediaDescription:
        """Parse m= line: <media> <port> <proto> <fmt> ...

        Example: audio 49170 RTP/AVP 0 8 97 101
        """
        parts = value.split()
        media = SDPMediaDescription()

        if len(parts) >= 3:
            media.media_type = parts[0]
            media.port = int(parts[1])
            media.protocol = parts[2]
            if len(parts) > 3:
                for fmt in parts[3:]:
                    try:
                        media.formats.append(int(fmt))
                    except ValueError:
                        pass  # Non-numeric format (e.g., "webrtc-datachannel")

        return media

    def _parse_session_attribute(self, session: SDPSession, value: str) -> None:
        """Parse a session-level attribute (a= line)."""
        attr_name, _, attr_value = value.partition(":")

        if attr_name == "ice-ufrag":
            session.ice_ufrag = attr_value
        elif attr_name == "ice-pwd":
            session.ice_pwd = attr_value
        elif attr_name == "ice-options":
            session.ice_options = attr_value
        elif attr_name == "ice-lite":
            session.ice_lite = True
        elif attr_name == "fingerprint":
            session.fingerprint = attr_value
        elif attr_name == "setup":
            session.setup = attr_value
        elif attr_name == "group":
            session.group = attr_value
        elif attr_name == "msid-semantic":
            session.msid_semantic = attr_value
        else:
            session.attributes.setdefault(attr_name, []).append(attr_value)

    def _parse_media_attribute(
        self, media: SDPMediaDescription, value: str
    ) -> None:
        """Parse a media-level attribute (a= line within an m= block)."""
        attr_name, _, attr_value = value.partition(":")

        if attr_name == "rtpmap":
            self._parse_rtpmap(media, attr_value)
        elif attr_name == "fmtp":
            self._parse_fmtp(media, attr_value)
        elif attr_name == "rtcp-fb":
            self._parse_rtcp_fb(media, attr_value)
        elif attr_name == "ice-ufrag":
            media.ice_ufrag = attr_value
        elif attr_name == "ice-pwd":
            media.ice_pwd = attr_value
        elif attr_name == "ice-options":
            media.ice_options = attr_value
        elif attr_name == "candidate":
            media.candidates.append(self._parse_candidate(attr_value))
        elif attr_name == "fingerprint":
            media.fingerprint = attr_value
        elif attr_name == "setup":
            media.setup = attr_value
        elif attr_name == "mid":
            media.mid = attr_value
        elif attr_name == "rtcp":
            media.rtcp = attr_value
        elif attr_name == "rtcp-mux":
            media.rtcp_mux = True
        elif attr_name == "rtcp-rsize":
            media.rtcp_rsize = True
        elif attr_name == "ssrc":
            self._parse_ssrc(media, attr_value)
        elif attr_name == "ssrc-group":
            media.ssrc_group = attr_value
        elif attr_name == "extmap":
            media.ext_maps.append(attr_value)
        elif attr_name in ("sendrecv", "sendonly", "recvonly", "inactive"):
            media.direction = attr_name
        else:
            media.attributes.setdefault(attr_name, []).append(attr_value)

    def _parse_rtpmap(self, media: SDPMediaDescription, value: str) -> None:
        """Parse a=rtpmap:<payload> <encoding>/<clock>[/<channels>]."""
        parts = value.split(None, 1)
        if len(parts) < 2:
            return

        try:
            pt = int(parts[0])
        except ValueError:
            return

        encoding_parts = parts[1].split("/")
        encoding_name = encoding_parts[0]
        clock_rate = int(encoding_parts[1]) if len(encoding_parts) > 1 else 8000
        channels = int(encoding_parts[2]) if len(encoding_parts) > 2 else 1

        # Find or create codec entry
        codec = media.get_codec(pt)
        if codec is None:
            codec = SDPMediaCodec(payload_type=pt)
            media.codecs.append(codec)

        codec.encoding_name = encoding_name
        codec.clock_rate = clock_rate
        codec.channels = channels

    def _parse_fmtp(self, media: SDPMediaDescription, value: str) -> None:
        """Parse a=fmtp:<payload> <params>."""
        parts = value.split(None, 1)
        if len(parts) < 2:
            return

        try:
            pt = int(parts[0])
        except ValueError:
            return

        codec = media.get_codec(pt)
        if codec is None:
            codec = SDPMediaCodec(payload_type=pt)
            media.codecs.append(codec)

        codec.fmtp_params = parts[1]

    def _parse_rtcp_fb(self, media: SDPMediaDescription, value: str) -> None:
        """Parse a=rtcp-fb:<payload> <type> [<subtype>]."""
        parts = value.split(None, 1)
        if len(parts) < 2:
            return

        try:
            pt = int(parts[0])
        except ValueError:
            # Wildcard "*" applies to all codecs
            if parts[0] == "*":
                for codec in media.codecs:
                    codec.rtcp_feedback.append(parts[1])
            return

        codec = media.get_codec(pt)
        if codec:
            codec.rtcp_feedback.append(parts[1])

    def _parse_ssrc(self, media: SDPMediaDescription, value: str) -> None:
        """Parse a=ssrc:<ssrc-id> <attribute>:<value>."""
        parts = value.split(None, 1)
        if len(parts) >= 2:
            ssrc_id = parts[0]
            attr_name_val = parts[1]
            name, _, val = attr_name_val.partition(":")
            media.ssrc.append({"ssrc": ssrc_id, "attribute": name, "value": val})
        elif len(parts) == 1:
            media.ssrc.append({"ssrc": parts[0], "attribute": "", "value": ""})

    def _parse_candidate(self, value: str) -> SDPCandidate:
        """Parse a=candidate: line into an SDPCandidate.

        Format: foundation component transport priority addr port typ type
                [raddr rel-addr rport rel-port] [ext-name ext-value]*
        """
        candidate = SDPCandidate()
        parts = value.split()
        if len(parts) < 8:
            candidate.foundation = value
            return candidate

        candidate.foundation = parts[0]
        candidate.component = int(parts[1])
        candidate.transport = parts[2].upper()
        candidate.priority = int(parts[3])
        candidate.address = parts[4]
        candidate.port = int(parts[5])
        # parts[6] should be "typ"
        candidate.candidate_type = parts[7]

        # Parse remaining optional parameters
        i = 8
        while i < len(parts) - 1:
            key = parts[i]
            val = parts[i + 1]
            if key == "raddr":
                candidate.rel_addr = val
            elif key == "rport":
                candidate.rel_port = int(val)
            else:
                candidate.extensions[key] = val
            i += 2

        return candidate

    def serialize(self, session: SDPSession) -> str:
        """Serialize an SDPSession object back to SDP text.

        Args:
            session: The parsed SDP session to serialize.

        Returns:
            SDP text with \\r\\n line endings per RFC 4566.
        """
        lines: list[str] = []

        # Session-level fields
        lines.append(f"v={session.version}")
        lines.append(f"o={session.origin_line}")
        lines.append(f"s={session.session_name}")

        if session.session_info:
            lines.append(f"i={session.session_info}")
        if session.uri:
            lines.append(f"u={session.uri}")
        if session.email:
            lines.append(f"e={session.email}")
        if session.phone:
            lines.append(f"p={session.phone}")

        if session.connection:
            lines.append(f"c=IN IP4 {session.connection}")

        if session.bandwidth:
            lines.append(f"b={session.bandwidth}")

        lines.append(f"t={session.timing}")

        if session.repeat:
            lines.append(f"r={session.repeat}")

        # Session-level attributes
        if session.ice_lite:
            lines.append("a=ice-lite")
        if session.ice_ufrag:
            lines.append(f"a=ice-ufrag:{session.ice_ufrag}")
        if session.ice_pwd:
            lines.append(f"a=ice-pwd:{session.ice_pwd}")
        if session.ice_options:
            lines.append(f"a=ice-options:{session.ice_options}")
        if session.fingerprint:
            lines.append(f"a=fingerprint:{session.fingerprint}")
        if session.setup:
            lines.append(f"a=setup:{session.setup}")
        if session.group:
            lines.append(f"a=group:{session.group}")
        if session.msid_semantic:
            lines.append(f"a=msid-semantic:{session.msid_semantic}")

        for attr_name, values in session.attributes.items():
            for val in values:
                if val:
                    lines.append(f"a={attr_name}:{val}")
                else:
                    lines.append(f"a={attr_name}")

        # Media descriptions
        for m in session.media:
            formats_str = " ".join(str(f) for f in m.formats)
            lines.append(f"m={m.media_type} {m.port} {m.protocol} {formats_str}")

            if m.connection:
                lines.append(f"c=IN IP4 {m.connection}")

            if m.bandwidth:
                lines.append(f"b={m.bandwidth}")

            if m.mid:
                lines.append(f"a=mid:{m.mid}")

            if m.ice_ufrag:
                lines.append(f"a=ice-ufrag:{m.ice_ufrag}")
            if m.ice_pwd:
                lines.append(f"a=ice-pwd:{m.ice_pwd}")
            if m.ice_options:
                lines.append(f"a=ice-options:{m.ice_options}")

            for cand in m.candidates:
                lines.append(f"a=candidate:{cand.raw}")

            if m.fingerprint:
                lines.append(f"a=fingerprint:{m.fingerprint}")
            if m.setup:
                lines.append(f"a=setup:{m.setup}")

            if m.rtcp:
                lines.append(f"a=rtcp:{m.rtcp}")
            if m.rtcp_mux:
                lines.append("a=rtcp-mux")
            if m.rtcp_rsize:
                lines.append("a=rtcp-rsize")

            lines.append(f"a={m.direction}")

            # Codec details
            for codec in m.codecs:
                lines.append(f"a=rtpmap:{codec.rtpmap_line}")
                if codec.fmtp_params:
                    lines.append(f"a=fmtp:{codec.payload_type} {codec.fmtp_params}")
                for fb in codec.rtcp_feedback:
                    lines.append(f"a=rtcp-fb:{codec.payload_type} {fb}")

            # SSRC
            if m.ssrc_group:
                lines.append(f"a=ssrc-group:{m.ssrc_group}")
            for ssrc_entry in m.ssrc:
                ssrc_id = ssrc_entry["ssrc"]
                attr = ssrc_entry.get("attribute", "")
                val = ssrc_entry.get("value", "")
                if attr:
                    lines.append(f"a=ssrc:{ssrc_id} {attr}:{val}")
                else:
                    lines.append(f"a=ssrc:{ssrc_id}")

            # Extension maps
            for ext in m.ext_maps:
                lines.append(f"a=extmap:{ext}")

            # Remaining attributes
            for attr_name, values in m.attributes.items():
                for val in values:
                    if val:
                        lines.append(f"a={attr_name}:{val}")
                    else:
                        lines.append(f"a={attr_name}")

        return "\r\n".join(lines) + "\r\n"
