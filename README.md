# WebRTC-SIP Gateway

[![Build Status](https://img.shields.io/github/actions/workflow/status/kambidi1973/webrtc-sip-gateway/ci.yml?branch=main)](https://github.com/kambidi1973/webrtc-sip-gateway/actions)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](Dockerfile)

A high-performance **WebRTC to SIP gateway** that bridges browser-based WebRTC clients with enterprise SIP/VoIP infrastructure. Enables click-to-call, browser softphones, and web-based unified communications without requiring SIP endpoints on the client side.

## Architecture

```
                    WebRTC Clients
                   ┌──────┐ ┌──────┐
                   │Chrome│ │Safari│
                   └──┬───┘ └──┬───┘
                      │  WSS   │
              ┌───────▼────────▼───────┐
              │   WebSocket Signaling   │
              │   Server (JSEP/SDP)     │
              ├─────────────────────────┤
              │                         │
              │  ┌───────────────────┐  │
              │  │  SDP Translator   │  │
              │  │  WebRTC ↔ SIP     │  │
              │  └───────────────────┘  │
              │                         │
              │  ┌───────────────────┐  │
              │  │  Media Bridge     │  │
              │  │  SRTP ↔ RTP      │  │
              │  │  VP8/H.264 trans  │  │
              │  └───────────────────┘  │
              │                         │
              │  ┌───────────────────┐  │
              │  │  ICE/STUN/TURN    │  │
              │  │  NAT Traversal    │  │
              │  └───────────────────┘  │
              │                         │
              │  ┌───────────────────┐  │
              │  │  SIP Client       │  │
              │  │  (UAC/UAS)        │  │
              │  └───────────────────┘  │
              └────────────┬────────────┘
                           │ SIP/RTP
              ┌────────────▼────────────┐
              │   Enterprise SIP Infra   │
              │  ┌─────┐ ┌─────┐ ┌────┐ │
              │  │ PBX │ │ SBC │ │PSTN│ │
              │  └─────┘ └─────┘ └────┘ │
              └─────────────────────────┘
```

## Features

### Signaling
- **WebSocket Server** — Secure WSS endpoint for WebRTC JSEP signaling
- **SIP Client** — Full SIP UAC/UAS with INVITE, REGISTER, BYE, CANCEL, re-INVITE support
- **SDP Translation** — Automatic SDP munging between WebRTC and SIP formats (ICE candidates, DTLS-SRTP → SDES-SRTP, codec reordering)
- **Ofer/Answer Model** — Proper SDP offer/answer negotiation across both legs

### Media
- **SRTP/RTP Bridge** — Decrypt WebRTC DTLS-SRTP and re-encrypt or forward as RTP/SRTP to SIP side
- **Codec Transcoding** — Support for Opus ↔ G.711 μ-law/A-law, VP8 ↔ H.264 passthrough
- **DTMF Relay** — RFC 2833 telephone-event conversion between WebRTC and SIP
- **Media Recording** — Optional call recording with configurable storage backends

### NAT Traversal
- **Built-in STUN Server** — Lightweight STUN for candidate gathering
- **TURN Relay** — Integrated TURN server for symmetric NAT scenarios
- **ICE Processing** — Full ICE-lite implementation for reliable connectivity

### Operations
- **Multi-tenant** — Support multiple SIP registrations and routing rules
- **Load Balancing** — Horizontal scaling with Redis-backed session state
- **Health Monitoring** — Prometheus metrics, call quality stats, active session tracking
- **REST API** — Management API for configuration, monitoring, and call control

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ (asyncio) |
| WebSocket | websockets / aiohttp |
| SIP Stack | Custom async SIP (RFC 3261) |
| Media | GStreamer / aiortc |
| Config | YAML |
| Containerization | Docker / Docker Compose |
| Metrics | Prometheus |

## Quick Start

```bash
# Clone
git clone https://github.com/kambidi1973/webrtc-sip-gateway.git
cd webrtc-sip-gateway

# Docker (recommended)
docker-compose up -d

# Or run locally
pip install -r requirements.txt
python -m src.main --config config/gateway.yaml
```

## Configuration

```yaml
# config/gateway.yaml
websocket:
  host: "0.0.0.0"
  port: 8443
  ssl_cert: "/certs/cert.pem"
  ssl_key: "/certs/key.pem"

sip:
  transport: udp
  listen_port: 5060
  registrar:
    host: "sip.enterprise.com"
    port: 5060
    username: "gateway"
    password: "${SIP_PASSWORD}"
    expiry: 3600

media:
  rtp_port_range: [10000, 20000]
  codecs:
    audio: ["opus", "PCMU", "PCMA"]
    video: ["VP8", "H264"]
  srtp: true
  recording:
    enabled: false
    path: "/recordings"

ice:
  stun_server: "stun:stun.l.google.com:19302"
  turn_server: "turn:turn.example.com:3478"
  turn_username: "gateway"
  turn_credential: "${TURN_PASSWORD}"

routing:
  default_trunk: "enterprise-pbx"
  trunks:
    - name: "enterprise-pbx"
      host: "pbx.enterprise.com"
      port: 5060
      transport: udp
    - name: "pstn-breakout"
      host: "sbc.carrier.com"
      port: 5060
      transport: tls
      prefix: "+1"
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/sessions` | List active call sessions |
| GET | `/api/v1/sessions/{id}` | Session details with quality metrics |
| POST | `/api/v1/calls` | Initiate outbound call |
| DELETE | `/api/v1/calls/{id}` | Terminate call |
| GET | `/api/v1/registrations` | SIP registration status |
| GET | `/api/v1/health` | Gateway health check |
| GET | `/metrics` | Prometheus metrics |

## Use Cases

- **Click-to-Call** — Enable website visitors to call your contact center directly from the browser
- **Browser Softphone** — Full-featured softphone running in the browser, connecting to enterprise PBX
- **WebRTC Contact Center** — Agent interface running in browser, connected to SIP-based ACD
- **Unified Communications** — Bridge WebRTC-based UC clients with legacy SIP infrastructure

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a Pull Request

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

**Gopala Rao Kambidi** — Senior Technology Architect with 21+ years in VoIP, SIP, and real-time communications systems.
