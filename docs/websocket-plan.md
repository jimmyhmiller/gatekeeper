# WebSocket transport plan

SSE and WebSockets share connection lifetime concerns, but WebSockets are not a
streaming HTTP response. Gatekeeper should continue to own the wire protocol and
authentication rather than handing a raw socket to a native service.

## Boundary

Gatekeeper authenticates and routes the HTTP Upgrade request before any service
callback. It validates the RFC 6455 handshake, negotiates an explicitly allowed
subprotocol, parses and writes frames, enforces masking and size limits, handles
ping/pong and close frames, and owns socket timeouts.

The next ABI revision adds a distinct WebSocket response kind and session
callbacks. The native service owns an opaque session pointer, while Gatekeeper
owns the connection:

```c
GkWsAction gk_ws_open(const GkRequest*, GkWsSession**);
GkWsAction gk_ws_message(GkWsSession*, const GkWsMessage*);
GkWsAction gk_ws_poll(GkWsSession*, uint64_t timeout_ms);
void gk_ws_close(GkWsSession*, uint16_t code, const uint8_t*, size_t);
void gk_ws_free(GkWsSession*);
```

Actions are bounded, function-owned messages that Gatekeeper copies and frees.
`poll` lets a model or background worker produce outbound messages even when the
client is idle. Gatekeeper applies backpressure by not polling for more output
while a prior frame is blocked. Every session receives one close notification
and one free call, including protocol errors and abrupt disconnects. The loaded
library remains pinned by the live session.

## Initial scope

- HTTP/1.1 Upgrade only; no RFC 8441 extended CONNECT initially.
- Text and binary messages, ping/pong, and close.
- Fragmented inbound frames are reassembled up to a configured message limit.
- No per-message compression in the first version.
- Origin policy and allowed subprotocols are route configuration, default deny.
- Existing bearer/cookie authentication occurs before the `101` response.
- Rate limits cover both handshakes and concurrent live sessions.

## Why this is separate from ABI v3 streaming

ABI v3 is a pull-only response body, which maps directly to SSE and downloads.
A WebSocket is bidirectional and message-framed. Treating it as two byte streams
would lose control-frame semantics, message boundaries, close codes, and a clear
owner for protocol validation. The two transports can share internal session
accounting and cancellation primitives without sharing an unsafe wire contract.
