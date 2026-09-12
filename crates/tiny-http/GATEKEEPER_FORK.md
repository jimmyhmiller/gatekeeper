# Gatekeeper tiny_http fork

This directory vendors `tiny_http` 0.12.0. Gatekeeper needs one behavioral
change in `src/response.rs`: chunked responses use
`Encoder::with_flush_after_write` instead of `Encoder::new`.

Upstream's default encoder retains small writes until its 8 KiB buffer fills or
the response ends. That is valid for finite responses but breaks incremental
protocols such as Server-Sent Events. Flushing each producer read preserves
streaming latency. Socket writes remain blocking, so client backpressure still
propagates through `io::copy` to the native service's stream reader.

Keep the upstream license files with this fork. When updating tiny_http, rebase
this change and rerun Gatekeeper's native-function tests plus the harness's
`scripts/test_gatekeeper_function.sh` end-to-end SSE test.
