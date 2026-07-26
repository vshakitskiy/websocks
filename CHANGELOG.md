# Changelog

## 4.0.0 - 27.07.26

- Replace `process_incoming_frames` with `push_data` and `next_frame`, which return frames instead of taking a handler
- Add `Decoded` type with `MoreData` and `Decoded` variants
- Remove `ResolveNext`, `Continue` and `Stop`
- Remove `decode_many_frames` and `resolve_fragments`, leaving a single fragmentation state machine
- `decode_frame` and `DecodedFrame` are no longer public
- `has_deflate` and `get_compression_extensions` now take the raw `Sec-WebSocket-Extensions` header value instead of a pre-split list
- Fix extension parsing to trim whitespace, so `permessage-deflate; client_max_window_bits=10` no longer parses as no extensions at all
- Extension names and parameters are now matched case insensitively
- Replace the `CloseReason` variants with a `CloseCode` type, and `CloseReason(code:, reason:)`
- Close frame reasons are now `String` rather than `BitArray`
- Replace `CustomCloseCode` with `ApplicationCode`
- Remove `TLSHandshake`, as 1015 must never be sent on the wire
- Remove `ControlFrameFragmented` and `CompressedContinuation`, both now rejected while decoding
- Add `Limits`, `default_limits` and `with_limits` to cap how much a peer can make an endpoint buffer
- Add `FrameTooLarge` to `DecodeError`
- Add `MessageTooLarge` and `DecompressionFailed` to `ResolveError`
- Add validation on masking direction: client frames must be masked and server frames must not be
- Add validation on control frame size, which must not exceed 125 bytes
- Add validation on close code 1015, which is reserved for local use
- Add validation on payload length encoding, which must use the minimal number of bytes
- Add validation on 64 bit payload lengths, whose most significant bit must be zero
- Add validation on RSV1 for continuation frames, which only the first frame of a message may set
- Frames declaring more than `max_frame_size` are rejected before their payload is read, bounding the buffer
- Fragmented messages are rejected once they accumulate past `max_message_size`
- Inflate output is now bounded with `zlib:safeInflate`, so a small frame can no longer expand without limit
- `mask` with an empty key returns the payload untouched instead of crashing
- Expand the mask key by doubling rather than `binary:copy`, around 5x faster on large payloads
- Validate UTF-8 through `unicode:bin_is_7bit` with a `unicode:characters_to_binary` fallback, around 8x faster on ASCII text
- Accumulate fragments as a list and join once, instead of rebuilding the message per fragment
- Skip prepending the context buffer when it is empty
- Fragmented control frames are unrepresentable rather than asserted against, removing the last `panic`

## 3.0.1 - 01.04.26

- Use inflate window bits instead of deflate for inflate context.

## 3.0.0 - 01.04.26

- `create_context` now requires `Role` parameter
- Replace `ContextTakeover` with `CompressionExtensions` type
- Replace `get_context_takeovers` with `get_compression_extensions`
- Add window bits support
- Add `websocket_key` function for client handshake
- Fix compression to work correctly for both client and server endpoints
- Compression window bits are now configurable

## 2.0.0 - 06.11.2025

- Compression handles closing bytes
- Control frames are separated with `Control` type
- Add new `NoCloseReason` variant for `CloseReason`
- `decode_frame` now has context as an argument to track if compression is enabled
- Add validation on reserved flags (RSV2, RSV3)
- Add validation on invalid RSV1 flag
- Refactor close frames decoding
- Add validation on FIN flag for control frames
- Internal frame-to-frame function now returns the `Frame` type.
- Add `process_incoming_frames` function, alongside with `ResolveNext` & `ProcessError` types.


## 1.0.0 - 05.11.2025

- 🎉 First release!
