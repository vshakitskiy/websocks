# Changelog

## Unreleased

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
