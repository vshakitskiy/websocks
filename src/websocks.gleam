// TODO:
// pub fn begin_fragmentation(...)
// pub fn continue_fragmentation(...)
// pub fn finish_fragmentation(...)

// TODO: comments for internal functions

import gleam/bit_array
import gleam/bool
import gleam/bytes_tree
import gleam/crypto
import gleam/erlang/atom
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

// -----------------------------------------------------------------------------
// Handshake
// -----------------------------------------------------------------------------

/// Sequence of characters that is used to compute the `Sec-WebSocket-Accept`
/// header during the handshake.
/// 
pub const magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/// Computes the value of the `Sec-WebSocket-Accept` header during the handshake.
/// Requires `Sec-WebSocket-Key` header value to be present.
///
/// ### Example
/// 
/// ```gleam
/// websocks.compute_accept("dGhlIHNhbXBsZSBub25jZQ==")
/// // => "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
/// ```
/// 
pub fn compute_accept(key: String) -> String {
  string.append(key, magic_string)
  |> bit_array.from_string()
  |> crypto.hash(crypto.Sha1, _)
  |> bit_array.base64_encode(True)
}

/// Checks if the `permessage-deflate` extension is present in the list of
/// extensions.
///
/// ### Example
/// 
/// ```gleam
/// let extensions =
///    request.get_header(req, "sec-websocket-extensions")
///    |> result.map(string.split(_, ";"))
///    |> result.unwrap([])
/// // => ["permessage-deflate", "client_no_context_takeover"]
/// 
/// websocks.has_deflate(extensions)
/// // => True
/// ```
/// 
pub fn has_deflate(extensions: List(String)) -> Bool {
  list.any(extensions, fn(str) { str == "permessage-deflate" })
}

/// Context takeover settings. Disabling context takeover means the compression 
/// context is reset after each message, reducing memory overhead but making 
/// compression less effective for small, repetitive payloads.
///
pub type ContextTakeover {
  ContextTakeover(
    /// Indicates that the client does not want to use context takeover.
    no_client: Bool,
    /// Indicates that the server does not want to use context takeover.
    no_server: Bool,
  )
}

/// Extracts the client and server context takeover settings from the list of
/// extensions.
///
/// ### Example
/// 
/// ```gleam
/// let extensions =
///    request.get_header(req, "sec-websocket-extensions")
///    |> result.map(string.split(_, ";"))
///    |> result.unwrap([])
/// // => ["permessage-deflate", "client_no_context_takeover"]
/// 
/// websocks.get_context_takeovers(extensions)
/// // => ContextTakeover(no_client: True, no_server: False)
/// ```
/// 
pub fn get_context_takeovers(extensions: List(String)) -> ContextTakeover {
  let no_client_context_takeover =
    list.any(extensions, fn(str) { str == "client_no_context_takeover" })
  let no_server_context_takeover =
    list.any(extensions, fn(str) { str == "server_no_context_takeover" })
  ContextTakeover(
    no_client: no_client_context_takeover,
    no_server: no_server_context_takeover,
  )
}

// -----------------------------------------------------------------------------
// Masking
// -----------------------------------------------------------------------------

/// Masks the payload of any length using the provided mask.
///
/// ### Example
/// 
/// ```gleam
/// let payload = bit_array.from_string("Hello")
/// // Original: H(0x48) e(0x65) l(0x6c) l(0x6c) o(0x6f)
/// // Mask:     0x37     0xfa    0x21    0x3d    0x37
/// // Masked:   0x7f     0x9f    0x4d    0x51    0x58
/// websocks.mask(payload, <<0x37, 0xfa, 0x21, 0x3d>>)
/// // => <<0x7f, 0x9f, 0x4d, 0x51, 0x58>>
/// ```
/// 
pub fn mask(payload: BitArray, mask: BitArray) -> BitArray {
  let payload_length = bit_array.byte_size(payload)
  repeat_mask(mask, payload_length)
  |> exor(payload, _)
}

@external(erlang, "crypto", "exor")
fn exor(bin1: BitArray, bin2: BitArray) -> BitArray

fn repeat_mask(mask: BitArray, payload_length: Int) -> BitArray {
  let mask_length = bit_array.byte_size(mask)

  case payload_length {
    _ if payload_length <= mask_length ->
      bit_array.slice(mask, 0, payload_length)
      |> result.unwrap(<<>>)
    _ -> {
      let repeat = payload_length / mask_length
      let remainder = payload_length % mask_length

      let base = copy(mask, repeat)

      case remainder {
        0 -> base
        n -> {
          let partial = bit_array.slice(mask, 0, n) |> result.unwrap(<<>>)
          <<base:bits, partial:bits>>
        }
      }
    }
  }
}

@external(erlang, "binary", "copy")
fn copy(subject: BitArray, n: Int) -> BitArray

// -----------------------------------------------------------------------------
// Compression
// -----------------------------------------------------------------------------

type CompressionContext

type Compression {
  Disabled
  Enabled(
    inflate_context: CompressionContext,
    deflate_context: CompressionContext,
    no_client: Bool,
    no_server: Bool,
  )
}

type Flush {
  Sync
}

type Deflated {
  Deflated
}

type Default {
  Default
}

@external(erlang, "zlib", "open")
fn open_compression_context() -> CompressionContext

@external(erlang, "zlib", "inflateInit")
fn init_inflate(context: CompressionContext, window_bits: Int) -> atom.Atom

@external(erlang, "zlib", "deflateInit")
fn init_deflate(
  context: CompressionContext,
  level: Default,
  method: Deflated,
  window_bits: Int,
  mem_level: Int,
  strategy: Default,
) -> atom.Atom

@external(erlang, "zlib", "inflate")
fn do_inflate(
  context: CompressionContext,
  data: BitArray,
) -> bytes_tree.BytesTree

@external(erlang, "zlib", "deflate")
fn do_deflate(
  context: CompressionContext,
  data: BitArray,
  flush: Flush,
) -> bytes_tree.BytesTree

@external(erlang, "zlib", "inflateReset")
fn inflate_reset(context: CompressionContext) -> atom.Atom

@external(erlang, "zlib", "deflateReset")
fn deflate_reset(context: CompressionContext) -> atom.Atom

@external(erlang, "zlib", "close")
fn close_compression_context(context: CompressionContext) -> atom.Atom

const deflate_window_bits = -15

fn init_compression(no_client: Bool, no_server: Bool) -> Compression {
  let inflate_context = open_compression_context()
  init_inflate(inflate_context, deflate_window_bits)

  let deflate_context = open_compression_context()
  init_deflate(
    deflate_context,
    Default,
    Deflated,
    deflate_window_bits,
    8,
    Default,
  )

  Enabled(inflate_context:, deflate_context:, no_client:, no_server:)
}

fn compress(state: Compression, payload: BitArray) -> BitArray {
  case state {
    Disabled -> payload
    Enabled(_, deflate_context, _, no_server) -> {
      let compressed =
        do_deflate(deflate_context, payload, Sync)
        |> bytes_tree.to_bit_array()

      case no_server {
        True -> {
          deflate_reset(deflate_context)
          Nil
        }
        False -> Nil
      }

      compressed
    }
  }
}

fn decompress(state: Compression, payload: BitArray) -> BitArray {
  case state {
    Disabled -> payload
    Enabled(inflate_context, _, no_client, _) -> {
      let decompressed =
        do_inflate(inflate_context, payload) |> bytes_tree.to_bit_array()

      case no_client {
        True -> {
          inflate_reset(inflate_context)
          Nil
        }
        False -> Nil
      }

      decompressed
    }
  }
}

fn close_compression(state: Compression) -> Nil {
  case state {
    Disabled -> Nil
    Enabled(inflate_context:, deflate_context:, ..) -> {
      close_compression_context(inflate_context)
      close_compression_context(deflate_context)
      Nil
    }
  }
}

// -----------------------------------------------------------------------------
// Context
// -----------------------------------------------------------------------------

/// Context is the internal state of the WebSocket connection. It stores the 
/// remaining bytes from the decoding process, fragment accumulation and 
/// compression states. 
pub opaque type Context {
  Empty(compression: Compression, buffer: BitArray)
  Accumulating(
    compression: Compression,
    buffer: BitArray,
    frame_builder: fn(BitArray) -> Frame,
    accumulated_payload: BitArray,
    compressed: Bool,
  )
}

/// Creates a new context with the optional compression settings.
///
/// ### Example
/// 
/// ```gleam
/// websocks.create_context(
///   Some(websocks.ContextTakeover(no_client: True, no_server: False)),
/// )
/// // => Context
/// ```
/// 
pub fn create_context(compression: Option(ContextTakeover)) -> Context {
  case compression {
    Some(ContextTakeover(no_client, no_server)) ->
      Empty(compression: init_compression(no_client, no_server), buffer: <<>>)
    None -> Empty(compression: Disabled, buffer: <<>>)
  }
}

/// Frees the compression resources. Should be called when the context is no 
/// longer needed.
///
/// ### Example
/// 
/// ```gleam
/// websocks.close_context(context)
/// // => Nil
/// ```
/// 
pub fn close_context(context: Context) -> Nil {
  case context {
    Empty(compression, _buffer) -> close_compression(compression)
    Accumulating(..) -> Nil
  }
}

fn update_buffer(context: Context, data: BitArray) -> Context {
  case context {
    Empty(..) -> Empty(..context, buffer: data)
    Accumulating(..) -> Accumulating(..context, buffer: data)
  }
}

fn apply_compression(
  compression: Option(Compression),
  payload: BitArray,
) -> BitArray {
  case compression {
    Some(Enabled(..) as compression) -> compress(compression, payload)
    _ -> payload
  }
}

fn apply_decompression(
  compression: Compression,
  payload: BitArray,
  compressed: Bool,
) {
  case compressed {
    True -> decompress(compression, payload)
    False -> payload
  }
}

// -----------------------------------------------------------------------------
// Frames
// -----------------------------------------------------------------------------

/// Each variant corresponds to a type of WebSocket frame, carrying the 
/// appropriate payload.
pub type Frame {
  /// A continuation frame, used for fragmented messages.
  Continuation(payload: BitArray)
  /// A text frame, containing UTF-8 encoded payload.
  Text(payload: BitArray)
  /// A binary frame, containing arbitrary binary data.
  Binary(payload: BitArray)
  /// A ping control frame. Used for keepalive.
  Ping(payload: BitArray)
  /// A pong control frame. Response to ping.
  Pong(payload: BitArray)
  /// A close control frame. Contains the reason for closing if present.
  Close(reason: CloseReason)
}

/// Close reason codes, that can be used in the close control frame.
pub type CloseReason {
  /// The connection successfully completed its purpose and is closing normally.
  NormalClosure(data: BitArray)
  /// The endpoint is going away, either due to server shutdown or browser 
  /// navigation.
  GoingAway(data: BitArray)
  /// A WebSocket protocol violation was detected.
  ProtocolError(data: BitArray)
  /// The endpoint received data it cannot accept.
  UnsupportedData(data: BitArray)
  /// The message data doesn’t match the declared type.
  InvalidPayloadData(data: BitArray)
  /// Generic status for policy violations when no other code applies.
  PolicyViolation(data: BitArray)
  /// Message exceeds the maximum size the endpoint can handle.
  MessageTooBig(data: BitArray)
  /// The server encountered an unexpected condition preventing request 
  /// fulfillment.
  MandatoryExtension(data: BitArray)
  /// The server encountered unexpected error.
  InternalError(data: BitArray)
  /// Server is restarting.
  ServiceRestart(data: BitArray)
  /// Temporary server overload.
  TryAgainLater(data: BitArray)
  /// Gateway/proxy received invalid response.
  BadGateway(data: BitArray)
  /// TLS/SSL handshake failure.
  TLSHandshake(data: BitArray)
  /// Custom close codes for application-specific use cases.
  CustomCloseCode(code: Int, data: BitArray)
}

type InternalFrame {
  DecodedContinuation(payload: BitArray, compressed: Bool)
  DecodedText(payload: BitArray, compressed: Bool)
  DecodedBinary(payload: BitArray, compressed: Bool)
  DecodedPing(payload: BitArray)
  DecodedPong(payload: BitArray)
  DecodedClose(reason: CloseReason)
}

fn internal_frame_to_frame(
  internal_frame: InternalFrame,
  compression: Compression,
) -> Result(Frame, ResolveError) {
  case internal_frame {
    DecodedContinuation(payload:, compressed:) -> {
      Ok(
        Continuation(payload: apply_decompression(
          compression,
          payload,
          compressed,
        )),
      )
    }
    DecodedText(payload:, compressed:) -> {
      Ok(Text(payload: apply_decompression(compression, payload, compressed)))
    }
    DecodedBinary(payload:, compressed:) -> {
      Ok(Binary(payload: apply_decompression(compression, payload, compressed)))
    }
    DecodedPing(payload:) -> Ok(Ping(payload:))
    DecodedPong(payload:) -> Ok(Pong(payload:))
    DecodedClose(reason:) -> Ok(Close(reason:))
  }
}

// -----------------------------------------------------------------------------
// Decoding
// -----------------------------------------------------------------------------

/// The result of the decoding process. It contains the decoded 
/// complete/incomplete frame with possible compression applied.
pub opaque type DecodedFrame {
  Complete(InternalFrame)
  Incomplete(InternalFrame)
  Resolved(Frame)
}

/// Errors that can occur during the decoding process.
pub type DecodeError {
  /// The frame is invalid.
  InvalidFrame
  /// The data is not enough to decode the frame.
  NotEnoughData(data: BitArray)
}

/// Decodes a single frame from the given data. For decoding multiple frames 
/// it is recommended to use `decode_many_frames` instead.
/// 
/// ### Example
/// 
/// ```gleam
/// // Frame parts:
/// // 0x81 : fin=1, rsv1-3=0, opcode=1
/// // 0x05 : mask=0, payload length=5
/// let frame = <<0x81, 0x05>>
/// // 0x48 0x65 0x6c 0x6c 0x6f : "Hello"
/// let payload = <<0x48, 0x65, 0x6c, 0x6c, 0x6f>>
///
/// // Let's say we have this buffer:
/// let buffer = <<frame:bits, payload:bits, frame:bits>>
///
/// let decoded = websocks.decode_frame(buffer)
/// // => Ok(#(DecodedFrame, <<129, 5>>))
///
/// result.try(decoded, fn(decoded) { websocks.decode_frame(decoded.1) })
/// // => Error(NotEnoughData(<<129, 5>>))
/// ```
///  
pub fn decode_frame(
  data: BitArray,
) -> Result(#(DecodedFrame, BitArray), DecodeError) {
  case data {
    <<
      fin:1,
      rsv1:1,
      _rsv2:1,
      _rsv3:1,
      opcode:size(4),
      mask:1,
      payload_length:size(7),
      rest:bits,
    >> -> {
      let compressed = rsv1 == 1

      // Decoding payload length

      let extended_payload_length = case payload_length {
        126 -> Some(16)
        127 -> Some(64)
        _ -> None
      }

      use #(payload_length, rest) <- result.try(case extended_payload_length {
        Some(length) ->
          case rest {
            <<payload_length:size(length), rest:bits>> ->
              Ok(#(payload_length, rest))
            _ -> Error(NotEnoughData(data))
          }
        None -> Ok(#(payload_length, rest))
      })

      // Reading and unmasking the payload

      use #(payload, rest) <- result.try(case mask, rest {
        // Masked payload
        1, <<mask:bytes-size(4), payload:bytes-size(payload_length), rest:bits>>
        -> {
          let payload =
            repeat_mask(mask, payload_length)
            |> exor(payload, _)

          Ok(#(payload, rest))
        }
        1, _ -> Error(NotEnoughData(data))

        // Normal payload
        0, <<payload:bytes-size(payload_length), rest:bits>> ->
          Ok(#(payload, rest))
        0, _ -> Error(NotEnoughData(data))

        _, _ -> Error(InvalidFrame)
      })

      let frame = case opcode {
        0 -> Ok(DecodedContinuation(payload:, compressed:))
        1 -> Ok(DecodedText(payload:, compressed:))
        2 -> Ok(DecodedBinary(payload:, compressed:))
        8 -> {
          // TODO: Proper close code validation.
          case payload {
            <<1000:size(16), data:bits>> ->
              Ok(DecodedClose(NormalClosure(data:)))
            <<1001:size(16), data:bits>> -> Ok(DecodedClose(GoingAway(data:)))
            <<1002:size(16), data:bits>> ->
              Ok(DecodedClose(ProtocolError(data:)))
            <<1003:size(16), data:bits>> ->
              Ok(DecodedClose(UnsupportedData(data:)))
            <<1007:size(16), data:bits>> ->
              Ok(DecodedClose(InvalidPayloadData(data:)))
            <<1008:size(16), data:bits>> ->
              Ok(DecodedClose(PolicyViolation(data:)))
            <<1009:size(16), data:bits>> ->
              Ok(DecodedClose(MessageTooBig(data:)))
            <<1010:size(16), data:bits>> ->
              Ok(DecodedClose(MandatoryExtension(data:)))
            <<1011:size(16), data:bits>> ->
              Ok(DecodedClose(InternalError(data:)))
            <<1012:size(16), data:bits>> ->
              Ok(DecodedClose(ServiceRestart(data:)))
            <<1013:size(16), data:bits>> ->
              Ok(DecodedClose(TryAgainLater(data:)))
            <<1014:size(16), data:bits>> -> Ok(DecodedClose(BadGateway(data:)))
            <<1015:size(16), data:bits>> ->
              Ok(DecodedClose(TLSHandshake(data:)))
            <<code:size(16), data:bits>> ->
              Ok(DecodedClose(CustomCloseCode(code:, data:)))
            _ -> Error(InvalidFrame)
          }
        }
        9 -> Ok(DecodedPing(payload:))
        10 -> Ok(DecodedPong(payload:))
        _ -> Error(InvalidFrame)
      }

      case fin, frame {
        1, Ok(frame) -> Ok(#(Complete(frame), rest))
        0, Ok(frame) -> Ok(#(Incomplete(frame), rest))
        _, _ -> Error(InvalidFrame)
      }
    }
    _ -> Error(NotEnoughData(data))
  }
}

/// Decodes multiple frames from the given data until the buffer is empty or an 
/// error occurs. Returns the provided context with updated buffer.
/// 
/// ### Example
/// 
/// ```gleam
/// // Frame parts:
/// // 0x81 : fin=1, rsv1-3=0, opcode=1
/// // 0x04 : mask=0, payload length=4
/// let frame = <<0x81, 0x04>>
/// // 0x48 0x65 0x6c 0x6c : "Hell"
/// let payload1 = <<0x48, 0x65, 0x6c, 0x6c>>
/// // 0x6f 0x20 0x57 0x6f : "o Wo"
/// let payload2 = <<0x6f, 0x20, 0x57, 0x6f>>
/// // 0x72 0x6c 0x64 0x21 : "rld!"
/// let payload3 = <<0x72, 0x6c, 0x64, 0x21>>
/// 
/// // Let's say we have this buffer:
/// let frames = <<
///   frame:bits,
///   payload1:bits,
///   frame:bits,
///   payload2:bits,
///   frame:bits,
/// >>
///
/// // Context is used to store the remaining bytes after decoding.
/// let context = websocks.create_context(None)
/// 
/// let decoded = websocks.decode_many_frames(frames, context)
/// // => Ok(#([DecodedFrame, DecodedFrame], Context: <<0x81, 0x04>>))
/// 
/// result.try(decoded, fn(decoded) {
///   // We can try to decode the remaining frames using updated context.
///   websocks.decode_many_frames(payload3, decoded.1)
/// })
/// // => Ok(#([DecodedFrame], Context: <<>>))
/// ```
/// 
pub fn decode_many_frames(
  data: BitArray,
  context: Context,
) -> Result(#(List(DecodedFrame), Context), Nil) {
  do_decode_many_frames(<<context.buffer:bits, data:bits>>, context, [])
}

fn do_decode_many_frames(
  data: BitArray,
  context: Context,
  decoded_frames: List(DecodedFrame),
) -> Result(#(List(DecodedFrame), Context), Nil) {
  case decode_frame(data) {
    Ok(#(decoded_frame, <<>>)) ->
      Ok(#(
        list.reverse([decoded_frame, ..decoded_frames]),
        update_buffer(context, <<>>),
      ))
    Ok(#(decoded_frame, rest)) ->
      do_decode_many_frames(rest, context, [decoded_frame, ..decoded_frames])
    Error(NotEnoughData(data)) ->
      Ok(#(list.reverse(decoded_frames), update_buffer(context, data)))
    Error(InvalidFrame) -> Error(Nil)
  }
}

// -----------------------------------------------------------------------------
// Encoding
// -----------------------------------------------------------------------------

fn encode_frame(
  frame frame: Frame,
  final final: Bool,
  compression compression: Option(Compression),
  masking masking: Option(BitArray),
) -> BitArray {
  let #(opcode, payload) = case frame {
    Continuation(payload) -> #(0, payload)
    Text(payload) -> #(1, apply_compression(compression, payload))
    Binary(payload) -> #(2, apply_compression(compression, payload))
    Ping(payload) -> #(9, payload)
    Pong(payload) -> #(10, payload)
    Close(reason) -> {
      let payload = case reason {
        NormalClosure(data) -> <<1000:size(16), data:bits>>
        GoingAway(data) -> <<1001:size(16), data:bits>>
        ProtocolError(data) -> <<1002:size(16), data:bits>>
        UnsupportedData(data) -> <<1003:size(16), data:bits>>
        InvalidPayloadData(data) -> <<1007:size(16), data:bits>>
        PolicyViolation(data) -> <<1008:size(16), data:bits>>
        MessageTooBig(data) -> <<1009:size(16), data:bits>>
        MandatoryExtension(data) -> <<1010:size(16), data:bits>>
        InternalError(data) -> <<1011:size(16), data:bits>>
        ServiceRestart(data) -> <<1012:size(16), data:bits>>
        TryAgainLater(data) -> <<1013:size(16), data:bits>>
        BadGateway(data) -> <<1014:size(16), data:bits>>
        TLSHandshake(data) -> <<1015:size(16), data:bits>>
        CustomCloseCode(code, data) -> <<code:size(16), data:bits>>
      }

      #(8, payload)
    }
  }

  let payload_length = bit_array.byte_size(payload)

  let encoded_payload_length = case payload_length {
    _ if payload_length <= 125 -> payload_length
    _ if payload_length <= 65_535 -> 126
    _ -> 127
  }

  let extended_payload = case encoded_payload_length {
    126 -> <<payload_length:size(16)>>
    127 -> <<payload_length:size(64)>>
    _ -> <<>>
  }

  let #(mask_bit, mask, payload) = case masking {
    Some(mask_bytes) -> #(1, mask_bytes, mask(payload, mask_bytes))
    None -> #(0, <<>>, payload)
  }

  let rsv1 = case compression {
    Some(Enabled(..)) -> 1
    _ -> 0
  }

  let fin = case final {
    True -> 1
    False -> 0
  }

  <<
    fin:1,
    rsv1:1,
    0:2,
    opcode:4,
    mask_bit:1,
    encoded_payload_length:7,
    extended_payload:bits,
    mask:bits,
    payload:bits,
  >>
}

/// Encodes a text frame with the given payload, context and masking. If the
/// context has compression enabled, the payload will be compressed.
pub fn encode_text_frame(
  payload payload: BitArray,
  context context: Context,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(
    Text(payload:),
    final: True,
    compression: Some(context.compression),
    masking:,
  )
}

/// Encodes a binary frame with the given payload, context and mask. If the
/// context has compression enabled, the payload will be compressed.
pub fn encode_binary_frame(
  payload payload: BitArray,
  context context: Context,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(
    Binary(payload:),
    final: True,
    compression: Some(context.compression),
    masking:,
  )
}

/// Encodes a ping frame with the given payload and mask.
pub fn encode_ping_frame(
  payload payload: BitArray,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Ping(payload:), final: True, compression: None, masking:)
}

/// Encodes a pong frame with the given payload and mask.
pub fn encode_pong_frame(
  payload payload: BitArray,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Pong(payload:), final: True, compression: None, masking:)
}

/// Encodes a close frame with the given reason and mask.
pub fn encode_close_frame(
  reason reason: CloseReason,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Close(reason:), final: True, compression: None, masking:)
}

// -----------------------------------------------------------------------------
// Resolving fragments
// -----------------------------------------------------------------------------

/// Errors that can occur during the resolving fragments process.
pub type ResolveError {
  /// The complete text frame payload is not UTF-8.
  NotUtf8
  /// Receive continuation frame as the first frame in a fragmentation sequence.
  OrphanedContinuation
  /// The control frame is fragmented.
  ControlFrameFragmented
  /// Receive complete text/binary frame when resolving fragmented frame.
  FragmentationInterrupted
  /// Receive incomplete text/binary frame when resolving fragmented frame.
  ConcurrentFragmentation
  /// The continuation frame contains compressed flag (RSV1=1).
  CompressedContinuation
}

/// Resolves a list of decoded frames into a list of frames. If the context has 
/// compression enabled, the payload will be decompressed. Incomplete frames are
/// stored in the updated context until the fragmentation is complete. If 
/// returns an error, the protocol is violated, and the implementation should 
/// consider closing the WebSocket connection.
/// 
/// ### Example
/// 
/// ```gleam
/// // Frame parts:
/// // Incomplete text frame:
/// // 0x01 : fin=0, rsv1-3=0, opcode=1
/// // 0x04 : mask=0, payload length=4
/// let text = <<0x01, 0x04>>
/// // 0x00 : fin=0, rsv1-3=0, opcode=0
/// // 0x04 : mask=0, payload length=4
/// let continuation_complete = <<0x80, 0x04>>
/// // Complete continuation frame:
/// // 0x80 : fin=1, rsv1-3=0, opcode=0
/// // 0x04 : mask=0, payload length=4
/// let continuation_incomplete = <<0x00, 0x04>>
/// // 0x48 0x65 0x6c 0x6c : "Hell"
/// let payload1 = <<0x48, 0x65, 0x6c, 0x6c>>
/// // 0x6f 0x20 0x57 0x6f : "o Wo"
/// let payload2 = <<0x6f, 0x20, 0x57, 0x6f>>
/// // 0x72 0x6c 0x64 0x21 : "rld!"
/// let payload3 = <<0x72, 0x6c, 0x64, 0x21>>
///
/// // Let's say we have this buffer:
/// let frames = <<
///   text:bits,
///   payload1:bits,
///   continuation_incomplete:bits,
///   payload2:bits,
///   continuation_complete:bits,
///   payload3:bits,
/// >>
///
/// let context = websocks.create_context(None)
/// 
/// // We assume that the frames were successfully decoded.
/// let assert Ok(#(decoded_frames, context)) =
///   websocks.decode_many_frames(frames, context)
/// 
/// // Resolve the decoded frames
/// websocks.resolve_fragments(decoded_frames, context)
/// // => Ok(#([Text("Hello World!")], Context)
/// ```
/// 
pub fn resolve_fragments(
  decoded_frames: List(DecodedFrame),
  context: Context,
) -> Result(#(List(Frame), Context), ResolveError) {
  do_resolve_fragments(decoded_frames, context, [])
}

fn do_resolve_fragments(
  decoded_frames: List(DecodedFrame),
  context: Context,
  resolved: List(Frame),
) {
  case decoded_frames, context {
    // No more frames to process.
    [], context -> Ok(#(list.reverse(resolved), context))

    // Text frames must be UTF-8.
    [Resolved(Text(payload:)), ..rest], context -> {
      case bit_array.is_utf8(payload) {
        True ->
          do_resolve_fragments(rest, context, [Text(payload:), ..resolved])
        False -> Error(NotUtf8)
      }
    }
    // The rest resolved frame types can be freely added to the resolved list. 
    [Resolved(frame), ..rest], context ->
      do_resolve_fragments(rest, context, [frame, ..resolved])

    // Continuation frames cannot be the first frame in a fragmentation.
    [Complete(DecodedContinuation(..)), ..], Empty(..) ->
      Error(OrphanedContinuation)
    // Complete frames are considered resolved if there is no fragmentation 
    // happening.
    [Complete(frame), ..rest], Empty(..) as context -> {
      internal_frame_to_frame(frame, context.compression)
      |> result.try(fn(frame) {
        do_resolve_fragments([Resolved(frame), ..rest], context, resolved)
      })
    }

    // Incomplete text frame begins fragmentation of text frame.
    [Incomplete(DecodedText(payload:, compressed:)), ..rest],
      Empty(compression:, buffer:)
    ->
      do_resolve_fragments(
        rest,
        Accumulating(Text, payload, compressed:, compression:, buffer:),
        resolved,
      )
    // Incomplete binary frame begins fragmentation of binary frame.
    [Incomplete(DecodedBinary(payload:, compressed:)), ..rest],
      Empty(compression:, buffer:)
    ->
      do_resolve_fragments(
        rest,
        Accumulating(Binary, payload, compressed:, compression:, buffer:),
        resolved,
      )
    // Continuation frames cannot be the first frame in a fragmentation.
    [Incomplete(DecodedContinuation(..)), ..], Empty(..) ->
      Error(OrphanedContinuation)
    // Control frames cannot be fragmented.
    [Incomplete(..), ..], Empty(..) -> Error(ControlFrameFragmented)

    // Incomplete continuation frame continues fragmentation.
    [Incomplete(DecodedContinuation(payload:, compressed:)), ..rest],
      Accumulating(accumulated_payload:, ..) as context
    -> {
      use <- bool.guard(compressed, return: Error(CompressedContinuation))

      do_resolve_fragments(
        rest,
        Accumulating(..context, accumulated_payload: <<
          accumulated_payload:bits,
          payload:bits,
        >>),
        resolved,
      )
    }
    // Incomplete frames cannot be fragmented concurrently.
    [Incomplete(..), ..], Accumulating(..) -> Error(ConcurrentFragmentation)

    // Complete continuation frame completes fragmentation.
    [Complete(DecodedContinuation(payload:, compressed:)), ..rest],
      Accumulating(..) as context
    -> {
      use <- bool.guard(compressed, return: Error(CompressedContinuation))

      let payload =
        apply_decompression(
          context.compression,
          <<context.accumulated_payload:bits, payload:bits>>,
          context.compressed,
        )

      do_resolve_fragments(
        [Resolved(context.frame_builder(payload)), ..rest],
        Empty(context.compression, context.buffer),
        resolved,
      )
    }
    // Received complete frame when fragmentation is happening.
    [Complete(..), ..], Accumulating(..) -> Error(FragmentationInterrupted)
  }
}

// -----------------------------------------------------------------------------
// Testing
// -----------------------------------------------------------------------------
// NOTE: These functions are for internal use only, and are used in test 
// suites. Do NOT use them in your own code.

@internal
pub fn extract_accumulating_frame(context: Context) -> Result(Frame, Nil) {
  case context {
    Accumulating(frame_builder:, accumulated_payload:, ..) ->
      Ok(frame_builder(accumulated_payload))
    Empty(..) -> Error(Nil)
  }
}

@internal
pub fn extract_buffer(context: Context) -> BitArray {
  context.buffer
}

@internal
pub fn is_empty_context(context: Context) -> Bool {
  case context {
    Empty(..) -> True
    Accumulating(..) -> False
  }
}

@internal
pub fn to_decoded_frame(
  frame: Frame,
  final final: Bool,
  compressed compressed: Bool,
) -> DecodedFrame {
  let internal = case frame {
    Continuation(payload:) -> DecodedContinuation(payload:, compressed:)
    Text(payload:) -> DecodedText(payload:, compressed:)
    Binary(payload:) -> DecodedBinary(payload:, compressed:)
    Ping(payload:) -> DecodedPing(payload:)
    Pong(payload:) -> DecodedPong(payload:)
    Close(reason:) -> DecodedClose(reason:)
  }

  case final {
    True -> Complete(internal)
    False -> Incomplete(internal)
  }
}

@internal
pub fn compress_payload(payload: BitArray) -> BitArray {
  compress(init_compression(False, False), payload)
}
