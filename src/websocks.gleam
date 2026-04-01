//// <script>
//// const docs = [
////   {
////     header: "Handshake",
////     functions: [
////       "magic_string",
////       "compute_accept",
////       "has_deflate",
////       "get_compression_extensions"
////     ]
////   },
////   {
////     header: "Masking",
////     functions: ["mask"]
////   },
////   {
////     header: "Context",
////     functions: ["create_context", "close_context"]
////   },
////   {
////     header: "Decoding",
////     functions: ["decode_frame", "decode_many_frames"]
////   },
////   {
////     header: "Encoding",
////     functions: [
////       "encode_text_frame",
////       "encode_binary_frame",
////       "encode_ping_frame",
////       "encode_pong_frame",
////       "encode_close_frame"
////     ]
////   },
////   {
////     header: "Resolving fragments",
////     functions: ["resolve_fragments"]
////   },
////   {
////     header: "Processing",
////     functions: ["process_incoming_frames"]
////   }
//// ]
////
//// const callback = () => {
////   const list = document.querySelector(".sidebar > ul:last-of-type")
////   const sortedLists = document.createDocumentFragment()
////   const sortedMembers = document.createDocumentFragment()
////
////   for (const section of docs) {
////     sortedLists.append((() => {
////       const node = document.createElement("h3")
////       node.append(section.header)
////       return node
////     })())
////     sortedMembers.append((() => {
////       const node = document.createElement("h2")
////       node.append(section.header)
////       return node
////     })())
////
////     const sortedList = document.createElement("ul")
////     sortedLists.append(sortedList)
////
////     const sortedFunctions = [...section.functions].sort()
////
////     for (const funcName of sortedFunctions) {
////       const href = `#${funcName}`
////       const member = document.querySelector(
////         `.member:has(h2 > a[href="${href}"])`
////       )
////       const sidebar = list.querySelector(`li:has(a[href="${href}"])`)
////       sortedList.append(sidebar)
////       sortedMembers.append(member)
////     }
////   }
////
////   document.querySelector(".sidebar").insertBefore(sortedLists, list)
////   document
////     .querySelector(".module-members:has(#module-values)")
////     .insertBefore(
////       sortedMembers,
////       document.querySelector("#module-values").nextSibling
////     )
//// }
////
//// document.readyState !== "loading"
////   ? callback()
////   : document.addEventListener(
////     "DOMContentLoaded",
////     callback,
////     { once: true }
////   )
//// </script>

// TODO:
// pub fn begin_fragmentation(...)
// pub fn continue_fragmentation(...)
// pub fn finish_fragmentation(...)

import gleam/bit_array
import gleam/bool
import gleam/bytes_tree
import gleam/crypto
import gleam/erlang/atom
import gleam/int
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

/// Generates a random WebSocket key for the `Sec-WebSocket-Key` header.
/// Used by clients during the handshake.
///
/// ### Example
///
/// ```gleam
/// websocks.websocket_key()
/// // => "dGhlIHNhbXBsZSBub25jZQ=="
/// ```
///
pub fn websocket_key() -> String {
  crypto.strong_random_bytes(16)
  |> bit_array.base64_encode(True)
}

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

/// Specifies whether the endpoint is a client or server. This determines how
/// compression parameters are interpreted.
///
pub type Role {
  /// Endpoint initiates connections
  ///
  Client
  /// Endpoint accepts connections
  ///
  Server
}

/// Negotiated compression extension parameters from the WebSocket handshake.
/// These parameters control per-message-deflate compression behavior. Obtained
/// by calling `get_compression_extensions` on the `Sec-WebSocket-Extensions`
/// header value.
///
pub type CompressionExtensions {
  CompressionExtensions(
    /// Client does not use context takeover
    ///
    client_no_context_takeover: Bool,
    /// Client's maximum LZ77 window size for compression
    ///
    client_max_window_bits: Option(Int),
    /// Server does not use context takeover
    ///
    server_no_context_takeover: Bool,
    /// Server's maximum LZ77 window size for compression
    ///
    server_max_window_bits: Option(Int),
  )
}

const default_extensions = CompressionExtensions(
  client_no_context_takeover: False,
  client_max_window_bits: None,
  server_no_context_takeover: False,
  server_max_window_bits: None,
)

/// Parses compression extension parameters from the handshake extension list.
/// Extracts context takeover settings as well as window bits.
///
/// ### Example
///
/// ```gleam
/// let extensions = [
///   "permessage-deflate",
///   "client_no_context_takeover",
///   "client_max_window_bits=15",
/// ]
///
/// websocks.get_compression_extensions(extensions)
/// // => CompressionExtensions(
/// //      client_no_context_takeover: True,
/// //      client_max_window_bits: Some(15),
/// //      server_no_context_takeover: False,
/// //      server_max_window_bits: None,
/// //    )
/// ```
///
pub fn get_compression_extensions(extensions: List(String)) {
  list.fold(extensions, default_extensions, fn(acc, extension) {
    case extension {
      "client_no_context_takeover" ->
        CompressionExtensions(..acc, client_no_context_takeover: True)
      "client_max_window_bits=" <> bits -> {
        let client_max_window_bits = option.from_result(int.parse(bits))
        CompressionExtensions(..acc, client_max_window_bits:)
      }
      "server_no_context_takeover" ->
        CompressionExtensions(..acc, server_no_context_takeover: True)
      "server_max_window_bits=" <> bits -> {
        let server_max_window_bits = option.from_result(int.parse(bits))
        CompressionExtensions(..acc, server_max_window_bits:)
      }
      _ -> acc
    }
  })
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

@external(erlang, "crypto", "exor")
fn exor(bin1: BitArray, bin2: BitArray) -> BitArray

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
    inflate_window_bits: Int,
    deflate_context: CompressionContext,
    deflate_window_bits: Int,
    reset_on_compress: Bool,
    reset_on_decompress: Bool,
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

fn init_compression(
  reset_on_compress: Bool,
  reset_on_decompress: Bool,
  deflate_window_bits: Int,
  inflate_window_bits: Int,
) -> Compression {
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

  Enabled(
    inflate_context:,
    inflate_window_bits:,
    deflate_context:,
    deflate_window_bits:,
    reset_on_compress:,
    reset_on_decompress:,
  )
}

fn compress(state: Compression, payload: BitArray) -> BitArray {
  case state {
    Disabled -> payload
    Enabled(deflate_context:, reset_on_compress:, ..) -> {
      let compressed =
        do_deflate(deflate_context, <<payload:bits>>, Sync)
        |> bytes_tree.to_bit_array()

      let size = bit_array.byte_size(compressed) - 4
      let compressed = case compressed {
        <<compressed:bytes-size(size), 0x00, 0x00, 0xff, 0xff>> -> compressed
        _ -> compressed
      }

      case reset_on_compress {
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
    Enabled(inflate_context:, reset_on_decompress:, ..) -> {
      let decompressed =
        do_inflate(inflate_context, <<payload:bits, 0x00, 0x00, 0xff, 0xff>>)
        |> bytes_tree.to_bit_array()

      case reset_on_decompress {
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

/// Creates a new context with optional compression settings and role
/// specification. The role parameter determines how compression parameters are
/// interpreted.
///
/// ### Example
///
/// ```gleam
/// let extensions = websocks.get_compression_extensions([
///   "permessage-deflate",
///   "client_no_context_takeover",
/// ])
///
/// websocks.create_context(Some(extensions), websocks.Client)
/// // => Context
/// ```
///
pub fn create_context(
  extensions: Option(CompressionExtensions),
  role: Role,
) -> Context {
  case extensions {
    Some(CompressionExtensions(
      client_no_context_takeover:,
      client_max_window_bits:,
      server_no_context_takeover:,
      server_max_window_bits:,
    )) -> {
      let #(reset_on_compress, reset_on_decompress) = case role {
        Client -> #(client_no_context_takeover, server_no_context_takeover)
        Server -> #(server_no_context_takeover, client_no_context_takeover)
      }

      let client_max_window_bits =
        option.map(client_max_window_bits, int.negate) |> option.unwrap(-15)
      let server_max_window_bits =
        option.map(server_max_window_bits, int.negate) |> option.unwrap(-15)

      let #(deflate_window_bits, inflate_window_bits) = case role {
        Client -> #(client_max_window_bits, server_max_window_bits)
        Server -> #(server_max_window_bits, client_max_window_bits)
      }

      init_compression(
        reset_on_compress,
        reset_on_decompress,
        deflate_window_bits,
        inflate_window_bits,
      )
      |> Empty(buffer: <<>>)
    }
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
  close_compression(context.compression)
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
  /// A control frame, controlling WebSocket connection.
  Control(control: Control)
}

/// Control frames that can appear in WebSocket communication.
pub type Control {
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
  /// No close reason.
  NoCloseReason
}

type InternalFrame {
  DecodedContinuation(payload: BitArray, compressed: Bool)
  DecodedText(payload: BitArray, compressed: Bool)
  DecodedBinary(payload: BitArray, compressed: Bool)
  DecodedControl(control: Control)
}

fn internal_frame_to_frame(
  internal_frame: InternalFrame,
  compression: Compression,
) -> Frame {
  case internal_frame {
    DecodedContinuation(payload:, compressed:) ->
      Continuation(payload: apply_decompression(
        compression,
        payload,
        compressed,
      ))

    DecodedText(payload:, compressed:) ->
      Text(payload: apply_decompression(compression, payload, compressed))

    DecodedBinary(payload:, compressed:) ->
      Binary(payload: apply_decompression(compression, payload, compressed))

    DecodedControl(control:) -> Control(control:)
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
/// // 0x81 : fin=1, rsv1-3=0, opcode=1
/// // 0x05 : mask=0, payload length=5
/// let frame = <<0x81, 0x05>>
/// // 0x48 0x65 0x6c 0x6c 0x6f : "Hello"
/// let payload = <<0x48, 0x65, 0x6c, 0x6c, 0x6f>>
///
/// // Let's assume we have this buffer:
/// let buffer = <<frame:bits, payload:bits, frame:bits>>
///
/// // The first frame is decoded, and the remaining binary is returned.
/// let decoded = websocks.decode_frame(buffer)
/// // => Ok(#(DecodedFrame, <<129, 5>>))
///
/// let assert Ok(#(_decoded_frame, rest)) = decoded
///
/// // Remaining binary is not enough to decode the frame.
/// websocks.decode_frame(rest)
/// // => Error(NotEnoughData(<<129, 5>>))
///
/// // If we add the remaining payload to the buffer, the frame is decoded.
/// websocks.decode_frame(<<rest:bits, payload:bits>>)
/// // => Ok(#(DecodedFrame, <<>>))
/// ```
///
pub fn decode_frame(
  data: BitArray,
  context: Context,
) -> Result(#(DecodedFrame, BitArray), DecodeError) {
  case data {
    <<
      fin:1,
      rsv1:1,
      rsv2:1,
      rsv3:1,
      opcode:size(4),
      mask:1,
      payload_length:size(7),
      rest:bits,
    >> -> {
      let compressed = rsv1 == 1

      use _nil <- result.try(case compressed, context.compression {
        True, Disabled(..) -> Error(InvalidFrame)
        _, _ -> Ok(Nil)
      })

      use <- bool.guard(rsv2 == 1 || rsv3 == 1, return: Error(InvalidFrame))

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
          case payload {
            <<>> -> Ok(DecodedControl(Close(NoCloseReason)))
            <<code:size(16), data:bits>> -> {
              use <- bool.guard(
                when: !bit_array.is_utf8(data),
                return: Error(InvalidFrame),
              )

              case code {
                1000 -> Ok(DecodedControl(Close(NormalClosure(data:))))
                1001 -> Ok(DecodedControl(Close(GoingAway(data:))))
                1002 -> Ok(DecodedControl(Close(ProtocolError(data:))))
                1003 -> Ok(DecodedControl(Close(UnsupportedData(data:))))
                1007 -> Ok(DecodedControl(Close(InvalidPayloadData(data:))))
                1008 -> Ok(DecodedControl(Close(PolicyViolation(data:))))
                1009 -> Ok(DecodedControl(Close(MessageTooBig(data:))))
                1010 -> Ok(DecodedControl(Close(MandatoryExtension(data:))))
                1011 -> Ok(DecodedControl(Close(InternalError(data:))))
                1012 -> Ok(DecodedControl(Close(ServiceRestart(data:))))
                1013 -> Ok(DecodedControl(Close(TryAgainLater(data:))))
                1014 -> Ok(DecodedControl(Close(BadGateway(data:))))
                1015 -> Ok(DecodedControl(Close(TLSHandshake(data:))))
                code if code >= 3000 && code <= 4999 ->
                  Ok(DecodedControl(Close(CustomCloseCode(code:, data:))))
                _ -> Error(InvalidFrame)
              }
            }
            _ -> Error(InvalidFrame)
          }
        }
        9 -> Ok(DecodedControl(Ping(payload:)))
        10 -> Ok(DecodedControl(Pong(payload:)))
        _ -> Error(InvalidFrame)
      }

      case fin, frame {
        1, Ok(DecodedControl(control:)) ->
          Ok(#(Resolved(Control(control:)), rest))
        0, Ok(DecodedControl(_)) -> Error(InvalidFrame)
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
/// // Let's assume we have this buffer:
/// let frames = <<
///   frame:bits,
///   payload1:bits,
///   frame:bits,
///   payload2:bits,
///   frame:bits,
/// >>
///
/// // The context is used to store the remaining bytes after decoding.
/// let context = websocks.create_context(None)
///
/// let decoded = websocks.decode_many_frames(frames, context)
/// // => Ok(#([DecodedFrame, DecodedFrame], Context: <<0x81, 0x04>>))
///
/// let assert Ok(#(_decoded_frames, updated_context)) = decoded
///
/// // We can try to decode the remaining frames using the updated context.
/// websocks.decode_many_frames(payload3, updated_context)
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
  case decode_frame(data, context) {
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
    Control(Ping(payload)) -> #(9, payload)
    Control(Pong(payload)) -> #(10, payload)
    Control(Close(reason)) -> {
      let payload = case reason {
        NoCloseReason -> <<>>
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
  encode_frame(
    Control(Ping(payload:)),
    final: True,
    compression: None,
    masking:,
  )
}

/// Encodes a pong frame with the given payload and mask.
pub fn encode_pong_frame(
  payload payload: BitArray,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(
    Control(Pong(payload:)),
    final: True,
    compression: None,
    masking:,
  )
}

/// Encodes a close frame with the given reason and mask.
pub fn encode_close_frame(
  reason reason: CloseReason,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(
    Control(Close(reason:)),
    final: True,
    compression: None,
    masking:,
  )
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
/// // Let's assume we have this buffer:
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
/// // We assume that the frames have been successfully decoded.
/// let assert Ok(#(decoded_frames, context)) =
///   websocks.decode_many_frames(frames, context)
///
/// // Resolve the decoded frames.
/// websocks.resolve_fragments(decoded_frames, context)
/// // => Ok(#([Text("Hello World!")], Context))
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
      let frame = Resolved(internal_frame_to_frame(frame, context.compression))
      do_resolve_fragments([frame, ..rest], context, resolved)
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

/// Represents an instruction, indicating whether to continue processing
/// more frames or stop. Used by the frame handler in `process_incoming_frames`
/// to control the processing flow.
pub type ResolveNext(state) {
  /// Continue processing more frames with the updated state.
  Continue(state: state)
  /// Stop processing frames and return the updated state. Remaining data will
  /// be stored in the context buffer for the next processing call.
  Stop(state: state)
}

/// Errors that can occur during the frame processing in
/// `process_incoming_frames`.
pub type ProcessError {
  /// Frame decoding failed with the given decode error.
  DecodeFailed(reason: DecodeError)
  /// Frame resolution failed with the given resolve error.
  ResolveFailed(reason: ResolveError)
}

/// Processes incoming WebSocket frames from the given data. This function
/// combines the context buffer with the new data, decodes frames, resolves
/// fragments, and calls the handler function for each resolved frame. The
/// handler returns `ResolveNext` to control the processing flow. If there's not
/// enough data to decode a complete frame, the remaining data is stored in the
/// context buffer for the next call.
///
/// ### Example
///
/// ```gleam
/// // 0x81 : fin=1, rsv1-3=0, opcode=1
/// // 0x05 : mask=0, payload length=5
/// let frame = <<0x81, 0x05>>
/// // 0x48 0x65 0x6c 0x6c 0x6f : "Hello"
/// let payload = <<0x48, 0x65, 0x6c, 0x6c, 0x6f>>
///
/// // let's assume we have this buffer:
/// let data = <<frame:bits, payload:bits, frame:bits>>
///
/// let context = websocks.create_context(None)
/// let initial_state = 0
///
/// // Handler that collects all text frames
/// let handler = fn(state, _context, frame) {
///   case frame {
///     websocks.Continuation(payload) ->
///       echo #("received continuation frame", payload)
///     websocks.Text(payload) -> echo #("received text frame", payload)
///     websocks.Binary(payload) -> echo #("received binary frame", payload)
///     websocks.Control(websocks.Ping(payload)) ->
///       echo #("received ping frame", payload)
///     websocks.Control(websocks.Pong(payload)) ->
///       echo #("received pong frame", payload)
///     websocks.Control(websocks.Close(reason)) ->
///       echo #(
///         "received close frame",
///         bit_array.from_string(string.inspect(reason)),
///       )
///   }
///
///   websocks.Continue(state + 1)
/// }
///
/// let processed =
///   websocks.process_incoming_frames(data, context, initial_state, handler)
///   // => #("received text frame", "Hello")
///
/// echo processed
/// // => Ok(#(1, context: <<0x81, 0x05>>))
/// ```
///
pub fn process_incoming_frames(
  data: BitArray,
  context: Context,
  state: state,
  handler: fn(state, Context, Frame) -> ResolveNext(state),
) {
  let data = <<context.buffer:bits, data:bits>>
  do_process_incoming_frames(data, context, state, handler)
}

fn do_process_incoming_frames(
  data: BitArray,
  context: Context,
  state: state,
  handler: fn(state, Context, Frame) -> ResolveNext(state),
) {
  case decode_frame(data, context) {
    Ok(#(decoded_frame, rest)) -> {
      let result =
        resolve_and_handle_single_frame(decoded_frame, context, state, handler)
      case result {
        Ok(#(Continue(new_state), new_context)) ->
          case rest {
            <<>> -> Ok(#(new_state, update_buffer(new_context, <<>>)))
            _ ->
              do_process_incoming_frames(rest, new_context, new_state, handler)
          }
        Ok(#(Stop(new_state), new_context)) ->
          Ok(#(new_state, update_buffer(new_context, rest)))
        Error(e) -> Error(ResolveFailed(e))
      }
    }
    Error(NotEnoughData(remaining)) ->
      Ok(#(state, update_buffer(context, remaining)))
    Error(e) -> Error(DecodeFailed(e))
  }
}

fn resolve_and_handle_single_frame(
  decoded_frame: DecodedFrame,
  context: Context,
  state: state,
  handler: fn(state, Context, Frame) -> ResolveNext(state),
) {
  case decoded_frame, context {
    Resolved(Text(payload:)), context ->
      case bit_array.is_utf8(payload) {
        True -> Ok(#(handler(state, context, Text(payload:)), context))
        False -> Error(NotUtf8)
      }

    Resolved(frame), context -> Ok(#(handler(state, context, frame), context))

    Complete(DecodedContinuation(..)), Empty(..) -> Error(OrphanedContinuation)

    Complete(frame), Empty(..) as context ->
      internal_frame_to_frame(frame, context.compression)
      |> Resolved
      |> resolve_and_handle_single_frame(context, state, handler)

    Incomplete(DecodedText(payload:, compressed:)), Empty(compression:, buffer:)
    ->
      Ok(#(
        Continue(state),
        Accumulating(Text, payload, compressed:, compression:, buffer:),
      ))

    Incomplete(DecodedBinary(payload:, compressed:)),
      Empty(compression:, buffer:)
    -> {
      Ok(#(
        Continue(state),
        Accumulating(Binary, payload, compressed:, compression:, buffer:),
      ))
    }

    Incomplete(DecodedContinuation(..)), Empty(..) ->
      Error(OrphanedContinuation)

    Incomplete(DecodedControl(..)), Empty(..) ->
      panic as "Incomplete(DecodedControl(..)) is not allowed"

    Incomplete(DecodedContinuation(payload:, compressed:)),
      Accumulating(accumulated_payload:, ..) as context
    -> {
      case compressed {
        // TODO: handle this in decode_frame function?
        True -> Error(CompressedContinuation)
        False ->
          Ok(#(
            Continue(state),
            Accumulating(..context, accumulated_payload: <<
              accumulated_payload:bits,
              payload:bits,
            >>),
          ))
      }
    }

    // Incomplete frames cannot be fragmented concurrently.
    Incomplete(..), Accumulating(..) -> Error(ConcurrentFragmentation)

    // Complete continuation completes fragmentation
    Complete(DecodedContinuation(payload:, compressed:)),
      Accumulating(..) as context
    -> {
      case compressed {
        // TODO: handle this in decode_frame function?
        True -> Error(CompressedContinuation)
        False -> {
          let complete_payload =
            apply_decompression(
              context.compression,
              <<context.accumulated_payload:bits, payload:bits>>,
              context.compressed,
            )

          let frame = context.frame_builder(complete_payload)
          let new_context = Empty(context.compression, context.buffer)

          resolve_and_handle_single_frame(
            Resolved(frame),
            new_context,
            state,
            handler,
          )
        }
      }
    }

    // Received complete frame when fragmentation is happening.
    Complete(..), Accumulating(..) -> Error(FragmentationInterrupted)
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
  case frame {
    Continuation(payload:) ->
      DecodedContinuation(payload:, compressed:)
      |> wrap_decoded_frame(final)
    Text(payload:) ->
      DecodedText(payload:, compressed:)
      |> wrap_decoded_frame(final)
    Binary(payload:) ->
      DecodedBinary(payload:, compressed:)
      |> wrap_decoded_frame(final)
    Control(control:) -> Resolved(Control(control:))
  }
}

fn wrap_decoded_frame(internal: InternalFrame, final: Bool) -> DecodedFrame {
  case final {
    True -> Complete(internal)
    False -> Incomplete(internal)
  }
}

@internal
pub fn compress_payload(payload: BitArray) -> BitArray {
  compress(init_compression(False, False, -15, -15), payload)
}
