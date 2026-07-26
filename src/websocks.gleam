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
////     functions: ["create_context", "with_limits", "close_context"]
////   },
////   {
////     header: "Decoding",
////     functions: ["push_data", "next_frame"]
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

@external(erlang, "websocks_ffi", "is_utf8")
fn is_utf8(payload: BitArray) -> Bool

@external(erlang, "websocks_ffi", "to_string")
fn to_string(payload: BitArray) -> Result(String, Nil)

// -----------------------------------------------------------------------------
// Handshake
// -----------------------------------------------------------------------------

/// Sequence of characters that is used to compute the `Sec-WebSocket-Accept`
/// header during the handshake.
///
pub const magic_string: String = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

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

/// Splits a `Sec-WebSocket-Extensions` header value into its tokens. Offers are
/// separated by commas and parameters by semicolons, and either may be padded
/// with whitespace, which is why splitting the header belongs here rather than in
/// the caller.
///
fn extension_tokens(header: String) -> List(String) {
  header
  |> string.replace(",", ";")
  |> string.split(";")
  |> list.filter_map(fn(token) {
    case string.trim(token) {
      "" -> Error(Nil)
      token -> Ok(string.lowercase(token))
    }
  })
}

/// Checks whether a `Sec-WebSocket-Extensions` header value offers
/// `permessage-deflate`.
///
/// ### Example
///
/// ```gleam
/// let header =
///   request.get_header(req, "sec-websocket-extensions")
///   |> result.unwrap("")
/// // => "permessage-deflate; client_no_context_takeover"
///
/// websocks.has_deflate(header)
/// // => True
/// ```
///
pub fn has_deflate(header: String) -> Bool {
  extension_tokens(header)
  |> list.contains("permessage-deflate")
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

const default_extensions: CompressionExtensions = CompressionExtensions(
  client_no_context_takeover: False,
  client_max_window_bits: None,
  server_no_context_takeover: False,
  server_max_window_bits: None,
)

/// Parses compression extension parameters out of a `Sec-WebSocket-Extensions`
/// header value. Extracts context takeover settings as well as window bits.
///
/// Note that a header offering several alternatives is read as one set of
/// parameters rather than as competing offers to choose between.
///
/// ### Example
///
/// ```gleam
/// let header =
///   "permessage-deflate; client_no_context_takeover; client_max_window_bits=15"
///
/// websocks.get_compression_extensions(header)
/// // => CompressionExtensions(
/// //      client_no_context_takeover: True,
/// //      client_max_window_bits: Some(15),
/// //      server_no_context_takeover: False,
/// //      server_max_window_bits: None,
/// //    )
/// ```
///
pub fn get_compression_extensions(header: String) -> CompressionExtensions {
  list.fold(extension_tokens(header), default_extensions, fn(acc, token) {
    case token {
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
      _token -> acc
    }
  })
}

// -----------------------------------------------------------------------------
// Masking
// -----------------------------------------------------------------------------

/// Masks the payload of any length using the provided mask. Masking is its own
/// inverse, so this unmasks too. A mask key of no bytes leaves the payload alone.
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
  case bit_array.byte_size(mask) {
    // `exor` needs operands of equal length, and an empty key can never be
    // expanded to reach one.
    0 -> payload
    _mask_length ->
      repeat_mask(mask, bit_array.byte_size(payload))
      |> exor(payload, _)
  }
}

fn repeat_mask(mask: BitArray, payload_length: Int) -> BitArray {
  case bit_array.byte_size(mask) {
    mask_length if mask_length >= payload_length ->
      bit_array.slice(mask, 0, payload_length)
      |> result.unwrap(<<>>)
    _mask_length -> repeat_mask(<<mask:bits, mask:bits>>, payload_length)
  }
}

@external(erlang, "crypto", "exor")
fn exor(bin1: BitArray, bin2: BitArray) -> BitArray

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

@external(erlang, "websocks_ffi", "inflate_limited")
fn inflate_limited(
  context: CompressionContext,
  data: BitArray,
  limit: Int,
) -> Result(BitArray, Nil)

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
  init_inflate(inflate_context, inflate_window_bits)

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

fn decompress(
  state: Compression,
  payload: BitArray,
  limit: Int,
) -> Result(BitArray, Nil) {
  case state {
    Disabled -> Ok(payload)
    Enabled(inflate_context:, reset_on_decompress:, ..) -> {
      let decompressed =
        inflate_limited(
          inflate_context,
          <<payload:bits, 0x00, 0x00, 0xff, 0xff>>,
          limit,
        )

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

/// Caps on how much data a peer can make this endpoint hold at once. Without
/// them a peer can declare an arbitrarily large frame, or fragment a single
/// message indefinitely, and exhaust memory.
///
pub type Limits {
  Limits(
    /// Largest payload a single frame may declare.
    ///
    max_frame_size: Int,
    /// Largest payload a fragmented message may accumulate to.
    ///
    max_message_size: Int,
  )
}

/// 16 MiB per frame, 64 MiB per reassembled message. Use `with_limits` function
/// to override the limits.
///
pub const default_limits: Limits = Limits(
  max_frame_size: 16_777_216,
  max_message_size: 67_108_864,
)

type Fragmentation {
  NotFragmented
  Fragmenting(
    frame_builder: fn(BitArray) -> Frame,
    accumulated_payload: List(BitArray),
    accumulated_size: Int,
    compressed: Bool,
  )
}

/// Context is the internal state of the WebSocket connection. It stores the
/// remaining bytes from the decoding process, fragment accumulation and
/// compression states.
pub opaque type Context {
  Context(
    role: Role,
    limits: Limits,
    compression: Compression,
    buffer: BitArray,
    fragmentation: Fragmentation,
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
  let compression = case extensions {
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
    }
    None -> Disabled
  }

  Context(
    role:,
    limits: default_limits,
    compression:,
    buffer: <<>>,
    fragmentation: NotFragmented,
  )
}

/// Replaces the context's buffering limits. Call before any frames are 
/// processed.
///
/// ### Example
///
/// ```gleam
/// websocks.create_context(None, websocks.Server)
/// |> websocks.with_limits(websocks.Limits(
///   max_frame_size: 65_536,
///   max_message_size: 1_048_576,
/// ))
/// ```
///
pub fn with_limits(context: Context, limits: Limits) -> Context {
  Context(..context, limits:)
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
  Context(..context, buffer: data)
}

// Concatenating an empty buffer still copies the whole read, which costs more
// than decoding a small frame does.
fn prepend_buffer(context: Context, data: BitArray) -> BitArray {
  case context.buffer {
    <<>> -> data
    buffer -> <<buffer:bits, data:bits>>
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

fn join_fragments(fragments: List(BitArray)) -> BitArray {
  fragments
  |> list.reverse
  |> bit_array.concat
}

fn apply_decompression(
  compression: Compression,
  payload: BitArray,
  compressed: Bool,
  limit: Int,
) -> Result(BitArray, ResolveError) {
  case compressed {
    True ->
      decompress(compression, payload, limit)
      |> result.replace_error(DecompressionFailed)
    False -> Ok(payload)
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

/// Status codes that may appear in a close frame. 
/// 
/// The codes reserved for local use only, such as 1005, 1006 and 1015, are 
/// absent. They must never be sent, and receiving one is a protocol violation.
///
pub type CloseCode {
  /// The connection successfully completed its purpose and is closing normally.
  NormalClosure
  /// The endpoint is going away, either due to server shutdown or browser
  /// navigation.
  GoingAway
  /// A WebSocket protocol violation was detected.
  ProtocolError
  /// The endpoint received data it cannot accept.
  UnsupportedData
  /// The message data doesn’t match the declared type.
  InvalidPayloadData
  /// Generic status for policy violations when no other code applies.
  PolicyViolation
  /// Message exceeds the maximum size the endpoint can handle.
  MessageTooBig
  /// The server encountered an unexpected condition preventing request
  /// fulfillment.
  MandatoryExtension
  /// The server encountered unexpected error.
  InternalError
  /// Server is restarting.
  ServiceRestart
  /// Temporary server overload.
  TryAgainLater
  /// Gateway/proxy received invalid response.
  BadGateway
  /// An application-specific code, between 3000 and 4999.
  ApplicationCode(code: Int)
}

fn close_code_to_int(code: CloseCode) -> Int {
  case code {
    NormalClosure -> 1000
    GoingAway -> 1001
    ProtocolError -> 1002
    UnsupportedData -> 1003
    InvalidPayloadData -> 1007
    PolicyViolation -> 1008
    MessageTooBig -> 1009
    MandatoryExtension -> 1010
    InternalError -> 1011
    ServiceRestart -> 1012
    TryAgainLater -> 1013
    BadGateway -> 1014
    ApplicationCode(code:) -> code
  }
}

fn close_code_from_int(code: Int) -> Result(CloseCode, Nil) {
  case code {
    1000 -> Ok(NormalClosure)
    1001 -> Ok(GoingAway)
    1002 -> Ok(ProtocolError)
    1003 -> Ok(UnsupportedData)
    1007 -> Ok(InvalidPayloadData)
    1008 -> Ok(PolicyViolation)
    1009 -> Ok(MessageTooBig)
    1010 -> Ok(MandatoryExtension)
    1011 -> Ok(InternalError)
    1012 -> Ok(ServiceRestart)
    1013 -> Ok(TryAgainLater)
    1014 -> Ok(BadGateway)
    code if code >= 3000 && code <= 4999 -> Ok(ApplicationCode(code:))
    _code -> Error(Nil)
  }
}

/// Why the connection is closing. Close frame is allowed to carry neither code nor reason.
///
pub type CloseReason {
  /// A close frame with an empty payload.
  NoCloseReason
  /// A close frame carrying a status code and an optional description.
  CloseReason(code: CloseCode, reason: String)
}

// Three opcodes that may be fragmented.
type FragmentFrame {
  ContinuationFragment(payload: BitArray, compressed: Bool)
  TextFragment(payload: BitArray, compressed: Bool)
  BinaryFragment(payload: BitArray, compressed: Bool)
}

// What an opcode denotes, before `fin` decides whether the frame is complete.
type DecodedPayload {
  FragmentPayload(fragment: FragmentFrame)
  ControlPayload(control: Control)
}

fn fragment_to_frame(
  fragment: FragmentFrame,
  compression: Compression,
  limit: Int,
) -> Result(Frame, ResolveError) {
  let #(build, payload, compressed) = case fragment {
    ContinuationFragment(payload:, compressed:) -> #(
      Continuation,
      payload,
      compressed,
    )
    TextFragment(payload:, compressed:) -> #(Text, payload, compressed)
    BinaryFragment(payload:, compressed:) -> #(Binary, payload, compressed)
  }

  apply_decompression(compression, payload, compressed, limit)
  |> result.map(build)
}

// -----------------------------------------------------------------------------
// Decoding
// -----------------------------------------------------------------------------

/// The result of decoding one frame off the wire, before fragmentation is
/// resolved.
@internal
pub opaque type DecodedFrame {
  Complete(FragmentFrame)
  Incomplete(FragmentFrame)
  Resolved(Frame)
}

/// Errors that can occur during the decoding process.
pub type DecodeError {
  /// The frame is invalid.
  InvalidFrame
  /// The data is not enough to decode the frame.
  NotEnoughData(data: BitArray)
  /// The frame declares a payload larger than the context's `max_frame_size`.
  FrameTooLarge(length: Int, limit: Int)
}

// Decodes a single frame from the given data, leaving fragmentation unresolved.
fn decode_frame(
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
      masked:1,
      payload_length:size(7),
      rest:bits,
    >> -> {
      let compressed = rsv1 == 1

      use _nil <- result.try(case compressed, context.compression {
        True, Disabled(..) -> Error(InvalidFrame)
        _compressed, _compression -> Ok(Nil)
      })

      use <- bool.guard(rsv2 == 1 || rsv3 == 1, return: Error(InvalidFrame))

      // RSV1 marks a compressed message, so it belongs on the first frame only
      // and never on a continuation.
      use <- bool.guard(compressed && opcode == 0, return: Error(InvalidFrame))

      // Every client frame is masked and no server frame is.
      let misdirected_mask = case context.role, masked {
        Server, 0 -> True
        Client, 1 -> True
        _role, _masked -> False
      }
      use <- bool.guard(misdirected_mask, return: Error(InvalidFrame))

      // Control frames carry at most 125 bytes and are never fragmented. 
      let control = opcode >= 8
      use <- bool.guard(
        control && { payload_length > 125 || fin == 0 },
        return: Error(InvalidFrame),
      )

      use #(payload_length, rest) <- result.try(case payload_length {
        // The length must use the minimal number of bytes.
        126 ->
          case rest {
            <<extended:size(16), rest:bits>> if extended > 125 ->
              Ok(#(extended, rest))
            <<_extended:size(16), _rest:bits>> -> Error(InvalidFrame)
            _rest -> Error(NotEnoughData(data))
          }
        // The most significant bit of a 64 bit length must be zero.
        127 ->
          case rest {
            <<0:1, extended:size(63), rest:bits>> if extended > 65_535 ->
              Ok(#(extended, rest))
            <<_msb:1, _extended:size(63), _rest:bits>> -> Error(InvalidFrame)
            _rest -> Error(NotEnoughData(data))
          }
        _payload_length -> Ok(#(payload_length, rest))
      })

      // Rejecting before the payload is read keeps the buffer bounded. A peer
      // cannot make us hold more than one frame's worth of bytes.
      use <- bool.guard(
        payload_length > context.limits.max_frame_size,
        return: Error(FrameTooLarge(
          length: payload_length,
          limit: context.limits.max_frame_size,
        )),
      )

      use #(payload, rest) <- result.try(case masked, rest {
        // Masked payload
        1,
          <<
            mask_key:bytes-size(4),
            payload:bytes-size(payload_length),
            rest:bits,
          >>
        -> Ok(#(mask(payload, mask_key), rest))
        1, _rest -> Error(NotEnoughData(data))

        // Normal payload
        0, <<payload:bytes-size(payload_length), rest:bits>> ->
          Ok(#(payload, rest))
        0, _rest -> Error(NotEnoughData(data))

        _masked, _rest -> Error(InvalidFrame)
      })

      use decoded_payload <- result.try(case opcode {
        0 -> Ok(FragmentPayload(ContinuationFragment(payload:, compressed:)))
        1 -> Ok(FragmentPayload(TextFragment(payload:, compressed:)))
        2 -> Ok(FragmentPayload(BinaryFragment(payload:, compressed:)))
        8 ->
          case payload {
            <<>> -> Ok(ControlPayload(Close(NoCloseReason)))
            <<code:size(16), data:bits>> -> {
              use code <- result.try(
                close_code_from_int(code) |> result.replace_error(InvalidFrame),
              )
              use reason <- result.try(
                to_string(data) |> result.replace_error(InvalidFrame),
              )

              Ok(ControlPayload(Close(CloseReason(code:, reason:))))
            }
            // A one byte payload is neither absent nor a whole status code.
            _payload -> Error(InvalidFrame)
          }
        9 -> Ok(ControlPayload(Ping(payload:)))
        10 -> Ok(ControlPayload(Pong(payload:)))
        _opcode -> Error(InvalidFrame)
      })

      case fin, decoded_payload {
        1, ControlPayload(control:) -> Ok(#(Resolved(Control(control:)), rest))
        // Control frames carry no continuation, so they cannot be fragmented.
        _fin, ControlPayload(..) -> Error(InvalidFrame)
        1, FragmentPayload(fragment:) -> Ok(#(Complete(fragment), rest))
        _fin, FragmentPayload(fragment:) -> Ok(#(Incomplete(fragment), rest))
      }
    }
    _ -> Error(NotEnoughData(data))
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
        CloseReason(code:, reason:) -> {
          let code = close_code_to_int(code)
          <<code:size(16), reason:utf8>>
        }
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
  /// Receive complete text/binary frame when resolving fragmented frame.
  FragmentationInterrupted
  /// Receive incomplete text/binary frame when resolving fragmented frame.
  ConcurrentFragmentation
  /// The fragments accumulated past the context's `max_message_size`.
  MessageTooLarge(size: Int, limit: Int)
  /// The payload is not a valid deflate stream, or inflating it would exceed
  /// the context's `max_message_size`.
  DecompressionFailed
}

/// Errors that can occur in `next_frame`. Each means the peer has broken the
/// protocol and the connection should be closed.
///
pub type ProcessError {
  /// Frame decoding failed with the given decode error.
  DecodeFailed(reason: DecodeError)
  /// Frame resolution failed with the given resolve error.
  ResolveFailed(reason: ResolveError)
}

/// The outcome of decoding one frame with `next_frame`.
///
pub type Decoded {
  /// The buffer holds no further complete frame. Its leftover bytes are kept in
  /// the returned context, to be joined with the next read.
  ///
  MoreData(context: Context)
  /// A frame, with fragmentation reassembled and compression applied.
  ///
  Decoded(frame: Frame, context: Context)
}

/// Adds a read to the context's buffer, ready to be drained by `next_frame`.
///
pub fn push_data(context: Context, data: BitArray) -> Context {
  update_buffer(context, prepend_buffer(context, data))
}

/// Decodes the next frame from the context's buffer, resolving fragmentation and
/// decompression. Fragments are consumed internally, so `MoreData` always means
/// the connection needs another read rather than another call.
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
/// let context =
///   websocks.create_context(None, websocks.Client)
///   |> websocks.push_data(<<frame:bits, payload:bits, frame:bits>>)
///
/// let assert Ok(websocks.Decoded(frame:, context:)) =
///   websocks.next_frame(context)
/// // frame => Text(<<"Hello">>)
///
/// // The trailing header alone is not a whole frame, so it stays buffered.
/// websocks.next_frame(context)
/// // => Ok(MoreData(context))
/// ```
///
pub fn next_frame(context: Context) -> Result(Decoded, ProcessError) {
  case decode_frame(context.buffer, context) {
    Error(NotEnoughData(remaining)) ->
      Ok(MoreData(update_buffer(context, remaining)))
    Error(error) -> Error(DecodeFailed(error))

    Ok(#(decoded_frame, rest)) -> {
      let context = update_buffer(context, rest)

      case resolve_frame(decoded_frame, context) {
        Error(error) -> Error(ResolveFailed(error))
        Ok(#(Some(frame), context)) -> Ok(Decoded(frame:, context:))
        // A fragment carries no message on its own, so keep draining rather
        // than handing the caller a `MoreData` it cannot act on.
        Ok(#(None, context)) -> next_frame(context)
      }
    }
  }
}

fn resolve_frame(
  decoded_frame: DecodedFrame,
  context: Context,
) -> Result(#(Option(Frame), Context), ResolveError) {
  case decoded_frame, context.fragmentation {
    Resolved(Text(payload:)), _fragmentation ->
      case is_utf8(payload) {
        True -> Ok(#(Some(Text(payload:)), context))
        False -> Error(NotUtf8)
      }

    Resolved(frame), _fragmentation -> Ok(#(Some(frame), context))

    Complete(ContinuationFragment(..)), NotFragmented ->
      Error(OrphanedContinuation)

    Complete(fragment), NotFragmented -> {
      use frame <- result.try(fragment_to_frame(
        fragment,
        context.compression,
        context.limits.max_message_size,
      ))

      resolve_frame(Resolved(frame), context)
    }

    Incomplete(TextFragment(payload:, compressed:)), NotFragmented ->
      begin_fragmentation(context, Text, payload, compressed)

    Incomplete(BinaryFragment(payload:, compressed:)), NotFragmented ->
      begin_fragmentation(context, Binary, payload, compressed)

    Incomplete(ContinuationFragment(..)), NotFragmented ->
      Error(OrphanedContinuation)

    Incomplete(ContinuationFragment(payload:, ..)),
      Fragmenting(accumulated_payload:, accumulated_size:, ..) as fragmenting
    -> {
      let accumulated_size = accumulated_size + bit_array.byte_size(payload)
      use _nil <- result.try(check_message_size(context, accumulated_size))

      Ok(#(
        None,
        Context(
          ..context,
          fragmentation: Fragmenting(
            ..fragmenting,
            accumulated_payload: [payload, ..accumulated_payload],
            accumulated_size:,
          ),
        ),
      ))
    }

    // Incomplete frames cannot be fragmented concurrently.
    Incomplete(..), Fragmenting(..) -> Error(ConcurrentFragmentation)

    // Complete continuation completes fragmentation
    Complete(ContinuationFragment(payload:, ..)),
      Fragmenting(
        frame_builder:,
        accumulated_payload:,
        accumulated_size:,
        compressed:,
      )
    -> {
      let accumulated_size = accumulated_size + bit_array.byte_size(payload)
      use _nil <- result.try(check_message_size(context, accumulated_size))

      use complete_payload <- result.try(apply_decompression(
        context.compression,
        join_fragments([payload, ..accumulated_payload]),
        compressed,
        context.limits.max_message_size,
      ))

      resolve_frame(
        Resolved(frame_builder(complete_payload)),
        Context(..context, fragmentation: NotFragmented),
      )
    }

    // Received complete frame when fragmentation is happening.
    Complete(..), Fragmenting(..) -> Error(FragmentationInterrupted)
  }
}

fn check_message_size(
  context: Context,
  size: Int,
) -> Result(Nil, ResolveError) {
  case size > context.limits.max_message_size {
    True ->
      Error(MessageTooLarge(size:, limit: context.limits.max_message_size))
    False -> Ok(Nil)
  }
}

fn begin_fragmentation(
  context: Context,
  frame_builder: fn(BitArray) -> Frame,
  payload: BitArray,
  compressed: Bool,
) -> Result(#(Option(Frame), Context), ResolveError) {
  let accumulated_size = bit_array.byte_size(payload)
  use _nil <- result.try(check_message_size(context, accumulated_size))

  Ok(#(
    None,
    Context(
      ..context,
      fragmentation: Fragmenting(
        frame_builder:,
        accumulated_payload: [payload],
        accumulated_size:,
        compressed:,
      ),
    ),
  ))
}

// -----------------------------------------------------------------------------
// Testing
// -----------------------------------------------------------------------------
// NOTE: These functions are for internal use only, and are used in test
// suites. Do NOT use them in your own code.

@internal
pub fn extract_accumulating_frame(context: Context) -> Result(Frame, Nil) {
  case context {
    Context(
      fragmentation: Fragmenting(frame_builder:, accumulated_payload:, ..),
      ..,
    ) -> Ok(frame_builder(join_fragments(accumulated_payload)))
    Context(fragmentation: NotFragmented, ..) -> Error(Nil)
  }
}

@internal
pub fn extract_buffer(context: Context) -> BitArray {
  context.buffer
}

@internal
pub fn is_empty_context(context: Context) -> Bool {
  case context {
    Context(fragmentation: NotFragmented, ..) -> True
    Context(fragmentation: Fragmenting(..), ..) -> False
  }
}

@internal
pub fn compress_payload(payload: BitArray) -> BitArray {
  compress(init_compression(False, False, -15, -15), payload)
}
