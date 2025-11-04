// TODO: Documentation

// TODO:
// pub fn begin_fragmentation(...)
// pub fn continue_fragmentation(...)
// pub fn finish_fragmentation(...)

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

pub const magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

pub fn compute_accept(key: String) -> String {
  string.append(key, magic_string)
  |> bit_array.from_string()
  |> crypto.hash(crypto.Sha1, _)
  |> bit_array.base64_encode(True)
}

pub fn has_deflate(extensions: List(String)) -> Bool {
  list.any(extensions, fn(str) { str == "permessage-deflate" })
}

pub type ContextTakeover {
  ContextTakeover(no_client: Bool, no_server: Bool)
}

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
    Enabled(_, defalte_context, _, no_server) -> {
      let compressed =
        do_deflate(defalte_context, payload, Sync)
        |> bytes_tree.to_bit_array()

      case no_server {
        True -> {
          deflate_reset(defalte_context)
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
// Frames
// -----------------------------------------------------------------------------

pub type Frame {
  Continuation(payload: BitArray)
  Text(payload: BitArray)
  Binary(payload: BitArray)
  Ping(payload: BitArray)
  Pong(payload: BitArray)
  Close(reason: CloseReason)
}

pub type CloseReason {
  NormalClosure(data: BitArray)
  GoingAway(data: BitArray)
  ProtocolError(data: BitArray)
  UnsupportedData(data: BitArray)
  InvalidPayloadData(data: BitArray)
  PolicyViolation(data: BitArray)
  MessageTooBig(data: BitArray)
  MandatoryExtension(data: BitArray)
  InternalError(data: BitArray)
  ServiceRestart(data: BitArray)
  TryAgainLater(data: BitArray)
  BadGateway(data: BitArray)
  TLSHandshake(data: BitArray)
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

// -----------------------------------------------------------------------------
// Decoding
// -----------------------------------------------------------------------------

pub opaque type DecodedFrame {
  Complete(InternalFrame)
  Incomplete(InternalFrame)
  Resolved(Frame)
}

pub type DecodeError {
  InvalidFrame
  NotEnoughData(data: BitArray)
}

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

fn apply_compression(
  compression: Option(Compression),
  payload: BitArray,
) -> BitArray {
  case compression {
    Some(Enabled(..) as compression) -> compress(compression, payload)
    _ -> payload
  }
}

// -----------------------------------------------------------------------------
// Context
// -----------------------------------------------------------------------------

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

pub fn create_context(compression: Option(ContextTakeover)) -> Context {
  case compression {
    Some(ContextTakeover(no_client, no_server)) ->
      Empty(compression: init_compression(no_client, no_server), buffer: <<>>)
    None -> Empty(compression: Disabled, buffer: <<>>)
  }
}

pub fn close_context(context: Context) -> Nil {
  case context {
    Empty(compression, _buffer) -> close_compression(compression)
    Accumulating(..) -> Nil
  }
}

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

pub fn encode_ping_frame(
  payload payload: BitArray,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Ping(payload:), final: True, compression: None, masking:)
}

pub fn encode_pong_frame(
  payload payload: BitArray,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Pong(payload:), final: True, compression: None, masking:)
}

pub fn encode_close_frame(
  reason reason: CloseReason,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Close(reason:), final: True, compression: None, masking:)
}

pub type ResolveError {
  NotUtf8
  OrphanedContinuation
  ControlFrameFragmented
  FragmentationInterrupted
  ConcurrentFragmentation
  CompressedContinuation
}

pub fn resolve_fragments(decoded_frames: List(DecodedFrame), context: Context) {
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
    [Resolved(frame), ..rest], context ->
      do_resolve_fragments(rest, context, [frame, ..resolved])

    // Continuation frames cannot be the first frame in a fragmentation sequence.
    [Complete(DecodedContinuation(..)), ..], Empty(..) ->
      Error(OrphanedContinuation)

    [Complete(frame), ..rest], Empty(..) as context -> {
      internal_frame_to_frame(frame, context.compression)
      |> result.try(fn(frame) {
        do_resolve_fragments([Resolved(frame), ..rest], context, resolved)
      })
    }

    // FIN=0 Text frame begins accumulation of fragmented frames.
    [Incomplete(DecodedText(payload:, compressed:)), ..rest],
      Empty(compression:, buffer:)
    ->
      do_resolve_fragments(
        rest,
        Accumulating(Text, payload, compressed:, compression:, buffer:),
        resolved,
      )
    // FIN=0 Binary frame begins accumulation of fragmented frames.
    [Incomplete(DecodedBinary(payload:, compressed:)), ..rest],
      Empty(compression:, buffer:)
    ->
      do_resolve_fragments(
        rest,
        Accumulating(Binary, payload, compressed:, compression:, buffer:),
        resolved,
      )
    // Continuation frames cannot be the first frame in a fragmentation sequence.
    [Incomplete(DecodedContinuation(..)), ..], Empty(..) ->
      Error(OrphanedContinuation)
    // Control frames cannot be fragmented.
    [Incomplete(..), ..], Empty(..) -> Error(ControlFrameFragmented)

    // FIN=0 Continuation frame continues fragmentation.
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
    // Concurrent fragmentation is not allowed.
    [Incomplete(..), ..], Accumulating(..) -> Error(ConcurrentFragmentation)

    // FIN=1 Continuation frame completes fragmentation.
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
    // Fragmentation interrupted.
    [Complete(..), ..], Accumulating(..) -> Error(FragmentationInterrupted)
  }
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
// For testing purposes only.
// -----------------------------------------------------------------------------

@internal
pub fn extract_accumulated_context_value(context: Context) -> Result(Frame, Nil) {
  case context {
    Accumulating(frame_builder:, accumulated_payload:, ..) ->
      Ok(frame_builder(accumulated_payload))
    Empty(..) -> Error(Nil)
  }
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
