// TODO: Documentation
// TODO: Compression

import gleam/bit_array
import gleam/crypto
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

pub const magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

pub fn compute_accept(key: String) -> String {
  string.append(key, magic_string)
  |> bit_array.from_string()
  |> crypto.hash(crypto.Sha1, _)
  |> bit_array.base64_encode(True)
}

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

pub type Frame {
  Continuation(payload: BitArray)
  Text(payload: BitArray)
  Binary(payload: BitArray)
  Ping(payload: BitArray)
  Pong(payload: BitArray)
  Close(reason: CloseReason)
}

pub type DecodedFrame {
  Complete(frame: Frame)
  Incomplete(frame: Frame)
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
      // TODO: compression
      _rsv1:1,
      _rsv2:1,
      _rsv3:1,
      opcode:size(4),
      mask:1,
      payload_length:size(7),
      rest:bits,
    >> -> {
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
        0 -> Ok(Continuation(payload:))
        1 -> Ok(Text(payload:))
        2 -> Ok(Binary(payload:))
        8 -> {
          // TODO: Proper close code validation.
          case payload {
            <<1000:size(16), data:bits>> -> Ok(Close(NormalClosure(data:)))
            <<1001:size(16), data:bits>> -> Ok(Close(GoingAway(data:)))
            <<1002:size(16), data:bits>> -> Ok(Close(ProtocolError(data:)))
            <<1003:size(16), data:bits>> -> Ok(Close(UnsupportedData(data:)))
            <<1007:size(16), data:bits>> -> Ok(Close(InvalidPayloadData(data:)))
            <<1008:size(16), data:bits>> -> Ok(Close(PolicyViolation(data:)))
            <<1009:size(16), data:bits>> -> Ok(Close(MessageTooBig(data:)))
            <<1010:size(16), data:bits>> -> Ok(Close(MandatoryExtension(data:)))
            <<1011:size(16), data:bits>> -> Ok(Close(InternalError(data:)))
            <<1012:size(16), data:bits>> -> Ok(Close(ServiceRestart(data:)))
            <<1013:size(16), data:bits>> -> Ok(Close(TryAgainLater(data:)))
            <<1014:size(16), data:bits>> -> Ok(Close(BadGateway(data:)))
            <<1015:size(16), data:bits>> -> Ok(Close(TLSHandshake(data:)))
            <<code:size(16), data:bits>> ->
              Ok(Close(CustomCloseCode(code:, data:)))
            _ -> Error(InvalidFrame)
          }
        }
        9 -> Ok(Ping(payload:))
        10 -> Ok(Pong(payload:))
        _ -> Error(InvalidFrame)
      }

      case fin, frame {
        1, Ok(frame) -> Ok(#(Complete(frame:), rest))
        0, Ok(frame) -> Ok(#(Incomplete(frame:), rest))
        _, _ -> Error(InvalidFrame)
      }
    }
    _ -> Error(NotEnoughData(data))
  }
}

fn encode_frame(
  frame frame: Frame,
  final final: Bool,
  masking masking: Option(BitArray),
) -> BitArray {
  let #(opcode, payload_length, payload) = case frame {
    Continuation(payload) -> #(0, bit_array.byte_size(payload), payload)
    Text(payload) -> #(1, bit_array.byte_size(payload), payload)
    Binary(payload) -> #(2, bit_array.byte_size(payload), payload)
    Ping(payload) -> #(9, bit_array.byte_size(payload), payload)
    Pong(payload) -> #(10, bit_array.byte_size(payload), payload)
    Close(reason) -> {
      let #(payload_length, payload) = case reason {
        NormalClosure(data) -> #(bit_array.byte_size(data) + 2, <<
          1000:size(16),
          data:bits,
        >>)
        GoingAway(data) -> #(bit_array.byte_size(data) + 2, <<
          1001:size(16),
          data:bits,
        >>)
        ProtocolError(data) -> #(bit_array.byte_size(data) + 2, <<
          1002:size(16),
          data:bits,
        >>)
        UnsupportedData(data) -> #(bit_array.byte_size(data) + 2, <<
          1003:size(16),
          data:bits,
        >>)
        InvalidPayloadData(data) -> #(bit_array.byte_size(data) + 2, <<
          1007:size(16),
          data:bits,
        >>)
        PolicyViolation(data) -> #(bit_array.byte_size(data) + 2, <<
          1008:size(16),
          data:bits,
        >>)
        MessageTooBig(data) -> #(bit_array.byte_size(data) + 2, <<
          1009:size(16),
          data:bits,
        >>)
        MandatoryExtension(data) -> #(bit_array.byte_size(data) + 2, <<
          1010:size(16),
          data:bits,
        >>)
        InternalError(data) -> #(bit_array.byte_size(data) + 2, <<
          1011:size(16),
          data:bits,
        >>)
        ServiceRestart(data) -> #(bit_array.byte_size(data) + 2, <<
          1012:size(16),
          data:bits,
        >>)
        TryAgainLater(data) -> #(bit_array.byte_size(data) + 2, <<
          1013:size(16),
          data:bits,
        >>)
        BadGateway(data) -> #(bit_array.byte_size(data) + 2, <<
          1014:size(16),
          data:bits,
        >>)
        TLSHandshake(data) -> #(bit_array.byte_size(data) + 2, <<
          1015:size(16),
          data:bits,
        >>)
        CustomCloseCode(code, data) -> #(bit_array.byte_size(data) + 2, <<
          code:size(16),
          data:bits,
        >>)
      }

      #(8, payload_length, payload)
    }
  }

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

  let fin = case final {
    True -> 1
    False -> 0
  }

  <<
    fin:1,
    // TODO: compression
    0:3,
    opcode:4,
    mask_bit:1,
    encoded_payload_length:7,
    extended_payload:bits,
    mask:bits,
    payload:bits,
  >>
}

pub fn encode_continuation_frame(
  payload payload: BitArray,
  final final: Bool,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Continuation(payload:), final:, masking:)
}

pub fn encode_text_frame(
  payload payload: BitArray,
  final final: Bool,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Text(payload:), final:, masking:)
}

pub fn encode_binary_frame(
  payload payload: BitArray,
  final final: Bool,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Binary(payload:), final:, masking:)
}

pub fn encode_ping_frame(
  payload payload: BitArray,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Ping(payload:), final: True, masking:)
}

pub fn encode_pong_frame(
  payload payload: BitArray,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Pong(payload:), final: True, masking:)
}

pub fn encode_close_frame(
  reason reason: CloseReason,
  masking masking: Option(BitArray),
) -> BitArray {
  encode_frame(Close(reason:), final: True, masking:)
}

pub type ResolveError {
  NotUtf8
  OrphanedContinuation
  ControlFrameFragmented
  FragmentationInterrupted
  ConcurrentFragmentation
}

pub opaque type Context {
  Empty
  Accumulating(
    frame_builder: fn(BitArray) -> Frame,
    accumulated_payload: BitArray,
  )
}

@internal
pub fn extract_accumulated_context_value(context: Context) -> Result(Frame, Nil) {
  case context {
    Accumulating(frame_builder, accumulated_payload) ->
      Ok(frame_builder(accumulated_payload))
    Empty -> Error(Nil)
  }
}

pub fn create_context() -> Context {
  Empty
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

    // FIN=1 text frames must be UTF-8.
    [Complete(Text(payload:)), ..rest], Empty -> {
      case bit_array.is_utf8(payload) {
        True -> do_resolve_fragments(rest, Empty, [Text(payload:), ..resolved])
        False -> Error(NotUtf8)
      }
    }
    // Continuation frames cannot be the first frame in a fragmentation sequence.
    [Complete(Continuation(..)), ..], Empty -> Error(OrphanedContinuation)
    // Rest FIN=1 frames are joining resolved list without further processing.
    [Complete(frame), ..rest], Empty ->
      do_resolve_fragments(rest, Empty, [frame, ..resolved])

    // FIN=0 Text frame begins accumulation of fragmented frames.
    [Incomplete(Text(payload:)), ..rest], Empty ->
      do_resolve_fragments(rest, Accumulating(Text, payload), resolved)
    // FIN=0 Binary frame begins accumulation of fragmented frames.
    [Incomplete(Binary(payload:)), ..rest], Empty ->
      do_resolve_fragments(rest, Accumulating(Binary, payload), resolved)
    // Continuation frames cannot be the first frame in a fragmentation sequence.
    [Incomplete(Continuation(..)), ..], Empty -> Error(OrphanedContinuation)
    // Control frames cannot be fragmented.
    [Incomplete(..), ..], Empty -> Error(ControlFrameFragmented)

    // FIN=0 Continuation frame continues fragmentation.
    [Incomplete(Continuation(payload:)), ..rest], Accumulating(builder, acc) ->
      do_resolve_fragments(
        rest,
        Accumulating(builder, <<acc:bits, payload:bits>>),
        resolved,
      )
    // Concurrent fragmentation is not allowed.
    [Incomplete(..), ..], Accumulating(..) -> Error(ConcurrentFragmentation)

    // FIN=1 Continuation frame completes fragmentation.
    [Complete(Continuation(payload:)), ..rest], Accumulating(builder, acc) ->
      do_resolve_fragments(
        [Complete(builder(<<acc:bits, payload:bits>>)), ..rest],
        Empty,
        resolved,
      )
    // Fragmentation interrupted.
    [Complete(..), ..], Accumulating(..) -> Error(FragmentationInterrupted)
  }
}
