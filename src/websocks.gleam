import gleam/bit_array
import gleam/crypto
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string

pub const magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

pub fn compute_accept(key: String) -> String {
  string.concat([key, magic_string])
  |> bit_array.from_string()
  |> crypto.hash(crypto.Sha1, _)
  |> bit_array.base64_encode(True)
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
