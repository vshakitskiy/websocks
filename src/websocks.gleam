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

pub type DecodeError {
  InvalidFrame
  NotEnoughData(data: BitArray)
}

pub fn decode_frame(data: BitArray) {
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
      echo #(fin, opcode, mask, payload_length, rest)

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

      use #(data, rest) <- result.try(case mask, rest {
        1, <<mask:bytes-size(4), payload:bytes-size(payload_length), rest:bits>>
        -> {
          let data =
            repeat_mask(mask, payload_length)
            |> exor(payload, _)

          Ok(#(data, rest))
        }
        1, _ -> Error(NotEnoughData(rest))

        0, <<payload:bytes-size(payload_length), rest:bits>> ->
          Ok(#(payload, rest))
        0, _ -> Error(NotEnoughData(rest))

        _, _ -> Error(InvalidFrame)
      })

      echo #(data, rest)

      Ok(Nil)
    }
    _ -> Error(InvalidFrame)
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
