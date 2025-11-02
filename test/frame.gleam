import gleam/bit_array
import gleam/option.{type Option, None, Some}
import websocks

// Only the fin bit as well as the reserved bits are present.
pub const unfinished_frame = <<1:1, 0:3>>

pub const invalid_opcode_frame = <<
  // fin
  1:1,
  // rsvs
  0:3,
  // opcode
  15:4,
  // mask bit
  0:1,
  // payload length
  0:7,
  // rest
  <<>>:bits,
>>

pub type Opcode {
  Continuation
  Text
  Binary
  Ping
  Pong
  Close
}

fn opcode_to_int(opcode: Opcode) -> Int {
  case opcode {
    Continuation -> 0
    Text -> 1
    Binary -> 2
    Ping -> 9
    Pong -> 10
    Close -> 8
  }
}

pub fn construct(
  fin fin: Bool,
  rsv1 rsv1: Bool,
  rsv2 rsv2: Bool,
  rsv3 rsv3: Bool,
  opcode opcode: Opcode,
  mask mask: Option(BitArray),
  payload payload: BitArray,
) -> BitArray {
  let fin = case fin {
    True -> 1
    False -> 0
  }

  let rsv1 = case rsv1 {
    True -> 1
    False -> 0
  }

  let rsv2 = case rsv2 {
    True -> 1
    False -> 0
  }

  let rsv3 = case rsv3 {
    True -> 1
    False -> 0
  }

  let opcode = opcode_to_int(opcode)

  let payload_length = bit_array.byte_size(payload)

  let #(mask_bit, mask, payload) = case mask {
    Some(mask) -> #(1, mask, websocks.mask(payload, mask))
    None -> #(0, <<>>, payload)
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

  <<
    fin:1,
    rsv1:1,
    rsv2:1,
    rsv3:1,
    opcode:4,
    mask_bit:1,
    encoded_payload_length:7,
    extended_payload:bits,
    mask:bits,
    payload:bits,
  >>
}
