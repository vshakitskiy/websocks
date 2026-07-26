//// Builds raw WebSocket frames for the test suite.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}

/// The mask key from RFC 6455 section 5.7, used by most tests.
///
pub const mask_key = <<0x37, 0xfa, 0x21, 0x3d>>

pub type Opcode {
  Continuation
  Text
  Binary
  Close
  Ping
  Pong
  /// An opcode the protocol does not define, for rejection tests.
  Reserved(code: Int)
}

fn opcode_to_int(opcode: Opcode) -> Int {
  case opcode {
    Continuation -> 0
    Text -> 1
    Binary -> 2
    Close -> 8
    Ping -> 9
    Pong -> 10
    Reserved(code:) -> code
  }
}

pub opaque type Builder {
  Builder(
    fin: Bool,
    rsv1: Bool,
    rsv2: Bool,
    rsv3: Bool,
    opcode: Opcode,
    mask: Option(BitArray),
    payload: BitArray,
  )
}

/// A final, unmasked, uncompressed frame with an empty payload.
///
pub fn new(opcode: Opcode) -> Builder {
  Builder(
    fin: True,
    rsv1: False,
    rsv2: False,
    rsv3: False,
    opcode:,
    mask: None,
    payload: <<>>,
  )
}

pub fn payload(builder: Builder, payload: BitArray) -> Builder {
  Builder(..builder, payload:)
}

pub fn text(builder: Builder, text: String) -> Builder {
  Builder(..builder, payload: <<text:utf8>>)
}

pub fn fin(builder: Builder, fin: Bool) -> Builder {
  Builder(..builder, fin:)
}

pub fn rsv1(builder: Builder, rsv1: Bool) -> Builder {
  Builder(..builder, rsv1:)
}

pub fn rsv2(builder: Builder, rsv2: Bool) -> Builder {
  Builder(..builder, rsv2:)
}

pub fn rsv3(builder: Builder, rsv3: Bool) -> Builder {
  Builder(..builder, rsv3:)
}

/// Masks with `mask_key`, as a client must.
///
pub fn masked(builder: Builder) -> Builder {
  Builder(..builder, mask: Some(mask_key))
}

pub fn masked_with(builder: Builder, key: BitArray) -> Builder {
  Builder(..builder, mask: Some(key))
}

pub fn build(builder: Builder) -> BitArray {
  let Builder(fin:, rsv1:, rsv2:, rsv3:, opcode:, mask:, payload:) = builder

  let #(mask_bit, mask_bytes, body) = case mask {
    Some(key) -> #(1, key, apply_mask(payload, key))
    None -> #(0, <<>>, payload)
  }

  <<
    to_bit(fin):1,
    to_bit(rsv1):1,
    to_bit(rsv2):1,
    to_bit(rsv3):1,
    opcode_to_int(opcode):4,
    mask_bit:1,
    encoded_length(payload):bits,
    mask_bytes:bits,
    body:bits,
  >>
}

/// Builds a frame whose length is declared in `bits` bits regardless of how
/// small the payload is, so the decoder's minimal-encoding rule can be tested.
///
pub fn with_forced_length_bits(builder: Builder, bits: Int) -> BitArray {
  let Builder(fin:, rsv1:, rsv2:, rsv3:, opcode:, mask:, payload:) = builder
  let length = byte_size(payload)

  let #(mask_bit, mask_bytes, body) = case mask {
    Some(key) -> #(1, key, apply_mask(payload, key))
    None -> #(0, <<>>, payload)
  }

  let #(length_code, extended) = case bits {
    16 -> #(126, <<length:size(16)>>)
    _bits -> #(127, <<length:size(64)>>)
  }

  <<
    to_bit(fin):1,
    to_bit(rsv1):1,
    to_bit(rsv2):1,
    to_bit(rsv3):1,
    opcode_to_int(opcode):4,
    mask_bit:1,
    length_code:7,
    extended:bits,
    mask_bytes:bits,
    body:bits,
  >>
}

fn encoded_length(payload: BitArray) -> BitArray {
  let length = byte_size(payload)
  case length {
    _ if length <= 125 -> <<length:7>>
    _ if length <= 65_535 -> <<126:7, length:size(16)>>
    _ -> <<127:7, length:size(64)>>
  }
}

fn to_bit(flag: Bool) -> Int {
  case flag {
    True -> 1
    False -> 0
  }
}

fn byte_size(bits: BitArray) -> Int {
  do_byte_size(bits, 0)
}

fn do_byte_size(bits: BitArray, count: Int) -> Int {
  case bits {
    <<_byte:8, rest:bits>> -> do_byte_size(rest, count + 1)
    _remainder -> count
  }
}

fn apply_mask(payload: BitArray, key: BitArray) -> BitArray {
  case to_bytes(key, []) {
    [] -> payload
    keys -> do_apply_mask(payload, keys, keys, <<>>)
  }
}

fn do_apply_mask(
  payload: BitArray,
  all_keys: List(Int),
  keys: List(Int),
  acc: BitArray,
) -> BitArray {
  case payload, keys {
    <<>>, _keys -> acc
    _payload, [] -> do_apply_mask(payload, all_keys, all_keys, acc)
    <<byte:8, rest:bits>>, [key, ..remaining_keys] -> {
      let masked = int.bitwise_exclusive_or(byte, key)
      do_apply_mask(rest, all_keys, remaining_keys, <<acc:bits, masked:8>>)
    }
    _payload, _keys -> acc
  }
}

fn to_bytes(bits: BitArray, acc: List(Int)) -> List(Int) {
  case bits {
    <<byte:8, rest:bits>> -> to_bytes(rest, [byte, ..acc])
    _remainder -> list.reverse(acc)
  }
}

/// `size` bytes of filler payload.
///
pub fn filler(size: Int) -> BitArray {
  list.repeat(<<"a":utf8>>, size)
  |> bit_array.concat
}

/// Roughly `size` bytes of multi-byte UTF-8 filler, for validation tests.
///
pub fn utf8_filler(size: Int) -> BitArray {
  let unit = <<"añ日🐑x":utf8>>
  list.repeat(unit, size / bit_array.byte_size(unit) + 1)
  |> bit_array.concat
}

/// Joins built frames into a single read.
///
pub fn join(frames: List(BitArray)) -> BitArray {
  bit_array.concat(frames)
}
