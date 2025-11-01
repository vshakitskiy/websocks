import gleam/bit_array
import gleam/int
import gleam/list
import gleeunit
import websocks

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn magic_string_test() {
  // lol
  assert websocks.magic_string == "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
}

pub fn compute_accept_test() {
  let websocket_key = "dGhlIHNhbXBsZSBub25jZQ=="
  let expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

  assert websocks.compute_accept(websocket_key) == expected_accept
}

pub fn decode_basic_frame_test() {
  let frame = <<
    1:size(1),
    0:size(1),
    0:size(1),
    0:size(1),
    0:size(4),
    0:size(1),
    127:size(7),
    256:size(64),
    12:size(4),
  >>

  echo websocks.decode_frame(frame)
}

pub fn mask_simple_test() {
  // Original: H(0x48) e(0x65) l(0x6c) l(0x6c) o(0x6f)
  // Mask:     0x37     0xfa    0x21    0x3d    0x37
  // Masked:   0x7f     0x9f    0x4d    0x51    0x58
  let masked = websocks.mask(<<"Hello":utf8>>, <<0x37, 0xfa, 0x21, 0x3d>>)
  assert masked == <<0x7f, 0x9f, 0x4d, 0x51, 0x58>>
}

pub fn mask_small_test() {
  let unmasked = <<"Gl":utf8>>
  let mask = <<0x37, 0xfa, 0x21, 0x3d>>
  let result = websocks.mask(unmasked, mask) |> websocks.mask(mask)
  assert result == unmasked
}

pub fn mask_repeatedly_test() {
  let unmasked = <<"Wibble Wobble":utf8>>

  let result =
    list.repeat(Nil, 10)
    |> list.fold(from: unmasked, with: fn(acc, _) {
      websocks.mask(acc, <<0x21, 0x3d, 0xa5, 0x6b, 0x21>>)
    })

  assert result == unmasked
}
