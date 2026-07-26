import frame
import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleeunit
import websocks

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn magic_string_test() {
  assert websocks.magic_string == "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
}

pub fn compute_accept_test() {
  // RFC 6455 section 1.3
  assert websocks.compute_accept("dGhlIHNhbXBsZSBub25jZQ==")
    == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
}

pub fn compute_accept_is_deterministic_test() {
  let key = websocks.websocket_key()
  assert websocks.compute_accept(key) == websocks.compute_accept(key)
}

pub fn websocket_key_is_16_encoded_bytes_test() {
  let assert Ok(decoded) = bit_array.base64_decode(websocks.websocket_key())
  assert bit_array.byte_size(decoded) == 16
}

pub fn websocket_key_is_random_test() {
  let keys =
    list.repeat(Nil, 20)
    |> list.map(fn(_nil) { websocks.websocket_key() })

  assert list.unique(keys) == keys
}

const no_extensions = websocks.CompressionExtensions(
  client_no_context_takeover: False,
  client_max_window_bits: None,
  server_no_context_takeover: False,
  server_max_window_bits: None,
)

pub fn extensions_of_empty_header_test() {
  assert websocks.get_compression_extensions("") == no_extensions
}

pub fn extensions_of_unrelated_header_test() {
  assert websocks.get_compression_extensions("x-webkit-deflate-frame")
    == no_extensions
}

pub fn extensions_without_whitespace_test() {
  assert websocks.get_compression_extensions(
      "permessage-deflate;client_no_context_takeover",
    )
    == websocks.CompressionExtensions(
      ..no_extensions,
      client_no_context_takeover: True,
    )
}

// Real clients put a space after the separator, which an earlier version of this
// function silently ignored, disabling compression negotiation entirely.
pub fn extensions_with_whitespace_after_semicolon_test() {
  assert websocks.get_compression_extensions(
      "permessage-deflate; client_max_window_bits=10",
    )
    == websocks.CompressionExtensions(
      ..no_extensions,
      client_max_window_bits: Some(10),
    )
}

pub fn extensions_with_whitespace_after_comma_test() {
  assert websocks.get_compression_extensions(
      "permessage-deflate, server_no_context_takeover",
    )
    == websocks.CompressionExtensions(
      ..no_extensions,
      server_no_context_takeover: True,
    )
}

pub fn extensions_with_padding_and_tabs_test() {
  assert websocks.get_compression_extensions(
      "  permessage-deflate ;\tclient_no_context_takeover  ",
    )
    == websocks.CompressionExtensions(
      ..no_extensions,
      client_no_context_takeover: True,
    )
}

pub fn extensions_are_case_insensitive_test() {
  assert websocks.get_compression_extensions(
      "PerMessage-Deflate; Client_No_Context_Takeover",
    )
    == websocks.CompressionExtensions(
      ..no_extensions,
      client_no_context_takeover: True,
    )
}

pub fn extensions_with_every_parameter_test() {
  assert websocks.get_compression_extensions(
      "permessage-deflate; client_no_context_takeover; client_max_window_bits=10;"
      <> " server_no_context_takeover; server_max_window_bits=12",
    )
    == websocks.CompressionExtensions(
      client_no_context_takeover: True,
      client_max_window_bits: Some(10),
      server_no_context_takeover: True,
      server_max_window_bits: Some(12),
    )
}

pub fn extensions_ignore_unparseable_window_bits_test() {
  assert websocks.get_compression_extensions(
      "permessage-deflate; client_max_window_bits=abc",
    )
    == no_extensions
}

pub fn extensions_accept_valueless_window_bits_test() {
  // A client may offer the parameter with no value at all
  assert websocks.get_compression_extensions(
      "permessage-deflate; client_max_window_bits",
    )
    == no_extensions
}

pub fn has_deflate_test() {
  assert websocks.has_deflate("permessage-deflate")
  assert websocks.has_deflate("permessage-deflate; client_max_window_bits")
  assert websocks.has_deflate(" permessage-deflate")
  assert websocks.has_deflate("PerMessage-Deflate")
  assert websocks.has_deflate("x-foo, permessage-deflate")
}

pub fn has_deflate_absent_test() {
  assert !websocks.has_deflate("")
  assert !websocks.has_deflate("x-webkit-deflate-frame")
  // a parameter name is not the extension name
  assert !websocks.has_deflate("client_no_context_takeover")
}

pub fn mask_known_vector_test() {
  // RFC 6455 section 5.7
  assert websocks.mask(<<"Hello":utf8>>, <<0x37, 0xfa, 0x21, 0x3d>>)
    == <<0x7f, 0x9f, 0x4d, 0x51, 0x58>>
}

pub fn mask_is_its_own_inverse_test() {
  let key = <<0x37, 0xfa, 0x21, 0x3d>>
  let payload = <<"Wibble Wobble":utf8>>

  assert websocks.mask(websocks.mask(payload, key), key) == payload
}

pub fn mask_empty_payload_test() {
  assert websocks.mask(<<>>, <<0x37, 0xfa, 0x21, 0x3d>>) == <<>>
}

pub fn mask_empty_key_test() {
  // An empty key has no bytes to exclusive-or with, so the payload is returned
  // untouched. It must neither crash nor loop forever expanding the key.
  assert websocks.mask(<<"Hello":utf8>>, <<>>) == <<"Hello":utf8>>
}

pub fn mask_repeats_key_across_payload_test() {
  // Zeroes mask to the repeated key, showing where each key byte lands
  assert websocks.mask(<<0, 0, 0, 0, 0>>, <<0xaa, 0xbb>>)
    == <<0xaa, 0xbb, 0xaa, 0xbb, 0xaa>>
}

pub fn mask_round_trips_at_every_size_test() {
  let key = <<0x37, 0xfa, 0x21, 0x3d>>

  // Sizes either side of the key length, of the key expansion's doubling steps,
  // and of the frame length encodings.
  let sizes = [
    0, 1, 3, 4, 5, 7, 8, 63, 64, 65, 125, 126, 127, 255, 256, 257, 1023, 1024,
    4095, 65_535, 65_536, 65_537,
  ]

  list.each(sizes, fn(size) {
    let payload = frame.filler(size)
    let masked = websocks.mask(payload, key)

    assert bit_array.byte_size(masked) == size
    assert websocks.mask(masked, key) == payload
  })
}

pub fn mask_round_trips_with_unusual_key_lengths_test() {
  let keys = [<<1>>, <<1, 2>>, <<1, 2, 3>>, <<1, 2, 3, 4, 5, 6, 7, 8>>]

  list.each(keys, fn(key) {
    list.each([0, 1, 7, 33, 100, 1000], fn(size) {
      let payload = frame.filler(size)
      assert websocks.mask(websocks.mask(payload, key), key) == payload
    })
  })
}
