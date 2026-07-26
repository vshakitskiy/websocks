import endpoint
import frame
import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import websocks.{
  Binary, Close, CloseReason, Control, NoCloseReason, Ping, Pong, Text,
}

pub fn text_frame_bytes_test() {
  assert websocks.encode_text_frame(<<"Hello":utf8>>, endpoint.server(), None)
    == <<0x81, 0x05, "Hello":utf8>>
}

pub fn binary_frame_bytes_test() {
  assert websocks.encode_binary_frame(<<0, 1, 2>>, endpoint.server(), None)
    == <<0x82, 0x03, 0, 1, 2>>
}

pub fn ping_and_pong_bytes_test() {
  assert websocks.encode_ping_frame(<<"p":utf8>>, None)
    == <<0x89, 0x01, "p":utf8>>
  assert websocks.encode_pong_frame(<<"p":utf8>>, None)
    == <<0x8a, 0x01, "p":utf8>>
}

pub fn empty_payload_bytes_test() {
  assert websocks.encode_text_frame(<<>>, endpoint.server(), None)
    == <<0x81, 0x00>>
}

pub fn masked_frame_sets_the_mask_bit_and_key_test() {
  let encoded =
    websocks.encode_text_frame(
      <<"Hello":utf8>>,
      endpoint.server(),
      Some(<<0x37, 0xfa, 0x21, 0x3d>>),
    )

  assert encoded
    == <<0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58>>
}

pub fn length_encodings_test() {
  // 125 fits the 7 bit field, 126 needs 16 bits, 65_536 needs 64
  let assert <<_fin, 125, _rest:bits>> =
    websocks.encode_binary_frame(frame.filler(125), endpoint.server(), None)

  let assert <<_fin2, 126, 126:size(16), _rest2:bits>> =
    websocks.encode_binary_frame(frame.filler(126), endpoint.server(), None)

  let assert <<_fin3, 126, 65_535:size(16), _rest3:bits>> =
    websocks.encode_binary_frame(frame.filler(65_535), endpoint.server(), None)

  let assert <<_fin4, 127, 65_536:size(64), _rest4:bits>> =
    websocks.encode_binary_frame(frame.filler(65_536), endpoint.server(), None)
}

pub fn close_without_a_reason_has_no_payload_test() {
  assert websocks.encode_close_frame(NoCloseReason, None) == <<0x88, 0x00>>
}

pub fn close_with_a_code_test() {
  assert websocks.encode_close_frame(
      CloseReason(websocks.NormalClosure, ""),
      None,
    )
    == <<0x88, 0x02, 1000:size(16)>>
}

pub fn close_with_a_code_and_reason_test() {
  assert websocks.encode_close_frame(
      CloseReason(websocks.GoingAway, "bye"),
      None,
    )
    == <<0x88, 0x05, 1001:size(16), "bye":utf8>>
}

pub fn application_close_code_test() {
  assert websocks.encode_close_frame(
      CloseReason(websocks.ApplicationCode(4000), "x"),
      None,
    )
    == <<0x88, 0x03, 4000:size(16), "x":utf8>>
}

/// Every code must survive encoding and decoding unchanged, which also pins the
/// two direction-specific mapping tables against each other.
pub fn every_close_code_round_trips_test() {
  let codes = [
    websocks.NormalClosure,
    websocks.GoingAway,
    websocks.ProtocolError,
    websocks.UnsupportedData,
    websocks.InvalidPayloadData,
    websocks.PolicyViolation,
    websocks.MessageTooBig,
    websocks.MandatoryExtension,
    websocks.InternalError,
    websocks.ServiceRestart,
    websocks.TryAgainLater,
    websocks.BadGateway,
    websocks.ApplicationCode(3000),
    websocks.ApplicationCode(4999),
  ]

  list.each(codes, fn(code) {
    let reason = CloseReason(code, "because")
    let encoded = websocks.encode_close_frame(reason, Some(frame.mask_key))

    assert endpoint.frames(endpoint.server(), encoded)
      == Ok([Control(Close(reason))])
  })
}

pub fn close_without_a_reason_round_trips_test() {
  let encoded = websocks.encode_close_frame(NoCloseReason, Some(frame.mask_key))

  assert endpoint.frames(endpoint.server(), encoded)
    == Ok([Control(Close(NoCloseReason))])
}

pub fn a_multibyte_close_reason_round_trips_test() {
  let reason = CloseReason(websocks.NormalClosure, "añ日🐑")
  let encoded = websocks.encode_close_frame(reason, Some(frame.mask_key))

  assert endpoint.frames(endpoint.server(), encoded)
    == Ok([Control(Close(reason))])
}

/// A client encodes masked and a server decodes it; then the reverse.
pub fn frames_round_trip_in_both_directions_test() {
  let sizes = [0, 1, 125, 126, 65_535, 65_536]

  list.each(sizes, fn(size) {
    let payload = frame.filler(size)

    let to_server =
      websocks.encode_binary_frame(
        payload,
        endpoint.client(),
        Some(frame.mask_key),
      )
    assert endpoint.frames(endpoint.server(), to_server)
      == Ok([Binary(payload)])

    let to_client =
      websocks.encode_binary_frame(payload, endpoint.server(), None)
    assert endpoint.frames(endpoint.client(), to_client)
      == Ok([Binary(payload)])
  })
}

pub fn text_round_trips_test() {
  list.each(["", "Hello", "añ日🐑", "line\nbreak\ttab"], fn(text) {
    let payload = bit_array.from_string(text)
    let encoded =
      websocks.encode_text_frame(
        payload,
        endpoint.client(),
        Some(frame.mask_key),
      )

    assert endpoint.frames(endpoint.server(), encoded) == Ok([Text(payload)])
  })
}

pub fn control_frames_round_trip_test() {
  let payload = frame.filler(125)

  let ping = websocks.encode_ping_frame(payload, Some(frame.mask_key))
  assert endpoint.frames(endpoint.server(), ping)
    == Ok([Control(Ping(payload))])

  let pong = websocks.encode_pong_frame(payload, Some(frame.mask_key))
  assert endpoint.frames(endpoint.server(), pong)
    == Ok([Control(Pong(payload))])
}

pub fn a_masked_frame_is_not_plaintext_test() {
  // Guards against the mask silently becoming a no-op
  let payload = frame.filler(64)
  let encoded =
    websocks.encode_binary_frame(
      payload,
      endpoint.client(),
      Some(frame.mask_key),
    )

  assert !bit_array.is_utf8(encoded)
  assert encoded
    != websocks.encode_binary_frame(payload, endpoint.client(), None)
}

pub fn several_encoded_frames_decode_together_test() {
  let data =
    frame.join([
      websocks.encode_text_frame(
        <<"one":utf8>>,
        endpoint.client(),
        Some(frame.mask_key),
      ),
      websocks.encode_ping_frame(<<>>, Some(frame.mask_key)),
      websocks.encode_text_frame(
        <<"two":utf8>>,
        endpoint.client(),
        Some(frame.mask_key),
      ),
    ])

  assert endpoint.frames(endpoint.server(), data)
    == Ok([Text(<<"one":utf8>>), Control(Ping(<<>>)), Text(<<"two":utf8>>)])
}
