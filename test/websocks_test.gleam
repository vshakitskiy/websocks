import frame
import gleam/list
import gleam/option.{None, Some}
import gleeunit
import websocks

pub fn main() -> Nil {
  gleeunit.main()
}

// -----------------------------------------------------------------------------
// Utility
// -----------------------------------------------------------------------------

pub fn magic_string_test() {
  // lol
  assert websocks.magic_string == "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
}

pub fn compute_accept_test() {
  let websocket_key = "dGhlIHNhbXBsZSBub25jZQ=="
  let expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

  assert websocks.compute_accept(websocket_key) == expected_accept
}

// -----------------------------------------------------------------------------
// Mask
// -----------------------------------------------------------------------------

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

pub fn mask_empty_payload_test() {
  let empty = <<>>
  let mask = <<0x37, 0xfa, 0x21, 0x3d>>
  let result = websocks.mask(empty, mask)
  assert result == <<>>
}

pub fn mask_large_payload_test() {
  let payload =
    list.repeat(0x41, 1000)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })
  let mask = <<0x37, 0xfa, 0x21, 0x3d>>
  let masked = websocks.mask(payload, mask)
  let unmasked = websocks.mask(masked, mask)
  assert unmasked == payload
}

// -----------------------------------------------------------------------------
// Decode
// -----------------------------------------------------------------------------

pub fn decode_complete_text_unmasked_frame_test() {
  let payload = <<"Hello, Joe!":utf8>>

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Complete(websocks.Text(payload:)), <<>>))
}

pub fn decode_complete_text_masked_frame_test() {
  let payload = <<"Hello, Joe!":utf8>>

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: Some(<<0x37, 0xfa, 0x21, 0x3d>>),
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Complete(websocks.Text(payload:)), <<>>))
}

pub fn decode_incomplete_text_continuation_unmasked_frame_test() {
  let payload = <<"Hello, Joe!":utf8>>

  let decoded_frame =
    frame.construct(
      fin: False,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Continuation,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Incomplete(websocks.Continuation(payload:)), <<>>))
}

pub fn decode_need_more_data_test() {
  let decoded_frame = websocks.decode_frame(frame.unfinished_frame)
  assert decoded_frame == Error(websocks.NotEnoughData(frame.unfinished_frame))
}

pub fn decode_invalid_frame_test() {
  let decoded_frame = websocks.decode_frame(frame.invalid_opcode_frame)
  assert decoded_frame == Error(websocks.InvalidFrame)
}

pub fn decode_ping_frame_test() {
  let payload = <<"Hello, Joe!":utf8>>

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Ping,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Complete(websocks.Ping(payload:)), <<>>))
}

pub fn decode_normal_close_frame_test() {
  let data = <<"Hello, Joe!":utf8>>
  let payload = <<1000:size(16), data:bits>>

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Close,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(
      #(websocks.Complete(websocks.Close(websocks.NormalClosure(data:))), <<>>),
    )
}

pub fn decode_custom_close_code_frame_test() {
  let code = 4180
  let data = <<"Hello, Joe!":utf8>>
  let payload = <<code:size(16), data:bits>>

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Close,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(
      #(
        websocks.Complete(
          websocks.Close(websocks.CustomCloseCode(code:, data:)),
        ),
        <<>>,
      ),
    )
}

pub fn decode_frame_with_leftover_data_test() {
  let payload = <<"Hello, ":utf8>>
  let next_payload = <<"Joe!":utf8>>

  let frame =
    frame.construct(
      fin: False,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )

  let next_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Continuation,
      mask: None,
      payload: next_payload,
    )

  let assert Ok(#(
    websocks.Incomplete(websocks.Text(decoded_payload)),
    next_frame,
  )) = websocks.decode_frame(<<frame:bits, next_frame:bits>>)
  assert decoded_payload == payload

  let assert Ok(#(
    websocks.Complete(websocks.Continuation(decoded_payload)),
    <<>>,
  )) = websocks.decode_frame(next_frame)
  assert decoded_payload == next_payload
}

pub fn decode_binary_frame_test() {
  let payload = <<0x01, 0x02, 0x03, 0x04, 0x05>>

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Complete(websocks.Binary(payload:)), <<>>))
}

pub fn decode_pong_frame_test() {
  let payload = <<"pong":utf8>>

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Pong,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Complete(websocks.Pong(payload:)), <<>>))
}

pub fn decode_empty_payload_frame_test() {
  let payload = <<>>

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Complete(websocks.Text(payload:)), <<>>))
}

pub fn decode_125_byte_boundary_test() {
  let payload =
    list.repeat(0x41, 125)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Complete(websocks.Binary(payload:)), <<>>))
}

pub fn decode_126_byte_extended_length_test() {
  let payload =
    list.repeat(0x41, 126)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Complete(websocks.Binary(payload:)), <<>>))
}

pub fn decode_200_byte_extended_length_test() {
  let payload =
    list.repeat(0x41, 200)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Complete(websocks.Text(payload:)), <<>>))
}

pub fn decode_65535_byte_boundary_test() {
  let payload =
    list.repeat(0x41, 65_535)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Complete(websocks.Binary(payload:)), <<>>))
}

pub fn decode_going_away_close_test() {
  let data = <<"bye":utf8>>
  let payload = <<1001:size(16), data:bits>>

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Close,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(#(websocks.Complete(websocks.Close(websocks.GoingAway(data:))), <<>>))
}

pub fn decode_protocol_error_close_test() {
  let data = <<"error":utf8>>
  let payload = <<1002:size(16), data:bits>>

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Close,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(
      #(websocks.Complete(websocks.Close(websocks.ProtocolError(data:))), <<>>),
    )
}

pub fn decode_all_standard_close_codes_test() {
  let data = <<>>
  let close_codes = [
    #(1000, websocks.NormalClosure(data:)),
    #(1001, websocks.GoingAway(data:)),
    #(1002, websocks.ProtocolError(data:)),
    #(1003, websocks.UnsupportedData(data:)),
    #(1007, websocks.InvalidPayloadData(data:)),
    #(1008, websocks.PolicyViolation(data:)),
    #(1009, websocks.MessageTooBig(data:)),
    #(1010, websocks.MandatoryExtension(data:)),
    #(1011, websocks.InternalError(data:)),
    #(1012, websocks.ServiceRestart(data:)),
    #(1013, websocks.TryAgainLater(data:)),
    #(1014, websocks.BadGateway(data:)),
    #(1015, websocks.TLSHandshake(data:)),
  ]

  list.each(close_codes, fn(pair) {
    let #(code, reason) = pair
    let payload = <<code:size(16), data:bits>>

    let decoded_frame =
      frame.construct(
        fin: True,
        rsv1: False,
        rsv2: False,
        rsv3: False,
        opcode: frame.Close,
        mask: None,
        payload:,
      )
      |> websocks.decode_frame()

    assert decoded_frame
      == Ok(#(websocks.Complete(websocks.Close(reason)), <<>>))
  })
}

pub fn decode_close_empty_data_test() {
  let data = <<>>
  let payload = <<1000:size(16), data:bits>>

  let decoded_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Close,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame()

  assert decoded_frame
    == Ok(
      #(websocks.Complete(websocks.Close(websocks.NormalClosure(data:))), <<>>),
    )
}

// -----------------------------------------------------------------------------
// Encode
// -----------------------------------------------------------------------------

pub fn encode_text_frame_test() {
  let frame = websocks.Text(payload: <<"Hello, Joe!":utf8>>)

  let encoded_frame =
    websocks.encode_frame(frame, finished: True, masking: None)

  let expect =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload: <<"Hello, Joe!":utf8>>,
    )

  assert encoded_frame == expect
}

pub fn encode_text_frame_masked_test() {
  let payload = <<"Hello, Joe!":utf8>>
  let frame = websocks.Text(payload:)
  let mask = <<0x37, 0xfa, 0x21, 0x3d>>

  let encoded_frame =
    websocks.encode_frame(frame, finished: True, masking: Some(mask))

  let expect =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: Some(mask),
      payload:,
    )

  assert encoded_frame == expect
}

pub fn encode_closing_frame_test() {
  let data = <<"Hello, Joe!":utf8>>
  let frame = websocks.Close(websocks.NormalClosure(data:))

  let encoded_frame =
    websocks.encode_frame(frame, finished: True, masking: None)

  let expect =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Close,
      mask: None,
      payload: <<1000:size(16), data:bits>>,
    )

  assert encoded_frame == expect
}

pub fn encode_binary_frame_test() {
  let payload = <<0x01, 0x02, 0x03, 0x04, 0x05>>
  let frame = websocks.Binary(payload:)

  let encoded_frame =
    websocks.encode_frame(frame, finished: True, masking: None)

  let expect =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload:,
    )

  assert encoded_frame == expect
}

pub fn encode_ping_frame_test() {
  let payload = <<"ping":utf8>>
  let frame = websocks.Ping(payload:)

  let encoded_frame =
    websocks.encode_frame(frame, finished: True, masking: None)

  let expect =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Ping,
      mask: None,
      payload:,
    )

  assert encoded_frame == expect
}

pub fn encode_pong_frame_test() {
  let payload = <<"pong":utf8>>
  let frame = websocks.Pong(payload:)

  let encoded_frame =
    websocks.encode_frame(frame, finished: True, masking: None)

  let expect =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Pong,
      mask: None,
      payload:,
    )

  assert encoded_frame == expect
}

pub fn encode_continuation_frame_test() {
  let payload = <<"continue":utf8>>
  let frame = websocks.Continuation(payload:)

  let encoded_frame =
    websocks.encode_frame(frame, finished: False, masking: None)

  let expect =
    frame.construct(
      fin: False,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Continuation,
      mask: None,
      payload:,
    )

  assert encoded_frame == expect
}

pub fn encode_incomplete_frame_test() {
  let payload = <<"incomplete":utf8>>
  let frame = websocks.Text(payload:)

  let encoded_frame =
    websocks.encode_frame(frame, finished: False, masking: None)

  let expect =
    frame.construct(
      fin: False,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )

  assert encoded_frame == expect
}

pub fn encode_empty_payload_test() {
  let payload = <<>>
  let frame = websocks.Text(payload:)

  let encoded_frame =
    websocks.encode_frame(frame, finished: True, masking: None)

  let expect =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )

  assert encoded_frame == expect
}

pub fn encode_126_byte_extended_length_test() {
  let payload =
    list.repeat(0x41, 126)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })
  let frame = websocks.Binary(payload:)

  let encoded_frame =
    websocks.encode_frame(frame, finished: True, masking: None)

  let expect =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload:,
    )

  assert encoded_frame == expect
}

pub fn encode_large_payload_test() {
  let payload =
    list.repeat(0x41, 500)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })
  let frame = websocks.Binary(payload:)

  let encoded_frame =
    websocks.encode_frame(frame, finished: True, masking: None)

  let expect =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload:,
    )

  assert encoded_frame == expect
}

pub fn encode_all_close_codes_test() {
  let data = <<"reason":utf8>>
  let close_frames = [
    #(websocks.NormalClosure(data:), <<1000:size(16), data:bits>>),
    #(websocks.GoingAway(data:), <<1001:size(16), data:bits>>),
    #(websocks.ProtocolError(data:), <<1002:size(16), data:bits>>),
    #(websocks.UnsupportedData(data:), <<1003:size(16), data:bits>>),
    #(websocks.InvalidPayloadData(data:), <<1007:size(16), data:bits>>),
    #(websocks.PolicyViolation(data:), <<1008:size(16), data:bits>>),
    #(websocks.MessageTooBig(data:), <<1009:size(16), data:bits>>),
    #(websocks.MandatoryExtension(data:), <<1010:size(16), data:bits>>),
    #(websocks.InternalError(data:), <<1011:size(16), data:bits>>),
    #(websocks.ServiceRestart(data:), <<1012:size(16), data:bits>>),
    #(websocks.TryAgainLater(data:), <<1013:size(16), data:bits>>),
    #(websocks.BadGateway(data:), <<1014:size(16), data:bits>>),
    #(websocks.TLSHandshake(data:), <<1015:size(16), data:bits>>),
  ]

  list.each(close_frames, fn(pair) {
    let #(reason, payload) = pair
    let frame = websocks.Close(reason)

    let encoded_frame =
      websocks.encode_frame(frame, finished: True, masking: None)

    let expect =
      frame.construct(
        fin: True,
        rsv1: False,
        rsv2: False,
        rsv3: False,
        opcode: frame.Close,
        mask: None,
        payload:,
      )

    assert encoded_frame == expect
  })
}

pub fn encode_custom_close_code_test() {
  let code = 4000
  let data = <<"custom":utf8>>
  let frame = websocks.Close(websocks.CustomCloseCode(code:, data:))

  let encoded_frame =
    websocks.encode_frame(frame, finished: True, masking: None)

  let expect =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Close,
      mask: None,
      payload: <<code:size(16), data:bits>>,
    )

  assert encoded_frame == expect
}

// -----------------------------------------------------------------------------
// Round-Trip
// -----------------------------------------------------------------------------

pub fn round_trip_text_test() {
  let original = websocks.Text(payload: <<"Hello, World!":utf8>>)
  let encoded = websocks.encode_frame(original, finished: True, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(original)
}

pub fn round_trip_text_masked_test() {
  let original = websocks.Text(payload: <<"Hello, World!":utf8>>)
  let mask = <<0x37, 0xfa, 0x21, 0x3d>>
  let encoded =
    websocks.encode_frame(original, finished: True, masking: Some(mask))
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(original)
}

pub fn round_trip_binary_test() {
  let original = websocks.Binary(payload: <<0x01, 0x02, 0x03, 0x04, 0x05>>)
  let encoded = websocks.encode_frame(original, finished: True, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(original)
}

pub fn round_trip_ping_test() {
  let original = websocks.Ping(payload: <<"ping":utf8>>)
  let encoded = websocks.encode_frame(original, finished: True, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(original)
}

pub fn round_trip_pong_test() {
  let original = websocks.Pong(payload: <<"pong":utf8>>)
  let encoded = websocks.encode_frame(original, finished: True, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(original)
}

pub fn round_trip_close_test() {
  let original = websocks.Close(websocks.NormalClosure(data: <<"bye":utf8>>))
  let encoded = websocks.encode_frame(original, finished: True, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(original)
}

pub fn round_trip_incomplete_test() {
  let original = websocks.Text(payload: <<"partial":utf8>>)
  let encoded = websocks.encode_frame(original, finished: False, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Incomplete(original)
}

pub fn round_trip_large_payload_test() {
  let payload =
    list.repeat(0x41, 1000)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })
  let original = websocks.Binary(payload:)
  let encoded = websocks.encode_frame(original, finished: True, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(original)
}

pub fn round_trip_empty_payload_test() {
  let original = websocks.Text(payload: <<>>)
  let encoded = websocks.encode_frame(original, finished: True, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(original)
}
