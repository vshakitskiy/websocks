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
  let payload = <<"Hello, Joe!":utf8>>

  let encoded_frame =
    websocks.encode_text_frame(payload, final: True, masking: None)

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

pub fn encode_text_frame_masked_test() {
  let payload = <<"Hello, Joe!":utf8>>
  let mask = <<0x37, 0xfa, 0x21, 0x3d>>

  let encoded_frame =
    websocks.encode_text_frame(payload, final: True, masking: Some(mask))

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

  let encoded_frame =
    websocks.encode_close_frame(
      reason: websocks.NormalClosure(data:),
      masking: None,
    )

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
  let encoded_frame =
    websocks.encode_binary_frame(payload, final: True, masking: None)

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
  let encoded_frame = websocks.encode_ping_frame(payload, masking: None)

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
  let encoded_frame = websocks.encode_pong_frame(payload, masking: None)

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

  let encoded_frame =
    websocks.encode_continuation_frame(payload, final: False, masking: None)

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

  let encoded_frame =
    websocks.encode_text_frame(payload, final: False, masking: None)

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

  let encoded_frame =
    websocks.encode_text_frame(payload, final: True, masking: None)

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

  let encoded_frame =
    websocks.encode_binary_frame(payload, final: True, masking: None)

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

  let encoded_frame =
    websocks.encode_binary_frame(payload, final: True, masking: None)

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

    let encoded_frame = websocks.encode_close_frame(reason, masking: None)

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

  let encoded_frame =
    websocks.encode_close_frame(
      websocks.CustomCloseCode(code:, data:),
      masking: None,
    )

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
  let payload = <<"Hello, World!":utf8>>
  let encoded = websocks.encode_text_frame(payload, final: True, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(websocks.Text(payload:))
}

pub fn round_trip_text_masked_test() {
  let payload = <<"Hello, World!":utf8>>
  let mask = <<0x37, 0xfa, 0x21, 0x3d>>
  let encoded =
    websocks.encode_text_frame(payload, final: True, masking: Some(mask))
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(websocks.Text(payload:))
}

pub fn round_trip_binary_test() {
  let payload = <<0x01, 0x02, 0x03, 0x04, 0x05>>
  let encoded =
    websocks.encode_binary_frame(payload, final: True, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(websocks.Binary(payload:))
}

pub fn round_trip_ping_test() {
  let payload = <<"ping":utf8>>
  let encoded = websocks.encode_ping_frame(payload, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(websocks.Ping(payload:))
}

pub fn round_trip_pong_test() {
  let payload = <<"pong":utf8>>
  let encoded = websocks.encode_pong_frame(payload, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(websocks.Pong(payload:))
}

pub fn round_trip_close_test() {
  let data = <<"bye":utf8>>
  let reason = websocks.NormalClosure(data:)
  let encoded = websocks.encode_close_frame(reason, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(websocks.Close(reason))
}

pub fn round_trip_incomplete_test() {
  let payload = <<"partial":utf8>>
  let encoded = websocks.encode_text_frame(payload, final: False, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Incomplete(websocks.Text(payload:))
}

pub fn round_trip_large_payload_test() {
  let payload =
    list.repeat(0x41, 1000)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })
  let encoded =
    websocks.encode_binary_frame(payload, final: True, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(websocks.Binary(payload:))
}

pub fn round_trip_empty_payload_test() {
  let payload = <<>>
  let encoded = websocks.encode_text_frame(payload, final: True, masking: None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded)
  assert decoded == websocks.Complete(websocks.Text(payload:))
}

// -----------------------------------------------------------------------------
// Resolve Fragments
// -----------------------------------------------------------------------------

pub fn resolve_complete_frames_test() {
  let frames = [
    websocks.Complete(websocks.Text(payload: <<"Hello":utf8>>)),
    websocks.Complete(websocks.Text(payload: <<"World":utf8>>)),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved
    == [
      websocks.Text(payload: <<"Hello":utf8>>),
      websocks.Text(payload: <<"World":utf8>>),
    ]
}

pub fn resolve_empty_frames_test() {
  let frames = []
  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context())
  assert resolved == []
  assert context == websocks.create_context()
}

pub fn resolve_complete_text_not_utf8_test() {
  let frames = [websocks.Complete(websocks.Text(payload: <<0xff, 0xff, 0xff>>))]

  let result = websocks.resolve_fragments(frames, websocks.create_context())

  assert result == Error(websocks.NotUtf8)
}

pub fn resolve_orphaned_continuation_complete_test() {
  let frames = [
    websocks.Complete(websocks.Continuation(payload: <<"test":utf8>>)),
  ]

  let result = websocks.resolve_fragments(frames, websocks.create_context())

  assert result == Error(websocks.OrphanedContinuation)
}

pub fn resolve_orphaned_continuation_incomplete_test() {
  let frames = [
    websocks.Incomplete(websocks.Continuation(payload: <<"test":utf8>>)),
  ]

  let result = websocks.resolve_fragments(frames, websocks.create_context())

  assert result == Error(websocks.OrphanedContinuation)
}

pub fn resolve_control_frame_fragmented_ping_test() {
  let frames = [websocks.Incomplete(websocks.Ping(payload: <<"ping":utf8>>))]

  let result = websocks.resolve_fragments(frames, websocks.create_context())

  assert result == Error(websocks.ControlFrameFragmented)
}

pub fn resolve_control_frame_fragmented_pong_test() {
  let frames = [websocks.Incomplete(websocks.Pong(payload: <<"pong":utf8>>))]

  let result = websocks.resolve_fragments(frames, websocks.create_context())

  assert result == Error(websocks.ControlFrameFragmented)
}

pub fn resolve_control_frame_fragmented_close_test() {
  let frames = [
    websocks.Incomplete(
      websocks.Close(websocks.NormalClosure(data: <<"bye":utf8>>)),
    ),
  ]

  let result = websocks.resolve_fragments(frames, websocks.create_context())

  assert result == Error(websocks.ControlFrameFragmented)
}

pub fn resolve_complete_binary_frame_test() {
  let payload = <<0x01, 0x02, 0x03>>
  let frames = [websocks.Complete(websocks.Binary(payload:))]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == [websocks.Binary(payload:)]
  assert context == websocks.create_context()
}

pub fn resolve_complete_ping_frame_test() {
  let payload = <<"ping":utf8>>
  let frames = [websocks.Complete(websocks.Ping(payload:))]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == [websocks.Ping(payload:)]
}

pub fn resolve_complete_pong_frame_test() {
  let payload = <<"pong":utf8>>
  let frames = [websocks.Complete(websocks.Pong(payload:))]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == [websocks.Pong(payload:)]
}

pub fn resolve_complete_close_frame_test() {
  let frames = [
    websocks.Complete(
      websocks.Close(websocks.NormalClosure(data: <<"bye":utf8>>)),
    ),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved
    == [websocks.Close(websocks.NormalClosure(data: <<"bye":utf8>>))]
}

pub fn resolve_text_fragmentation_simple_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>)),
    websocks.Complete(websocks.Continuation(payload: <<"lo":utf8>>)),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
  assert context == websocks.create_context()
}

pub fn resolve_binary_fragmentation_simple_test() {
  let frames = [
    websocks.Incomplete(websocks.Binary(payload: <<0x01, 0x02>>)),
    websocks.Complete(websocks.Continuation(payload: <<0x03, 0x04>>)),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == [websocks.Binary(payload: <<0x01, 0x02, 0x03, 0x04>>)]
  assert context == websocks.create_context()
}

pub fn resolve_text_fragmentation_multiple_continuations_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"H":utf8>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<"e":utf8>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<"l":utf8>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<"l":utf8>>)),
    websocks.Complete(websocks.Continuation(payload: <<"o":utf8>>)),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
  assert context == websocks.create_context()
}

pub fn resolve_concurrent_fragmentation_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>)),
    websocks.Incomplete(websocks.Text(payload: <<"World":utf8>>)),
  ]

  let result = websocks.resolve_fragments(frames, websocks.create_context())

  assert result == Error(websocks.ConcurrentFragmentation)
}

pub fn resolve_concurrent_fragmentation_binary_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>)),
    websocks.Incomplete(websocks.Binary(payload: <<0x01>>)),
  ]

  let result = websocks.resolve_fragments(frames, websocks.create_context())

  assert result == Error(websocks.ConcurrentFragmentation)
}

pub fn resolve_fragmentation_interrupted_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>)),
    websocks.Complete(websocks.Text(payload: <<"World":utf8>>)),
  ]

  let result = websocks.resolve_fragments(frames, websocks.create_context())

  assert result == Error(websocks.FragmentationInterrupted)
}

pub fn resolve_fragmentation_interrupted_by_binary_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>)),
    websocks.Complete(websocks.Binary(payload: <<0x01>>)),
  ]

  let result = websocks.resolve_fragments(frames, websocks.create_context())

  assert result == Error(websocks.FragmentationInterrupted)
}

pub fn resolve_fragmentation_interrupted_by_ping_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>)),
    websocks.Complete(websocks.Ping(payload: <<"ping":utf8>>)),
  ]

  let result = websocks.resolve_fragments(frames, websocks.create_context())

  assert result == Error(websocks.FragmentationInterrupted)
}

pub fn resolve_context_preserved_incomplete_test() {
  let frames = [websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>))]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == []
  assert websocks.extract_accumulated_context_value(context)
    == Ok(websocks.Text(payload: <<"Hel":utf8>>))
}

pub fn resolve_context_continuation_test() {
  let frames = [websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>))]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == []

  let next_frames = [
    websocks.Complete(websocks.Continuation(payload: <<"lo":utf8>>)),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(next_frames, context)

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
  assert context == websocks.create_context()
}

pub fn resolve_fragmentation_with_subsequent_message_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>)),
    websocks.Complete(websocks.Continuation(payload: <<"lo":utf8>>)),
    websocks.Complete(websocks.Text(payload: <<"World":utf8>>)),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved
    == [
      websocks.Text(payload: <<"Hello":utf8>>),
      websocks.Text(payload: <<"World":utf8>>),
    ]
  assert context == websocks.create_context()
}

pub fn resolve_multiple_fragmentations_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>)),
    websocks.Complete(websocks.Continuation(payload: <<"lo":utf8>>)),
    websocks.Incomplete(websocks.Binary(payload: <<0x01>>)),
    websocks.Complete(websocks.Continuation(payload: <<0x02>>)),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved
    == [
      websocks.Text(payload: <<"Hello":utf8>>),
      websocks.Binary(payload: <<0x01, 0x02>>),
    ]
  assert context == websocks.create_context()
}

pub fn resolve_fragmented_text_utf8_validation_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>)),
    websocks.Complete(websocks.Continuation(payload: <<"lo":utf8>>)),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
}

pub fn resolve_empty_payload_frames_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<>>)),
    websocks.Complete(websocks.Continuation(payload: <<"Hello":utf8>>)),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
}

pub fn resolve_fragmentation_empty_continuation_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"Hello":utf8>>)),
    websocks.Complete(websocks.Continuation(payload: <<>>)),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
}

pub fn resolve_long_fragmentation_chain_test() {
  let frames = [
    websocks.Incomplete(websocks.Binary(payload: <<0x01>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<0x02>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<0x03>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<0x04>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<0x05>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<0x06>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<0x07>>)),
    websocks.Complete(websocks.Continuation(payload: <<0x08>>)),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved
    == [
      websocks.Binary(payload: <<
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
      >>),
    ]
}

pub fn resolve_mixed_complete_and_fragmented_test() {
  let frames = [
    websocks.Complete(websocks.Text(payload: <<"First":utf8>>)),
    websocks.Incomplete(websocks.Binary(payload: <<0x01>>)),
    websocks.Complete(websocks.Continuation(payload: <<0x02>>)),
    websocks.Complete(websocks.Text(payload: <<"Last":utf8>>)),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved
    == [
      websocks.Text(payload: <<"First":utf8>>),
      websocks.Binary(payload: <<0x01, 0x02>>),
      websocks.Text(payload: <<"Last":utf8>>),
    ]
}

pub fn resolve_context_preserved_mid_fragmentation_test() {
  let frames = [
    websocks.Incomplete(websocks.Text(payload: <<"Hel":utf8>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<"lo":utf8>>)),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context())

  assert resolved == []
  assert websocks.extract_accumulated_context_value(context)
    == Ok(websocks.Text(payload: <<"Hello":utf8>>))

  let next_frames = [
    websocks.Incomplete(websocks.Continuation(payload: <<" Wor":utf8>>)),
    websocks.Complete(websocks.Continuation(payload: <<"ld":utf8>>)),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(next_frames, context)

  assert resolved == [websocks.Text(payload: <<"Hello World":utf8>>)]
  assert context == websocks.create_context()
}

pub fn resolve_stream_simulation_test() {
  let batch1 = [
    websocks.Complete(websocks.Text(payload: <<"Message1":utf8>>)),
    websocks.Incomplete(websocks.Binary(payload: <<0x01, 0x02>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<0x03>>)),
  ]

  let assert Ok(#(resolved1, context1)) =
    websocks.resolve_fragments(batch1, websocks.create_context())
  assert resolved1 == [websocks.Text(payload: <<"Message1":utf8>>)]
  assert websocks.extract_accumulated_context_value(context1)
    == Ok(websocks.Binary(payload: <<0x01, 0x02, 0x03>>))

  let batch2 = [
    websocks.Incomplete(websocks.Continuation(payload: <<0x04, 0x05>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<0x06>>)),
  ]

  let assert Ok(#(resolved2, context2)) =
    websocks.resolve_fragments(batch2, context1)
  assert resolved2 == []
  assert websocks.extract_accumulated_context_value(context2)
    == Ok(websocks.Binary(payload: <<0x01, 0x02, 0x03, 0x04, 0x05, 0x06>>))

  let batch3 = [
    websocks.Complete(websocks.Continuation(payload: <<0x07, 0x08>>)),
    websocks.Complete(websocks.Ping(payload: <<"ping":utf8>>)),
    websocks.Incomplete(websocks.Text(payload: <<"Frag":utf8>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<"ment":utf8>>)),
  ]

  let assert Ok(#(resolved3, context3)) =
    websocks.resolve_fragments(batch3, context2)
  assert resolved3
    == [
      websocks.Binary(payload: <<
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
      >>),
      websocks.Ping(payload: <<"ping":utf8>>),
    ]
  assert websocks.extract_accumulated_context_value(context3)
    == Ok(websocks.Text(payload: <<"Fragment":utf8>>))

  let batch4 = [
    websocks.Incomplete(websocks.Continuation(payload: <<"ed":utf8>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<" Text":utf8>>)),
  ]

  let assert Ok(#(resolved4, context4)) =
    websocks.resolve_fragments(batch4, context3)
  assert resolved4 == []
  assert websocks.extract_accumulated_context_value(context4)
    == Ok(websocks.Text(payload: <<"Fragmented Text":utf8>>))

  let batch5 = [
    websocks.Complete(websocks.Continuation(payload: <<" Message":utf8>>)),
    websocks.Complete(websocks.Text(payload: <<"Complete":utf8>>)),
    websocks.Incomplete(websocks.Binary(payload: <<0xaa>>)),
  ]

  let assert Ok(#(resolved5, context5)) =
    websocks.resolve_fragments(batch5, context4)
  assert resolved5
    == [
      websocks.Text(payload: <<"Fragmented Text Message":utf8>>),
      websocks.Text(payload: <<"Complete":utf8>>),
    ]
  assert websocks.extract_accumulated_context_value(context5)
    == Ok(websocks.Binary(payload: <<0xaa>>))

  let batch6 = [
    websocks.Incomplete(websocks.Continuation(payload: <<0xbb, 0xcc>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<0xdd>>)),
    websocks.Complete(websocks.Continuation(payload: <<0xee, 0xff>>)),
    websocks.Complete(websocks.Pong(payload: <<"pong":utf8>>)),
  ]

  let assert Ok(#(resolved6, context6)) =
    websocks.resolve_fragments(batch6, context5)
  assert resolved6
    == [
      websocks.Binary(payload: <<0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff>>),
      websocks.Pong(payload: <<"pong":utf8>>),
    ]
  assert context6 == websocks.create_context()

  let batch7 = [
    websocks.Incomplete(websocks.Text(payload: <<"Multi":utf8>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<"-":utf8>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<"part":utf8>>)),
  ]

  let assert Ok(#(resolved7, context7)) =
    websocks.resolve_fragments(batch7, context6)
  assert resolved7 == []
  assert websocks.extract_accumulated_context_value(context7)
    == Ok(websocks.Text(payload: <<"Multi-part":utf8>>))

  let batch8 = [
    websocks.Incomplete(websocks.Continuation(payload: <<" stream":utf8>>)),
    websocks.Incomplete(websocks.Continuation(payload: <<" test":utf8>>)),
    websocks.Complete(websocks.Continuation(payload: <<"!":utf8>>)),
    websocks.Complete(
      websocks.Close(websocks.NormalClosure(data: <<"done":utf8>>)),
    ),
  ]

  let assert Ok(#(resolved8, context8)) =
    websocks.resolve_fragments(batch8, context7)
  assert resolved8
    == [
      websocks.Text(payload: <<"Multi-part stream test!":utf8>>),
      websocks.Close(websocks.NormalClosure(data: <<"done":utf8>>)),
    ]
  assert context8 == websocks.create_context()
}
