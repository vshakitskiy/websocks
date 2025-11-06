import frame
import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/result
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
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, rest)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Text(payload:),
      final: True,
      compressed: False,
    )
  assert rest == <<>>
}

pub fn decode_complete_text_masked_frame_test() {
  let payload = <<"Hello, Joe!":utf8>>
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: Some(<<0x37, 0xfa, 0x21, 0x3d>>),
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Text(payload:),
      final: True,
      compressed: False,
    )
}

pub fn decode_incomplete_text_continuation_unmasked_frame_test() {
  let payload = <<"Hello, Joe!":utf8>>
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: False,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Continuation,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Continuation(payload:),
      final: False,
      compressed: False,
    )
}

pub fn decode_need_more_data_test() {
  let context = websocks.create_context(None)
  let decoded_frame = websocks.decode_frame(frame.unfinished_frame, context)
  assert decoded_frame == Error(websocks.NotEnoughData(frame.unfinished_frame))
}

pub fn decode_invalid_frame_test() {
  let context = websocks.create_context(None)
  let decoded_frame = websocks.decode_frame(frame.invalid_opcode_frame, context)
  assert decoded_frame == Error(websocks.InvalidFrame)
}

pub fn decode_ping_frame_test() {
  let payload = <<"Hello, Joe!":utf8>>
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Ping,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Control(websocks.Ping(payload:)),
      final: True,
      compressed: False,
    )
}

pub fn decode_normal_close_frame_test() {
  let data = <<"Hello, Joe!":utf8>>
  let payload = <<1000:size(16), data:bits>>
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Close,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Control(websocks.Close(websocks.NormalClosure(data:))),
      final: True,
      compressed: False,
    )
}

pub fn decode_custom_close_code_frame_test() {
  let code = 4180
  let data = <<"Hello, Joe!":utf8>>
  let payload = <<code:size(16), data:bits>>
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Close,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Control(websocks.Close(websocks.CustomCloseCode(code:, data:))),
      final: True,
      compressed: False,
    )
}

pub fn decode_frame_with_leftover_data_test() {
  let payload = <<"Hello, ":utf8>>
  let next_payload = <<"Joe!":utf8>>
  let context = websocks.create_context(None)

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

  let assert Ok(#(decoded, next_frame)) =
    websocks.decode_frame(<<frame:bits, next_frame:bits>>, context)
  assert decoded
    == websocks.to_decoded_frame(
      websocks.Text(payload:),
      final: False,
      compressed: False,
    )

  let assert Ok(#(decoded2, <<>>)) = websocks.decode_frame(next_frame, context)
  assert decoded2
    == websocks.to_decoded_frame(
      websocks.Continuation(payload: next_payload),
      final: True,
      compressed: False,
    )
}

pub fn decode_binary_frame_test() {
  let payload = <<0x01, 0x02, 0x03, 0x04, 0x05>>
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Binary(payload:),
      final: True,
      compressed: False,
    )
}

pub fn decode_pong_frame_test() {
  let payload = <<"pong":utf8>>
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Pong,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Control(websocks.Pong(payload:)),
      final: True,
      compressed: False,
    )
}

pub fn decode_empty_payload_frame_test() {
  let payload = <<>>
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Text(payload:),
      final: True,
      compressed: False,
    )
}

pub fn decode_125_byte_boundary_test() {
  let payload =
    list.repeat(0x41, 125)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Binary(payload:),
      final: True,
      compressed: False,
    )
}

pub fn decode_126_byte_extended_length_test() {
  let payload =
    list.repeat(0x41, 126)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Binary(payload:),
      final: True,
      compressed: False,
    )
}

pub fn decode_200_byte_extended_length_test() {
  let payload =
    list.repeat(0x41, 200)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Text(payload:),
      final: True,
      compressed: False,
    )
}

pub fn decode_65535_byte_boundary_test() {
  let payload =
    list.repeat(0x41, 65_535)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })
  let context = websocks.create_context(None)

  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Binary(payload:),
      final: True,
      compressed: False,
    )
}

pub fn decode_all_standard_close_codes_test() {
  let data = <<>>
  let context = websocks.create_context(None)
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

    let assert Ok(#(decoded, <<>>)) =
      frame.construct(
        fin: True,
        rsv1: False,
        rsv2: False,
        rsv3: False,
        opcode: frame.Close,
        mask: None,
        payload:,
      )
      |> websocks.decode_frame(context)

    assert decoded
      == websocks.to_decoded_frame(
        websocks.Control(websocks.Close(reason)),
        final: True,
        compressed: False,
      )
  })
}

pub fn decode_close_empty_data_test() {
  let data = <<>>
  let payload = <<1000:size(16), data:bits>>
  let context = websocks.create_context(None)
  let assert Ok(#(decoded, <<>>)) =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Close,
      mask: None,
      payload:,
    )
    |> websocks.decode_frame(context)

  assert decoded
    == websocks.to_decoded_frame(
      websocks.Control(websocks.Close(websocks.NormalClosure(data:))),
      final: True,
      compressed: False,
    )
}

// -----------------------------------------------------------------------------
// Decode Many Frames
// -----------------------------------------------------------------------------

pub fn decode_many_frames_single_complete_frame_test() {
  let payload = <<"Hello":utf8>>
  let context = websocks.create_context(None)
  let frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )

  let assert Ok(#(decoded_frames, context)) =
    websocks.decode_many_frames(frame, context)

  assert decoded_frames
    == [
      websocks.to_decoded_frame(
        websocks.Text(payload:),
        final: True,
        compressed: False,
      ),
    ]
  assert websocks.extract_buffer(context) == <<>>
}

pub fn decode_many_frames_multiple_complete_frames_test() {
  let payload1 = <<"Hello":utf8>>
  let payload2 = <<"World":utf8>>
  let context = websocks.create_context(None)

  let frame1 =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload: payload1,
    )

  let frame2 =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload: payload2,
    )

  let assert Ok(#(decoded_frames, context)) =
    websocks.decode_many_frames(<<frame1:bits, frame2:bits>>, context)

  assert decoded_frames
    == [
      websocks.to_decoded_frame(
        websocks.Text(payload: payload1),
        final: True,
        compressed: False,
      ),
      websocks.to_decoded_frame(
        websocks.Text(payload: payload2),
        final: True,
        compressed: False,
      ),
    ]
  assert websocks.extract_buffer(context) == <<>>
}

pub fn decode_many_frames_partial_frame_stored_in_buffer_test() {
  let payload = <<"Hello":utf8>>
  let context = websocks.create_context(None)
  let frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )

  let partial = bit_array.slice(frame, 0, 1) |> result.unwrap(<<>>)

  let assert Ok(#(decoded_frames, context)) =
    websocks.decode_many_frames(partial, context)

  assert decoded_frames == []
  assert websocks.extract_buffer(context) == partial
}

pub fn decode_many_frames_partial_then_complete_test() {
  let payload = <<"Hello":utf8>>
  let context = websocks.create_context(None)
  let frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload:,
    )

  let partial = bit_array.slice(frame, 0, 3) |> result.unwrap(<<>>)
  let assert Ok(#(decoded_frames1, context1)) =
    websocks.decode_many_frames(partial, context)

  assert decoded_frames1 == []
  assert websocks.extract_buffer(context1) == partial

  let rest =
    bit_array.slice(frame, 3, bit_array.byte_size(frame) - 3)
    |> result.unwrap(<<>>)
  let assert Ok(#(decoded_frames2, context2)) =
    websocks.decode_many_frames(rest, context1)

  assert decoded_frames2
    == [
      websocks.to_decoded_frame(
        websocks.Text(payload:),
        final: True,
        compressed: False,
      ),
    ]
  assert websocks.extract_buffer(context2) == <<>>
}

pub fn decode_many_frames_empty_data_test() {
  let context = websocks.create_context(None)
  let assert Ok(#(decoded_frames, context)) =
    websocks.decode_many_frames(<<>>, context)

  assert decoded_frames == []
  assert websocks.is_empty_context(context)
}

pub fn decode_many_frames_invalid_frame_test() {
  // FIN=1, RSV=0, OPCODE=15, MASK=0, PAYLOAD_LEN=0
  let invalid_frame = <<0x8F, 0x00>>
  let context = websocks.create_context(None)
  let result = websocks.decode_many_frames(invalid_frame, context)

  assert result == Error(Nil)
}

pub fn decode_many_frames_mixed_frame_types_test() {
  let text_payload = <<"Hello":utf8>>
  let binary_payload = <<0x01, 0x02, 0x03>>
  let ping_payload = <<"ping":utf8>>

  let context = websocks.create_context(None)

  let text_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload: text_payload,
    )

  let binary_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Binary,
      mask: None,
      payload: binary_payload,
    )

  let ping_frame =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Ping,
      mask: None,
      payload: ping_payload,
    )

  let assert Ok(#(decoded_frames, context)) =
    websocks.decode_many_frames(
      <<text_frame:bits, binary_frame:bits, ping_frame:bits>>,
      context,
    )

  assert decoded_frames
    == [
      websocks.to_decoded_frame(
        websocks.Text(payload: text_payload),
        final: True,
        compressed: False,
      ),
      websocks.to_decoded_frame(
        websocks.Binary(payload: binary_payload),
        final: True,
        compressed: False,
      ),
      websocks.to_decoded_frame(
        websocks.Control(websocks.Ping(payload: ping_payload)),
        final: True,
        compressed: False,
      ),
    ]
  assert websocks.extract_buffer(context) == <<>>
}

pub fn decode_many_frames_buffer_persists_across_calls_test() {
  let payload1 = <<"First":utf8>>
  let payload2 = <<"Second":utf8>>

  let context = websocks.create_context(None)

  let frame1 =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload: payload1,
    )

  let frame2 =
    frame.construct(
      fin: True,
      rsv1: False,
      rsv2: False,
      rsv3: False,
      opcode: frame.Text,
      mask: None,
      payload: payload2,
    )

  let partial1 = bit_array.slice(frame1, 0, 5) |> result.unwrap(<<>>)
  let assert Ok(#(decoded_frames1, context1)) =
    websocks.decode_many_frames(partial1, context)

  assert decoded_frames1 == []

  let rest1 =
    bit_array.slice(frame1, 5, bit_array.byte_size(frame1) - 5)
    |> result.unwrap(<<>>)
  let partial2 = bit_array.slice(frame2, 0, 5) |> result.unwrap(<<>>)
  let assert Ok(#(decoded_frames2, context2)) =
    websocks.decode_many_frames(<<rest1:bits, partial2:bits>>, context1)

  assert decoded_frames2
    == [
      websocks.to_decoded_frame(
        websocks.Text(payload: payload1),
        final: True,
        compressed: False,
      ),
    ]

  let rest2 =
    bit_array.slice(frame2, 5, bit_array.byte_size(frame2) - 5)
    |> result.unwrap(<<>>)
  let assert Ok(#(decoded_frames3, context3)) =
    websocks.decode_many_frames(rest2, context2)

  assert decoded_frames3
    == [
      websocks.to_decoded_frame(
        websocks.Text(payload: payload2),
        final: True,
        compressed: False,
      ),
    ]
  assert websocks.extract_buffer(context3) == <<>>
}

// -----------------------------------------------------------------------------
// Encode
// -----------------------------------------------------------------------------

pub fn encode_text_frame_test() {
  let payload = <<"Hello, Joe!":utf8>>
  let context = websocks.create_context(None)

  let encoded_frame =
    websocks.encode_text_frame(payload, context:, masking: None)

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
  let context = websocks.create_context(None)

  let encoded_frame =
    websocks.encode_text_frame(payload, context:, masking: Some(mask))

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
    websocks.encode_binary_frame(
      payload,
      context: websocks.create_context(None),
      masking: None,
    )

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

pub fn encode_empty_payload_test() {
  let payload = <<>>

  let encoded_frame =
    websocks.encode_text_frame(
      payload,
      context: websocks.create_context(None),
      masking: None,
    )

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
    websocks.encode_binary_frame(
      payload,
      context: websocks.create_context(None),
      masking: None,
    )

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
    websocks.encode_binary_frame(
      payload,
      context: websocks.create_context(None),
      masking: None,
    )

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

pub fn encode_text_frame_with_compression_test() {
  let payload = <<"Hello, World!":utf8>>
  let compressed_context =
    websocks.create_context(
      Some(websocks.ContextTakeover(no_client: False, no_server: False)),
    )

  let encoded_frame =
    websocks.encode_text_frame(
      payload,
      context: compressed_context,
      masking: None,
    )

  let assert Ok(#(decoded, <<>>)) =
    websocks.decode_frame(encoded_frame, compressed_context)
  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: False, no_server: False)),
      ),
    )

  assert resolved == [websocks.Text(payload:)]
}

pub fn encode_binary_frame_with_compression_test() {
  let payload = <<0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08>>
  let compressed_context =
    websocks.create_context(
      Some(websocks.ContextTakeover(no_client: False, no_server: False)),
    )

  let encoded_frame =
    websocks.encode_binary_frame(
      payload,
      context: compressed_context,
      masking: None,
    )

  let assert Ok(#(decoded, <<>>)) =
    websocks.decode_frame(encoded_frame, compressed_context)
  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: False, no_server: False)),
      ),
    )

  assert resolved == [websocks.Binary(payload:)]
}

pub fn encode_text_frame_with_compression_and_masking_test() {
  let payload = <<"Test message":utf8>>
  let mask = <<0x37, 0xfa, 0x21, 0x3d>>
  let compressed_context =
    websocks.create_context(
      Some(websocks.ContextTakeover(no_client: False, no_server: False)),
    )

  let encoded_frame =
    websocks.encode_text_frame(
      payload,
      context: compressed_context,
      masking: Some(mask),
    )

  let assert Ok(#(decoded, <<>>)) =
    websocks.decode_frame(encoded_frame, compressed_context)
  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: False, no_server: False)),
      ),
    )

  assert resolved == [websocks.Text(payload:)]
}

pub fn encode_text_frame_compressed_payload_smaller_test() {
  let payload =
    list.repeat(0x41, 100)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })

  let compressed_context =
    websocks.create_context(
      Some(websocks.ContextTakeover(no_client: False, no_server: False)),
    )

  let encoded_frame =
    websocks.encode_text_frame(
      payload,
      context: compressed_context,
      masking: None,
    )

  let assert Ok(#(decoded, <<>>)) =
    websocks.decode_frame(encoded_frame, compressed_context)
  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: False, no_server: False)),
      ),
    )

  assert resolved == [websocks.Text(payload:)]
}

pub fn encode_binary_frame_with_compression_no_context_takeover_test() {
  let payload = <<"No context takeover":utf8>>
  let compressed_context =
    websocks.create_context(
      Some(websocks.ContextTakeover(no_client: True, no_server: True)),
    )

  let encoded_frame =
    websocks.encode_binary_frame(
      payload,
      context: compressed_context,
      masking: None,
    )

  let assert Ok(#(decoded, <<>>)) =
    websocks.decode_frame(encoded_frame, compressed_context)
  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: True, no_server: True)),
      ),
    )

  assert resolved == [websocks.Binary(payload:)]
}

pub fn encode_text_frame_empty_payload_with_compression_test() {
  let payload = <<>>
  let compressed_context =
    websocks.create_context(
      Some(websocks.ContextTakeover(no_client: False, no_server: False)),
    )

  let encoded_frame =
    websocks.encode_text_frame(
      payload,
      context: compressed_context,
      masking: None,
    )

  let assert Ok(#(decoded, <<>>)) =
    websocks.decode_frame(encoded_frame, compressed_context)
  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: False, no_server: False)),
      ),
    )

  assert resolved == [websocks.Text(payload:)]
}

// -----------------------------------------------------------------------------
// Round-Trip
// -----------------------------------------------------------------------------

pub fn round_trip_text_test() {
  let payload = <<"Hello, World!":utf8>>
  let encoded =
    websocks.encode_text_frame(
      payload,
      context: websocks.create_context(None),
      masking: None,
    )
  let context = websocks.create_context(None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded, context)
  assert decoded
    == websocks.to_decoded_frame(
      websocks.Text(payload:),
      final: True,
      compressed: False,
    )
}

pub fn round_trip_text_masked_test() {
  let payload = <<"Hello, World!":utf8>>
  let mask = <<0x37, 0xfa, 0x21, 0x3d>>
  let encoded =
    websocks.encode_text_frame(
      payload,
      context: websocks.create_context(None),
      masking: Some(mask),
    )
  let context = websocks.create_context(None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded, context)
  assert decoded
    == websocks.to_decoded_frame(
      websocks.Text(payload:),
      final: True,
      compressed: False,
    )
}

pub fn round_trip_binary_test() {
  let payload = <<0x01, 0x02, 0x03, 0x04, 0x05>>
  let encoded =
    websocks.encode_binary_frame(
      payload,
      context: websocks.create_context(None),
      masking: None,
    )
  let context = websocks.create_context(None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded, context)
  assert decoded
    == websocks.to_decoded_frame(
      websocks.Binary(payload:),
      final: True,
      compressed: False,
    )
}

pub fn round_trip_ping_test() {
  let payload = <<"ping":utf8>>
  let encoded = websocks.encode_ping_frame(payload, masking: None)
  let context = websocks.create_context(None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded, context)
  assert decoded
    == websocks.to_decoded_frame(
      websocks.Control(websocks.Ping(payload:)),
      final: True,
      compressed: False,
    )
}

pub fn round_trip_pong_test() {
  let payload = <<"pong":utf8>>
  let encoded = websocks.encode_pong_frame(payload, masking: None)
  let context = websocks.create_context(None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded, context)
  assert decoded
    == websocks.to_decoded_frame(
      websocks.Control(websocks.Pong(payload:)),
      final: True,
      compressed: False,
    )
}

pub fn round_trip_close_test() {
  let data = <<"bye":utf8>>
  let reason = websocks.NormalClosure(data:)
  let encoded = websocks.encode_close_frame(reason, masking: None)
  let context = websocks.create_context(None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded, context)
  assert decoded
    == websocks.to_decoded_frame(
      websocks.Control(websocks.Close(reason)),
      final: True,
      compressed: False,
    )
}

pub fn round_trip_large_payload_test() {
  let payload =
    list.repeat(0x41, 1000)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })
  let encoded =
    websocks.encode_binary_frame(
      payload,
      context: websocks.create_context(None),
      masking: None,
    )
  let context = websocks.create_context(None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded, context)
  assert decoded
    == websocks.to_decoded_frame(
      websocks.Binary(payload:),
      final: True,
      compressed: False,
    )
}

pub fn round_trip_empty_payload_test() {
  let payload = <<>>
  let encoded =
    websocks.encode_text_frame(
      payload,
      context: websocks.create_context(None),
      masking: None,
    )
  let context = websocks.create_context(None)
  let assert Ok(#(decoded, <<>>)) = websocks.decode_frame(encoded, context)
  assert decoded
    == websocks.to_decoded_frame(
      websocks.Text(payload:),
      final: True,
      compressed: False,
    )
}

// -----------------------------------------------------------------------------
// Resolve Fragments
// -----------------------------------------------------------------------------

pub fn resolve_complete_frames_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hello":utf8>>),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"World":utf8>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved
    == [
      websocks.Text(payload: <<"Hello":utf8>>),
      websocks.Text(payload: <<"World":utf8>>),
    ]
}

pub fn resolve_empty_frames_test() {
  let frames = []
  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))
  assert resolved == []
  assert websocks.is_empty_context(context)
}

pub fn resolve_complete_text_not_utf8_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<0xff, 0xff, 0xff>>),
      final: True,
      compressed: False,
    ),
  ]

  assert Error(websocks.NotUtf8)
    == websocks.resolve_fragments(frames, websocks.create_context(None))
}

pub fn resolve_orphaned_continuation_complete_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"test":utf8>>),
      final: True,
      compressed: False,
    ),
  ]

  assert Error(websocks.OrphanedContinuation)
    == websocks.resolve_fragments(frames, websocks.create_context(None))
}

pub fn resolve_orphaned_continuation_incomplete_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"test":utf8>>),
      final: False,
      compressed: False,
    ),
  ]

  assert Error(websocks.OrphanedContinuation)
    == websocks.resolve_fragments(frames, websocks.create_context(None))
}

pub fn resolve_complete_binary_frame_test() {
  let payload = <<0x01, 0x02, 0x03>>
  let frames = [
    websocks.to_decoded_frame(
      websocks.Binary(payload:),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == [websocks.Binary(payload:)]
  assert websocks.is_empty_context(context)
}

pub fn resolve_complete_ping_frame_test() {
  let payload = <<"ping":utf8>>
  let frames = [
    websocks.to_decoded_frame(
      websocks.Control(websocks.Ping(payload:)),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == [websocks.Control(websocks.Ping(payload:))]
}

pub fn resolve_complete_pong_frame_test() {
  let payload = <<"pong":utf8>>
  let frames = [
    websocks.to_decoded_frame(
      websocks.Control(websocks.Pong(payload:)),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == [websocks.Control(websocks.Pong(payload:))]
}

pub fn resolve_complete_close_frame_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Control(
        websocks.Close(websocks.NormalClosure(data: <<"bye":utf8>>)),
      ),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved
    == [
      websocks.Control(
        websocks.Close(websocks.NormalClosure(data: <<"bye":utf8>>)),
      ),
    ]
}

pub fn resolve_text_fragmentation_simple_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hel":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"lo":utf8>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
  assert websocks.is_empty_context(context)
}

pub fn resolve_binary_fragmentation_simple_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Binary(payload: <<0x01, 0x02>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x03, 0x04>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == [websocks.Binary(payload: <<0x01, 0x02, 0x03, 0x04>>)]
  assert websocks.is_empty_context(context)
}

pub fn resolve_text_fragmentation_multiple_continuations_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"H":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"e":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"l":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"l":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"o":utf8>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
  assert websocks.is_empty_context(context)
}

pub fn resolve_concurrent_fragmentation_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hel":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"World":utf8>>),
      final: False,
      compressed: False,
    ),
  ]
  assert Error(websocks.ConcurrentFragmentation)
    == websocks.resolve_fragments(frames, websocks.create_context(None))
}

pub fn resolve_concurrent_fragmentation_binary_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hel":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Binary(payload: <<0x01>>),
      final: False,
      compressed: False,
    ),
  ]

  let result = websocks.resolve_fragments(frames, websocks.create_context(None))

  assert result == Error(websocks.ConcurrentFragmentation)
}

pub fn resolve_fragmentation_interrupted_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hel":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"World":utf8>>),
      final: True,
      compressed: False,
    ),
  ]
  assert Error(websocks.FragmentationInterrupted)
    == websocks.resolve_fragments(frames, websocks.create_context(None))
}

pub fn resolve_fragmentation_interrupted_by_binary_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hel":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Binary(payload: <<0x01>>),
      final: True,
      compressed: False,
    ),
  ]
  assert Error(websocks.FragmentationInterrupted)
    == websocks.resolve_fragments(frames, websocks.create_context(None))
}

pub fn resolve_context_preserved_incomplete_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hel":utf8>>),
      final: False,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == []
  assert websocks.extract_accumulating_frame(context)
    == Ok(websocks.Text(payload: <<"Hel":utf8>>))
}

pub fn resolve_context_continuation_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hel":utf8>>),
      final: False,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == []

  let next_frames = [
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"lo":utf8>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(next_frames, context)

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
  assert websocks.is_empty_context(context)
}

pub fn resolve_fragmentation_with_subsequent_message_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hel":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"lo":utf8>>),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"World":utf8>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved
    == [
      websocks.Text(payload: <<"Hello":utf8>>),
      websocks.Text(payload: <<"World":utf8>>),
    ]
  assert websocks.is_empty_context(context)
}

pub fn resolve_multiple_fragmentations_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hel":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"lo":utf8>>),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Binary(payload: <<0x01>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x02>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved
    == [
      websocks.Text(payload: <<"Hello":utf8>>),
      websocks.Binary(payload: <<0x01, 0x02>>),
    ]
  assert websocks.is_empty_context(context)
}

pub fn resolve_fragmented_text_utf8_validation_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hel":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"lo":utf8>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
}

pub fn resolve_empty_payload_frames_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"Hello":utf8>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
}

pub fn resolve_fragmentation_empty_continuation_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hello":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == [websocks.Text(payload: <<"Hello":utf8>>)]
}

pub fn resolve_long_fragmentation_chain_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Binary(payload: <<0x01>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x02>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x03>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x04>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x05>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x06>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x07>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x08>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

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
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"First":utf8>>),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Binary(payload: <<0x01>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x02>>),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Last":utf8>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved
    == [
      websocks.Text(payload: <<"First":utf8>>),
      websocks.Binary(payload: <<0x01, 0x02>>),
      websocks.Text(payload: <<"Last":utf8>>),
    ]
}

pub fn resolve_context_preserved_mid_fragmentation_test() {
  let frames = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hel":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"lo":utf8>>),
      final: False,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(frames, websocks.create_context(None))

  assert resolved == []
  assert websocks.extract_accumulating_frame(context)
    == Ok(websocks.Text(payload: <<"Hello":utf8>>))

  let next_frames = [
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<" Wor":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"ld":utf8>>),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved, context)) =
    websocks.resolve_fragments(next_frames, context)

  assert resolved == [websocks.Text(payload: <<"Hello World":utf8>>)]
  assert websocks.is_empty_context(context)
}

pub fn resolve_stream_simulation_test() {
  let batch1 = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Message1":utf8>>),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Binary(payload: <<0x01, 0x02>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x03>>),
      final: False,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved1, context1)) =
    websocks.resolve_fragments(batch1, websocks.create_context(None))
  assert resolved1 == [websocks.Text(payload: <<"Message1":utf8>>)]
  assert websocks.extract_accumulating_frame(context1)
    == Ok(websocks.Binary(payload: <<0x01, 0x02, 0x03>>))

  let batch2 = [
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x04, 0x05>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x06>>),
      final: False,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved2, context2)) =
    websocks.resolve_fragments(batch2, context1)
  assert resolved2 == []
  assert websocks.extract_accumulating_frame(context2)
    == Ok(websocks.Binary(payload: <<0x01, 0x02, 0x03, 0x04, 0x05, 0x06>>))

  let batch3 = [
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0x07, 0x08>>),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Control(websocks.Ping(payload: <<"ping":utf8>>)),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Frag":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"ment":utf8>>),
      final: False,
      compressed: False,
    ),
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
      websocks.Control(websocks.Ping(payload: <<"ping":utf8>>)),
    ]
  assert websocks.extract_accumulating_frame(context3)
    == Ok(websocks.Text(payload: <<"Fragment":utf8>>))

  let batch4 = [
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"ed":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<" Text":utf8>>),
      final: False,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved4, context4)) =
    websocks.resolve_fragments(batch4, context3)
  assert resolved4 == []
  assert websocks.extract_accumulating_frame(context4)
    == Ok(websocks.Text(payload: <<"Fragmented Text":utf8>>))

  let batch5 = [
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<" Message":utf8>>),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Complete":utf8>>),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Binary(payload: <<0xaa>>),
      final: False,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved5, context5)) =
    websocks.resolve_fragments(batch5, context4)
  assert resolved5
    == [
      websocks.Text(payload: <<"Fragmented Text Message":utf8>>),
      websocks.Text(payload: <<"Complete":utf8>>),
    ]
  assert websocks.extract_accumulating_frame(context5)
    == Ok(websocks.Binary(payload: <<0xaa>>))

  let batch6 = [
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0xbb, 0xcc>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0xdd>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<0xee, 0xff>>),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Control(websocks.Pong(payload: <<"pong":utf8>>)),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved6, context6)) =
    websocks.resolve_fragments(batch6, context5)
  assert resolved6
    == [
      websocks.Binary(payload: <<0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff>>),
      websocks.Control(websocks.Pong(payload: <<"pong":utf8>>)),
    ]
  assert websocks.is_empty_context(context6)

  let batch7 = [
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Multi":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"-":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"part":utf8>>),
      final: False,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved7, context7)) =
    websocks.resolve_fragments(batch7, context6)
  assert resolved7 == []
  assert websocks.extract_accumulating_frame(context7)
    == Ok(websocks.Text(payload: <<"Multi-part":utf8>>))

  let batch8 = [
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<" stream":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<" test":utf8>>),
      final: False,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Continuation(payload: <<"!":utf8>>),
      final: True,
      compressed: False,
    ),
    websocks.to_decoded_frame(
      websocks.Control(
        websocks.Close(websocks.NormalClosure(data: <<"done":utf8>>)),
      ),
      final: True,
      compressed: False,
    ),
  ]

  let assert Ok(#(resolved8, context8)) =
    websocks.resolve_fragments(batch8, context7)
  assert resolved8
    == [
      websocks.Text(payload: <<"Multi-part stream test!":utf8>>),
      websocks.Control(
        websocks.Close(websocks.NormalClosure(data: <<"done":utf8>>)),
      ),
    ]
  assert websocks.is_empty_context(context8)
}

pub fn resolve_compressed_text_frame_decompression_test() {
  let original = <<"Hello, World!":utf8>>
  let compressed = websocks.compress_payload(original)

  let decoded_frame =
    websocks.to_decoded_frame(
      websocks.Text(payload: compressed),
      final: True,
      compressed: True,
    )

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded_frame],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: False, no_server: False)),
      ),
    )

  assert resolved == [websocks.Text(payload: original)]
}

pub fn resolve_compressed_binary_frame_decompression_test() {
  let original = <<0x01, 0x02, 0x03, 0x04, 0x05>>
  let compressed = websocks.compress_payload(original)

  let decoded_frame =
    websocks.to_decoded_frame(
      websocks.Binary(payload: compressed),
      final: True,
      compressed: True,
    )

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded_frame],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: False, no_server: False)),
      ),
    )

  assert resolved == [websocks.Binary(payload: original)]
}

pub fn resolve_compressed_text_fragmentation_decompression_test() {
  let full_original = <<"Hello World!":utf8>>
  let compressed = websocks.compress_payload(full_original)
  let compressed_size = bit_array.byte_size(compressed)
  let split_point = compressed_size - 10
  let compressed_part1 =
    bit_array.slice(compressed, 0, split_point) |> result.unwrap(<<>>)
  let compressed_part2 =
    bit_array.slice(compressed, split_point, compressed_size - split_point)
    |> result.unwrap(<<>>)

  let decoded_frame1 =
    websocks.to_decoded_frame(
      websocks.Text(payload: compressed_part1),
      final: False,
      compressed: True,
    )
  let decoded_frame2 =
    websocks.to_decoded_frame(
      websocks.Continuation(payload: compressed_part2),
      final: True,
      compressed: False,
    )

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded_frame1, decoded_frame2],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: False, no_server: False)),
      ),
    )

  assert resolved == [websocks.Text(payload: full_original)]
}

pub fn resolve_compressed_large_payload_decompression_test() {
  let original =
    list.repeat(0x41, 500)
    |> list.fold(<<>>, fn(acc, byte) { <<acc:bits, byte>> })

  let compressed = websocks.compress_payload(original)

  let decoded_frame =
    websocks.to_decoded_frame(
      websocks.Binary(payload: compressed),
      final: True,
      compressed: True,
    )

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded_frame],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: False, no_server: False)),
      ),
    )

  assert resolved == [websocks.Binary(payload: original)]
}

pub fn resolve_compressed_empty_payload_decompression_test() {
  let original = <<>>
  let compressed = websocks.compress_payload(original)

  let decoded_frame =
    websocks.to_decoded_frame(
      websocks.Text(payload: compressed),
      final: True,
      compressed: True,
    )

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded_frame],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: False, no_server: False)),
      ),
    )

  assert resolved == [websocks.Text(payload: original)]
}

pub fn resolve_mixed_compressed_uncompressed_decompression_test() {
  let uncompressed_payload = <<"uncompressed":utf8>>
  let compressed_payload = websocks.compress_payload(<<"compressed":utf8>>)

  let decoded_frame1 =
    websocks.to_decoded_frame(
      websocks.Text(payload: uncompressed_payload),
      final: True,
      compressed: False,
    )
  let decoded_frame2 =
    websocks.to_decoded_frame(
      websocks.Text(payload: compressed_payload),
      final: True,
      compressed: True,
    )

  let assert Ok(#(resolved, _)) =
    websocks.resolve_fragments(
      [decoded_frame1, decoded_frame2],
      websocks.create_context(
        Some(websocks.ContextTakeover(no_client: False, no_server: False)),
      ),
    )

  assert resolved
    == [
      websocks.Text(payload: uncompressed_payload),
      websocks.Text(payload: <<"compressed":utf8>>),
    ]
}
