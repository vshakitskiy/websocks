import frame
import gleam/list
import gleam/option.{None, Some}
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
