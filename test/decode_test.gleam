import endpoint
import frame
import gleam/bit_array
import gleam/list
import websocks.{
  Binary, Close, CloseReason, Control, DecodeFailed, Decoded, FrameTooLarge,
  InvalidFrame, MoreData, NoCloseReason, Ping, Pong, ResolveFailed, Text,
}

pub fn text_frame_test() {
  let data =
    frame.new(frame.Text) |> frame.text("Hello") |> frame.masked |> frame.build

  assert endpoint.frames(endpoint.server(), data)
    == Ok([Text(<<"Hello":utf8>>)])
}

pub fn binary_frame_test() {
  let payload = <<0, 1, 2, 0xff>>
  let data =
    frame.new(frame.Binary)
    |> frame.payload(payload)
    |> frame.masked
    |> frame.build

  assert endpoint.frames(endpoint.server(), data) == Ok([Binary(payload)])
}

pub fn empty_payload_test() {
  let data = frame.new(frame.Text) |> frame.masked |> frame.build

  assert endpoint.frames(endpoint.server(), data) == Ok([Text(<<>>)])
}

pub fn ping_and_pong_test() {
  let ping =
    frame.new(frame.Ping) |> frame.text("hi") |> frame.masked |> frame.build
  let pong =
    frame.new(frame.Pong) |> frame.text("hi") |> frame.masked |> frame.build

  assert endpoint.frames(endpoint.server(), ping)
    == Ok([Control(Ping(<<"hi":utf8>>))])
  assert endpoint.frames(endpoint.server(), pong)
    == Ok([Control(Pong(<<"hi":utf8>>))])
}

pub fn multibyte_text_is_valid_utf8_test() {
  let payload = <<"añ日🐑":utf8>>
  let data =
    frame.new(frame.Text)
    |> frame.payload(payload)
    |> frame.masked
    |> frame.build

  assert endpoint.frames(endpoint.server(), data) == Ok([Text(payload)])
}

/// Every payload length that changes how the length is encoded on the wire.
const length_boundaries = [0, 1, 125, 126, 127, 65_535, 65_536, 65_537]

pub fn every_length_encoding_test() {
  list.each(length_boundaries, fn(size) {
    let payload = frame.filler(size)
    let data =
      frame.new(frame.Binary)
      |> frame.payload(payload)
      |> frame.masked
      |> frame.build

    assert endpoint.frames(endpoint.server(), data) == Ok([Binary(payload)])
  })
}

pub fn several_frames_in_one_read_test() {
  let hello =
    frame.new(frame.Text) |> frame.text("Hello") |> frame.masked |> frame.build
  let ping = frame.new(frame.Ping) |> frame.masked |> frame.build

  assert endpoint.frames(endpoint.server(), frame.join([hello, ping, hello]))
    == Ok([Text(<<"Hello":utf8>>), Control(Ping(<<>>)), Text(<<"Hello":utf8>>)])
}

pub fn server_requires_masked_frames_test() {
  let unmasked = frame.new(frame.Text) |> frame.text("hi") |> frame.build

  assert endpoint.frames(endpoint.server(), unmasked)
    == Error(DecodeFailed(InvalidFrame))
}

pub fn server_accepts_masked_frames_test() {
  let masked =
    frame.new(frame.Text) |> frame.text("hi") |> frame.masked |> frame.build

  assert endpoint.frames(endpoint.server(), masked) == Ok([Text(<<"hi":utf8>>)])
}

pub fn client_rejects_masked_frames_test() {
  let masked =
    frame.new(frame.Text) |> frame.text("hi") |> frame.masked |> frame.build

  assert endpoint.frames(endpoint.client(), masked)
    == Error(DecodeFailed(InvalidFrame))
}

pub fn client_accepts_unmasked_frames_test() {
  let unmasked = frame.new(frame.Text) |> frame.text("hi") |> frame.build

  assert endpoint.frames(endpoint.client(), unmasked)
    == Ok([Text(<<"hi":utf8>>)])
}

pub fn any_mask_key_decodes_test() {
  // The key is arbitrary four bytes, including zeroes
  list.each(
    [<<0, 0, 0, 0>>, <<0xff, 0xff, 0xff, 0xff>>, <<1, 2, 3, 4>>],
    fn(key) {
      let data =
        frame.new(frame.Text)
        |> frame.text("Hello")
        |> frame.masked_with(key)
        |> frame.build

      assert endpoint.frames(endpoint.server(), data)
        == Ok([Text(<<"Hello":utf8>>)])
    },
  )
}

pub fn control_frame_over_125_bytes_is_rejected_test() {
  let big = frame.filler(126)

  list.each([frame.Ping, frame.Pong], fn(opcode) {
    let data =
      frame.new(opcode) |> frame.payload(big) |> frame.masked |> frame.build
    assert endpoint.frames(endpoint.server(), data)
      == Error(DecodeFailed(InvalidFrame))
  })

  let close =
    frame.new(frame.Close)
    |> frame.payload(<<1000:size(16), big:bits>>)
    |> frame.masked
    |> frame.build

  assert endpoint.frames(endpoint.server(), close)
    == Error(DecodeFailed(InvalidFrame))
}

pub fn control_frame_of_exactly_125_bytes_is_accepted_test() {
  let payload = frame.filler(125)
  let data =
    frame.new(frame.Ping)
    |> frame.payload(payload)
    |> frame.masked
    |> frame.build

  assert endpoint.frames(endpoint.server(), data)
    == Ok([Control(Ping(payload))])
}

pub fn fragmented_control_frame_is_rejected_test() {
  list.each([frame.Ping, frame.Pong, frame.Close], fn(opcode) {
    let data =
      frame.new(opcode) |> frame.fin(False) |> frame.masked |> frame.build

    assert endpoint.frames(endpoint.server(), data)
      == Error(DecodeFailed(InvalidFrame))
  })
}

fn close_frame(payload: BitArray) -> BitArray {
  frame.new(frame.Close)
  |> frame.payload(payload)
  |> frame.masked
  |> frame.build
}

pub fn close_with_no_payload_test() {
  assert endpoint.frames(endpoint.server(), close_frame(<<>>))
    == Ok([Control(Close(NoCloseReason))])
}

pub fn close_with_code_only_test() {
  assert endpoint.frames(endpoint.server(), close_frame(<<1000:size(16)>>))
    == Ok([Control(Close(CloseReason(websocks.NormalClosure, "")))])
}

pub fn close_with_code_and_reason_test() {
  let payload = <<1001:size(16), "so long":utf8>>

  assert endpoint.frames(endpoint.server(), close_frame(payload))
    == Ok([Control(Close(CloseReason(websocks.GoingAway, "so long")))])
}

pub fn every_named_close_code_decodes_test() {
  let codes = [
    #(1000, websocks.NormalClosure),
    #(1001, websocks.GoingAway),
    #(1002, websocks.ProtocolError),
    #(1003, websocks.UnsupportedData),
    #(1007, websocks.InvalidPayloadData),
    #(1008, websocks.PolicyViolation),
    #(1009, websocks.MessageTooBig),
    #(1010, websocks.MandatoryExtension),
    #(1011, websocks.InternalError),
    #(1012, websocks.ServiceRestart),
    #(1013, websocks.TryAgainLater),
    #(1014, websocks.BadGateway),
  ]

  list.each(codes, fn(pair) {
    let #(number, code) = pair

    assert endpoint.frames(endpoint.server(), close_frame(<<number:size(16)>>))
      == Ok([Control(Close(CloseReason(code, "")))])
  })
}

pub fn application_close_codes_decode_test() {
  list.each([3000, 3999, 4000, 4999], fn(number) {
    assert endpoint.frames(endpoint.server(), close_frame(<<number:size(16)>>))
      == Ok([Control(Close(CloseReason(websocks.ApplicationCode(number), "")))])
  })
}

pub fn reserved_and_out_of_range_close_codes_are_rejected_test() {
  // 1004 has no meaning; 1005, 1006 and 1015 are for local use only and must
  // never appear on the wire; the rest are outside any assigned range.
  let rejected = [
    0, 1, 999, 1004, 1005, 1006, 1015, 1016, 1100, 2000, 2999, 5000, 65_535,
  ]

  list.each(rejected, fn(number) {
    assert endpoint.frames(endpoint.server(), close_frame(<<number:size(16)>>))
      == Error(DecodeFailed(InvalidFrame))
  })
}

pub fn close_with_one_byte_payload_is_rejected_test() {
  // Neither absent nor a whole status code
  assert endpoint.frames(endpoint.server(), close_frame(<<1>>))
    == Error(DecodeFailed(InvalidFrame))
}

pub fn close_reason_must_be_utf8_test() {
  assert endpoint.frames(
      endpoint.server(),
      close_frame(<<1000:size(16), 0xff, 0xfe>>),
    )
    == Error(DecodeFailed(InvalidFrame))
}

pub fn reserved_opcodes_are_rejected_test() {
  list.each([3, 4, 5, 6, 7, 11, 12, 13, 14, 15], fn(code) {
    let data = frame.new(frame.Reserved(code)) |> frame.masked |> frame.build

    assert endpoint.frames(endpoint.server(), data)
      == Error(DecodeFailed(InvalidFrame))
  })
}

pub fn rsv2_and_rsv3_are_rejected_test() {
  let with_rsv2 =
    frame.new(frame.Text) |> frame.rsv2(True) |> frame.masked |> frame.build
  let with_rsv3 =
    frame.new(frame.Text) |> frame.rsv3(True) |> frame.masked |> frame.build

  assert endpoint.frames(endpoint.server(), with_rsv2)
    == Error(DecodeFailed(InvalidFrame))
  assert endpoint.frames(endpoint.server(), with_rsv3)
    == Error(DecodeFailed(InvalidFrame))
}

pub fn rsv1_without_negotiated_compression_is_rejected_test() {
  let data =
    frame.new(frame.Text)
    |> frame.rsv1(True)
    |> frame.text("hi")
    |> frame.masked
    |> frame.build

  assert endpoint.frames(endpoint.server(), data)
    == Error(DecodeFailed(InvalidFrame))
}

pub fn rsv1_on_a_continuation_is_rejected_test() {
  // RSV1 marks a compressed message, so it belongs on the first frame only
  let data =
    frame.new(frame.Continuation)
    |> frame.rsv1(True)
    |> frame.fin(False)
    |> frame.text("hi")
    |> frame.masked
    |> frame.build

  assert endpoint.frames(endpoint.deflating(websocks.Server), data)
    == Error(DecodeFailed(InvalidFrame))
}

pub fn non_minimal_16_bit_length_is_rejected_test() {
  // A five byte payload fits in the seven bit field, so 126 is not minimal
  let data =
    frame.new(frame.Text)
    |> frame.text("hello")
    |> frame.masked
    |> frame.with_forced_length_bits(16)

  assert endpoint.frames(endpoint.server(), data)
    == Error(DecodeFailed(InvalidFrame))
}

pub fn non_minimal_64_bit_length_is_rejected_test() {
  let data =
    frame.new(frame.Text)
    |> frame.text("hello")
    |> frame.masked
    |> frame.with_forced_length_bits(64)

  assert endpoint.frames(endpoint.server(), data)
    == Error(DecodeFailed(InvalidFrame))
}

pub fn a_64_bit_length_below_65536_is_rejected_test() {
  let data =
    frame.new(frame.Binary)
    |> frame.payload(frame.filler(65_535))
    |> frame.masked
    |> frame.with_forced_length_bits(64)

  assert endpoint.frames(endpoint.server(), data)
    == Error(DecodeFailed(InvalidFrame))
}

pub fn minimal_extended_lengths_are_accepted_test() {
  // 126 needs 16 bits, 65_536 needs 64
  list.each([126, 65_536], fn(size) {
    let payload = frame.filler(size)
    let data =
      frame.new(frame.Binary)
      |> frame.payload(payload)
      |> frame.masked
      |> frame.build

    assert endpoint.frames(endpoint.server(), data) == Ok([Binary(payload)])
  })
}

pub fn a_64_bit_length_with_the_top_bit_set_is_rejected_test() {
  let data = <<
    1:1,
    0:3,
    1:4,
    1:1,
    127:7,
    0x8000000000000001:64,
    frame.mask_key:bits,
  >>

  assert endpoint.frames(endpoint.server(), data)
    == Error(DecodeFailed(InvalidFrame))
}

pub fn empty_read_is_buffered_test() {
  assert endpoint.frames(endpoint.server(), <<>>) == Ok([])
}

pub fn partial_frames_are_buffered_test() {
  let whole =
    frame.new(frame.Binary)
    |> frame.payload(frame.filler(300))
    |> frame.masked
    |> frame.build
  let size = bit_array.byte_size(whole)

  // every strict prefix must buffer rather than decode or fail
  list.each([1, 2, 3, 4, 5, 8, 10, 100, size - 1], fn(prefix) {
    let assert Ok(partial) = bit_array.slice(whole, 0, prefix)

    assert endpoint.frames(endpoint.server(), partial) == Ok([])
  })
}

pub fn a_buffered_frame_completes_on_the_next_read_test() {
  let whole =
    frame.new(frame.Text) |> frame.text("Hello") |> frame.masked |> frame.build
  let size = bit_array.byte_size(whole)
  let assert Ok(head) = bit_array.slice(whole, 0, 4)
  let assert Ok(tail) = bit_array.slice(whole, 4, size - 4)

  let assert Ok(#(frames, context)) = endpoint.drain(endpoint.server(), head)
  assert frames == []
  assert websocks.extract_buffer(context) == head

  assert endpoint.frames(context, tail) == Ok([Text(<<"Hello":utf8>>)])
}

pub fn a_frame_delivered_one_byte_at_a_time_test() {
  let payload = frame.filler(300)
  let data =
    frame.new(frame.Binary)
    |> frame.payload(payload)
    |> frame.masked
    |> frame.build

  let assert Ok(#(frames, _context)) =
    endpoint.drain_bytewise(endpoint.server(), data)

  assert frames == [Binary(payload)]
}

pub fn a_trailing_partial_frame_stays_buffered_test() {
  let hello =
    frame.new(frame.Text) |> frame.text("Hello") |> frame.masked |> frame.build
  let assert Ok(head) = bit_array.slice(hello, 0, 3)

  let assert Ok(#(frames, context)) =
    endpoint.drain(endpoint.server(), frame.join([hello, head]))

  assert frames == [Text(<<"Hello":utf8>>)]
  assert websocks.extract_buffer(context) == head
}

pub fn frame_larger_than_the_limit_reports_the_sizes_test() {
  let context = endpoint.with_limits(endpoint.server(), 1024, 8192)
  let data =
    frame.new(frame.Binary)
    |> frame.payload(frame.filler(2048))
    |> frame.masked
    |> frame.build

  assert endpoint.frames(context, data)
    == Error(DecodeFailed(FrameTooLarge(length: 2048, limit: 1024)))
}

pub fn invalid_text_reports_a_resolve_error_test() {
  let data =
    frame.new(frame.Text)
    |> frame.payload(<<"ok":utf8, 0xc3, 0x28>>)
    |> frame.masked
    |> frame.build

  assert endpoint.frames(endpoint.server(), data)
    == Error(ResolveFailed(websocks.NotUtf8))
}

pub fn a_frame_after_an_error_is_not_reached_test() {
  // The first frame is a protocol violation, so the second is never decoded
  let bad = frame.new(frame.Reserved(3)) |> frame.masked |> frame.build
  let good =
    frame.new(frame.Text) |> frame.text("Hello") |> frame.masked |> frame.build

  assert endpoint.frames(endpoint.server(), frame.join([bad, good]))
    == Error(DecodeFailed(InvalidFrame))
}

pub fn next_frame_on_an_empty_context_reports_more_data_test() {
  let assert Ok(decoded) = websocks.next_frame(endpoint.server())

  assert case decoded {
    MoreData(..) -> True
    Decoded(..) -> False
  }
}
