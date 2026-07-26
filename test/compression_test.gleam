import endpoint
import frame
import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import websocks.{Binary, DecompressionFailed, ResolveFailed, Text}

fn round_trip(
  payload: BitArray,
) -> Result(List(websocks.Frame), websocks.ProcessError) {
  let encoded =
    websocks.encode_binary_frame(
      payload,
      endpoint.deflating(websocks.Server),
      None,
    )

  endpoint.frames(endpoint.deflating(websocks.Client), encoded)
}

pub fn compressed_binary_round_trips_test() {
  list.each([0, 1, 64, 1024, 65_536], fn(size) {
    let payload = frame.filler(size)
    assert round_trip(payload) == Ok([Binary(payload)])
  })
}

pub fn compressed_text_round_trips_test() {
  let payload = <<"Hello, 日本語 🐑":utf8>>
  let encoded =
    websocks.encode_text_frame(
      payload,
      endpoint.deflating(websocks.Server),
      None,
    )

  assert endpoint.frames(endpoint.deflating(websocks.Client), encoded)
    == Ok([Text(payload)])
}

pub fn incompressible_data_round_trips_test() {
  // Random-looking bytes may deflate to something larger than the input
  let payload = <<0x8f, 0x2a, 0xd4, 0x01, 0x77, 0xbe, 0xef, 0x13>>
  assert round_trip(payload) == Ok([Binary(payload)])
}

pub fn compression_actually_shrinks_repetitive_data_test() {
  let payload = frame.filler(4096)
  let compressed =
    websocks.encode_binary_frame(
      payload,
      endpoint.deflating(websocks.Server),
      None,
    )
  let plain = websocks.encode_binary_frame(payload, endpoint.server(), None)

  assert bit_array.byte_size(compressed) < bit_array.byte_size(plain)
}

pub fn a_compressed_frame_sets_rsv1_test() {
  let assert <<_fin:1, rsv1:1, _rest:bits>> =
    websocks.encode_text_frame(
      <<"Hello":utf8>>,
      endpoint.deflating(websocks.Server),
      None,
    )

  assert rsv1 == 1
}

pub fn an_uncompressed_context_leaves_rsv1_clear_test() {
  let assert <<_fin:1, rsv1:1, _rest:bits>> =
    websocks.encode_text_frame(<<"Hello":utf8>>, endpoint.server(), None)

  assert rsv1 == 0
}

pub fn several_compressed_messages_in_sequence_test() {
  // With context takeover the deflate stream carries state between messages, so
  // the decoder has to be fed them in order to stay in step.
  let sender = endpoint.deflating(websocks.Server)
  let receiver = endpoint.deflating(websocks.Client)

  let payloads = ["first", "second", "third", "first again"]

  list.fold(payloads, receiver, fn(receiver, text) {
    let payload = bit_array.from_string(text)
    let encoded = websocks.encode_text_frame(payload, sender, None)
    let assert Ok(#(frames, receiver)) = endpoint.drain(receiver, encoded)

    assert frames == [Text(payload)]
    receiver
  })
}

pub fn no_context_takeover_round_trips_test() {
  let extensions =
    websocks.get_compression_extensions(
      "permessage-deflate; client_no_context_takeover;"
      <> " server_no_context_takeover",
    )
  let sender = websocks.create_context(Some(extensions), websocks.Server)
  let receiver = websocks.create_context(Some(extensions), websocks.Client)

  list.fold(["one", "two", "three"], receiver, fn(receiver, text) {
    let payload = bit_array.from_string(text)
    let encoded = websocks.encode_text_frame(payload, sender, None)
    let assert Ok(#(frames, receiver)) = endpoint.drain(receiver, encoded)

    assert frames == [Text(payload)]
    receiver
  })
}

pub fn a_negotiated_window_size_round_trips_test() {
  let extensions =
    websocks.get_compression_extensions(
      "permessage-deflate; client_max_window_bits=9; server_max_window_bits=9",
    )
  let sender = websocks.create_context(Some(extensions), websocks.Server)
  let receiver = websocks.create_context(Some(extensions), websocks.Client)
  let payload = frame.filler(2048)

  assert endpoint.frames(
      receiver,
      websocks.encode_binary_frame(payload, sender, None),
    )
    == Ok([Binary(payload)])
}

pub fn a_compressed_message_may_be_fragmented_test() {
  // Only the first frame carries RSV1; the continuations must not.
  let payload = frame.filler(3000)
  let compressed = websocks.compress_payload(payload)
  let size = bit_array.byte_size(compressed)
  let half = size / 2
  let assert Ok(head) = bit_array.slice(compressed, 0, half)
  let assert Ok(tail) = bit_array.slice(compressed, half, size - half)

  let data =
    frame.join([
      frame.new(frame.Binary)
        |> frame.rsv1(True)
        |> frame.fin(False)
        |> frame.payload(head)
        |> frame.masked
        |> frame.build,
      frame.new(frame.Continuation)
        |> frame.payload(tail)
        |> frame.masked
        |> frame.build,
    ])

  assert endpoint.frames(endpoint.deflating(websocks.Server), data)
    == Ok([Binary(payload)])
}

/// A few hundred bytes of deflate can expand to megabytes. Without a bound on
/// the inflated size, a single small frame exhausts memory.
pub fn a_decompression_bomb_is_rejected_test() {
  let payload = websocks.compress_payload(frame.filler(1_048_576))

  // the bomb really is tiny compared to what it expands to
  assert bit_array.byte_size(payload) < 4096

  let data =
    frame.new(frame.Binary)
    |> frame.rsv1(True)
    |> frame.payload(payload)
    |> frame.build

  let bounded =
    endpoint.with_limits(
      endpoint.deflating(websocks.Client),
      16_777_216,
      65_536,
    )

  assert endpoint.frames(bounded, data)
    == Error(ResolveFailed(DecompressionFailed))
}

pub fn the_same_frame_inflates_within_a_larger_limit_test() {
  let original = frame.filler(1_048_576)
  let payload = websocks.compress_payload(original)

  let data =
    frame.new(frame.Binary)
    |> frame.rsv1(True)
    |> frame.payload(payload)
    |> frame.build

  let bounded =
    endpoint.with_limits(
      endpoint.deflating(websocks.Client),
      16_777_216,
      2_097_152,
    )

  assert endpoint.frames(bounded, data) == Ok([Binary(original)])
}

pub fn a_malformed_deflate_stream_is_rejected_test() {
  let data =
    frame.new(frame.Binary)
    |> frame.rsv1(True)
    |> frame.payload(<<0xff, 0xff, 0xff, 0xff, 0xff, 0xff>>)
    |> frame.build

  assert endpoint.frames(endpoint.deflating(websocks.Client), data)
    == Error(ResolveFailed(DecompressionFailed))
}

pub fn a_compressed_frame_without_negotiation_is_rejected_test() {
  let data =
    frame.new(frame.Binary)
    |> frame.rsv1(True)
    |> frame.payload(<<1, 2, 3>>)
    |> frame.masked
    |> frame.build

  assert endpoint.frames(endpoint.server(), data)
    == Error(websocks.DecodeFailed(websocks.InvalidFrame))
}

pub fn an_uncompressed_frame_on_a_compressed_context_is_accepted_test() {
  // RSV1 is per message, so a peer may send a message uncompressed
  let payload = <<1, 2, 3>>
  let data =
    frame.new(frame.Binary)
    |> frame.payload(payload)
    |> frame.masked
    |> frame.build

  assert endpoint.frames(endpoint.deflating(websocks.Server), data)
    == Ok([Binary(payload)])
}

pub fn closing_a_context_is_safe_test() {
  assert websocks.close_context(endpoint.deflating(websocks.Server)) == Nil
  // a context without compression holds no zlib resources to free
  assert websocks.close_context(endpoint.server()) == Nil
}
