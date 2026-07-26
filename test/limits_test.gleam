import endpoint
import frame
import gleam/bit_array
import gleam/list
import websocks.{Binary, DecodeFailed, FrameTooLarge}

pub fn default_limits_test() {
  assert websocks.default_limits
    == websocks.Limits(max_frame_size: 16_777_216, max_message_size: 67_108_864)
}

pub fn with_limits_replaces_the_defaults_test() {
  let context = endpoint.with_limits(endpoint.server(), 10, 20)
  let data =
    frame.new(frame.Binary)
    |> frame.payload(frame.filler(11))
    |> frame.masked
    |> frame.build

  assert endpoint.frames(context, data)
    == Error(DecodeFailed(FrameTooLarge(length: 11, limit: 10)))
}

pub fn a_frame_at_the_limit_is_accepted_test() {
  let context = endpoint.with_limits(endpoint.server(), 1024, 8192)
  let payload = frame.filler(1024)
  let data =
    frame.new(frame.Binary)
    |> frame.payload(payload)
    |> frame.masked
    |> frame.build

  assert endpoint.frames(context, data) == Ok([Binary(payload)])
}

pub fn a_frame_one_byte_over_the_limit_is_rejected_test() {
  let context = endpoint.with_limits(endpoint.server(), 1024, 8192)
  let data =
    frame.new(frame.Binary)
    |> frame.payload(frame.filler(1025))
    |> frame.masked
    |> frame.build

  assert endpoint.frames(context, data)
    == Error(DecodeFailed(FrameTooLarge(length: 1025, limit: 1024)))
}

/// The declared length is rejected before the payload is read, so an enormous
/// claim costs nothing. This is what keeps the buffer bounded.
pub fn an_enormous_declared_frame_is_rejected_without_its_payload_test() {
  let header = <<
    1:1,
    0:3,
    2:4,
    1:1,
    127:7,
    1_099_511_627_776:64,
    frame.mask_key:bits,
  >>

  assert bit_array.byte_size(header) == 14

  assert endpoint.frames(endpoint.server(), header)
    == Error(
      DecodeFailed(FrameTooLarge(length: 1_099_511_627_776, limit: 16_777_216)),
    )
}

pub fn the_buffer_never_exceeds_one_frame_plus_its_header_test() {
  let context = endpoint.with_limits(endpoint.server(), 4096, 65_536)

  // A frame that will never complete, delivered in pieces
  let whole =
    frame.new(frame.Binary)
    |> frame.payload(frame.filler(4096))
    |> frame.masked
    |> frame.build
  let size = bit_array.byte_size(whole)
  let assert Ok(partial) = bit_array.slice(whole, 0, size - 1)

  let assert Ok(#(frames, context)) = endpoint.drain(context, partial)

  assert frames == []
  // held, but bounded by the frame limit rather than by what the peer sends
  assert bit_array.byte_size(websocks.extract_buffer(context)) <= 4096 + 14
}

fn fragmented(chunk: BitArray, count: Int) -> BitArray {
  let first =
    frame.new(frame.Binary)
    |> frame.fin(False)
    |> frame.payload(chunk)
    |> frame.masked
    |> frame.build
  let middle =
    frame.new(frame.Continuation)
    |> frame.fin(False)
    |> frame.payload(chunk)
    |> frame.masked
    |> frame.build
  let last =
    frame.new(frame.Continuation)
    |> frame.payload(chunk)
    |> frame.masked
    |> frame.build

  [first]
  |> list.append(list.repeat(middle, count - 2))
  |> list.append([last])
  |> frame.join
}

pub fn a_message_within_the_limit_is_accepted_test() {
  let context = endpoint.with_limits(endpoint.server(), 4096, 4096)
  let chunk = frame.filler(1024)

  assert endpoint.frames(context, fragmented(chunk, 4))
    == Ok([Binary(bit_array.concat(list.repeat(chunk, 4)))])
}

pub fn a_message_over_the_limit_is_rejected_test() {
  let context = endpoint.with_limits(endpoint.server(), 4096, 4096)
  let chunk = frame.filler(1024)

  assert endpoint.frames(context, fragmented(chunk, 5))
    == Error(
      websocks.ResolveFailed(websocks.MessageTooLarge(size: 5120, limit: 4096)),
    )
}

/// Each frame can sit under the frame limit while the message they build does
/// not, which is why the two limits are separate.
pub fn small_frames_cannot_add_up_past_the_message_limit_test() {
  let context = endpoint.with_limits(endpoint.server(), 1_048_576, 2048)
  let chunk = frame.filler(256)

  assert endpoint.frames(context, fragmented(chunk, 16))
    == Error(
      websocks.ResolveFailed(websocks.MessageTooLarge(size: 2304, limit: 2048)),
    )
}

pub fn the_limit_is_reached_before_the_final_fragment_test() {
  // The message is refused partway through rather than after it has all been held
  let context = endpoint.with_limits(endpoint.server(), 1_048_576, 1000)
  let chunk = frame.filler(600)

  assert endpoint.frames(context, fragmented(chunk, 10))
    == Error(
      websocks.ResolveFailed(websocks.MessageTooLarge(size: 1200, limit: 1000)),
    )
}

pub fn an_unfragmented_message_is_bounded_by_the_frame_limit_test() {
  // A single frame under the frame limit but over the message limit still decodes,
  // since nothing is accumulated
  let context = endpoint.with_limits(endpoint.server(), 4096, 1024)
  let payload = frame.filler(2048)
  let data =
    frame.new(frame.Binary)
    |> frame.payload(payload)
    |> frame.masked
    |> frame.build

  assert endpoint.frames(context, data) == Ok([Binary(payload)])
}
