import endpoint
import frame
import gleam/bit_array
import gleam/list
import websocks.{
  Binary, ConcurrentFragmentation, Control, DecodeFailed, Decoded,
  FragmentationInterrupted, InvalidFrame, MessageTooLarge, MoreData, NotUtf8,
  OrphanedContinuation, Ping, ResolveFailed, Text,
}

fn first(payload: BitArray, opcode: frame.Opcode) -> BitArray {
  frame.new(opcode)
  |> frame.fin(False)
  |> frame.payload(payload)
  |> frame.masked
  |> frame.build
}

fn middle(payload: BitArray) -> BitArray {
  frame.new(frame.Continuation)
  |> frame.fin(False)
  |> frame.payload(payload)
  |> frame.masked
  |> frame.build
}

fn last(payload: BitArray) -> BitArray {
  frame.new(frame.Continuation)
  |> frame.payload(payload)
  |> frame.masked
  |> frame.build
}

pub fn two_fragment_text_test() {
  let data =
    frame.join([first(<<"Hel":utf8>>, frame.Text), last(<<"lo":utf8>>)])

  assert endpoint.frames(endpoint.server(), data)
    == Ok([Text(<<"Hello":utf8>>)])
}

pub fn three_fragment_text_test() {
  let data =
    frame.join([
      first(<<"He":utf8>>, frame.Text),
      middle(<<"ll":utf8>>),
      last(<<"o":utf8>>),
    ])

  assert endpoint.frames(endpoint.server(), data)
    == Ok([Text(<<"Hello":utf8>>)])
}

pub fn many_fragment_binary_test() {
  let chunk = frame.filler(1000)
  let fragments =
    [first(chunk, frame.Binary)]
    |> list.append(list.repeat(middle(chunk), 8))
    |> list.append([last(chunk)])

  let expected = bit_array.concat(list.repeat(chunk, 10))

  assert endpoint.frames(endpoint.server(), frame.join(fragments))
    == Ok([Binary(expected)])
}

pub fn large_fragments_test() {
  let chunk = frame.filler(65_536)
  let data =
    frame.join([first(chunk, frame.Binary), middle(chunk), last(chunk)])

  assert endpoint.frames(endpoint.server(), data)
    == Ok([Binary(bit_array.concat([chunk, chunk, chunk]))])
}

pub fn empty_fragments_test() {
  let data =
    frame.join([
      first(<<>>, frame.Text),
      middle(<<"Hello":utf8>>),
      last(<<>>),
    ])

  assert endpoint.frames(endpoint.server(), data)
    == Ok([Text(<<"Hello":utf8>>)])
}

pub fn two_messages_in_a_row_test() {
  let one = frame.join([first(<<"Hel":utf8>>, frame.Text), last(<<"lo":utf8>>)])
  let two = frame.join([first(<<"Wor":utf8>>, frame.Text), last(<<"ld":utf8>>)])

  assert endpoint.frames(endpoint.server(), frame.join([one, two]))
    == Ok([Text(<<"Hello":utf8>>), Text(<<"World":utf8>>)])
}

/// A multi-byte codepoint split down the middle is only valid once reassembled,
/// so validation has to happen on the whole message and not per fragment.
pub fn a_codepoint_split_across_fragments_test() {
  // 🐑 is f0 9f 90 91
  let data =
    frame.join([
      first(<<0xf0, 0x9f>>, frame.Text),
      last(<<0x90, 0x91>>),
    ])

  assert endpoint.frames(endpoint.server(), data) == Ok([Text(<<"🐑":utf8>>)])
}

pub fn text_invalid_only_once_reassembled_test() {
  // Each fragment is a valid prefix, but together they are not valid UTF-8
  let data =
    frame.join([first(<<0xf0, 0x9f>>, frame.Text), last(<<0x28, 0x28>>)])

  assert endpoint.frames(endpoint.server(), data)
    == Error(ResolveFailed(NotUtf8))
}

pub fn binary_fragments_are_not_utf8_checked_test() {
  let data = frame.join([first(<<0xff, 0xfe>>, frame.Binary), last(<<0xfd>>)])

  assert endpoint.frames(endpoint.server(), data)
    == Ok([Binary(<<0xff, 0xfe, 0xfd>>)])
}

pub fn a_control_frame_may_interrupt_fragments_test() {
  let ping =
    frame.new(frame.Ping) |> frame.text("p") |> frame.masked |> frame.build
  let data =
    frame.join([first(<<"Hel":utf8>>, frame.Text), ping, last(<<"lo":utf8>>)])

  assert endpoint.frames(endpoint.server(), data)
    == Ok([Control(Ping(<<"p":utf8>>)), Text(<<"Hello":utf8>>)])
}

pub fn fragmentation_survives_a_control_frame_test() {
  let ping = frame.new(frame.Ping) |> frame.masked |> frame.build

  let assert Ok(#(_frames, context)) =
    endpoint.drain(endpoint.server(), first(<<"Hel":utf8>>, frame.Text))

  // still mid-message
  assert !websocks.is_empty_context(context)

  let assert Ok(#(frames, context)) = endpoint.drain(context, ping)
  assert frames == [Control(Ping(<<>>))]
  assert !websocks.is_empty_context(context)

  assert endpoint.frames(context, last(<<"lo":utf8>>))
    == Ok([Text(<<"Hello":utf8>>)])
}

pub fn a_continuation_without_a_start_is_rejected_test() {
  assert endpoint.frames(endpoint.server(), last(<<"Hello":utf8>>))
    == Error(ResolveFailed(OrphanedContinuation))

  assert endpoint.frames(endpoint.server(), middle(<<"Hello":utf8>>))
    == Error(ResolveFailed(OrphanedContinuation))
}

pub fn a_whole_message_during_fragmentation_is_rejected_test() {
  let whole =
    frame.new(frame.Text) |> frame.text("Hello") |> frame.masked |> frame.build
  let data = frame.join([first(<<"Hel":utf8>>, frame.Text), whole])

  assert endpoint.frames(endpoint.server(), data)
    == Error(ResolveFailed(FragmentationInterrupted))
}

pub fn a_second_fragmented_message_is_rejected_test() {
  let data =
    frame.join([
      first(<<"Hel":utf8>>, frame.Text),
      first(<<"Wor":utf8>>, frame.Text),
    ])

  assert endpoint.frames(endpoint.server(), data)
    == Error(ResolveFailed(ConcurrentFragmentation))
}

pub fn fragments_past_the_message_limit_are_rejected_test() {
  let context = endpoint.with_limits(endpoint.server(), 16_384, 2048)
  let chunk = frame.filler(1000)
  let data =
    frame.join([first(chunk, frame.Binary), middle(chunk), last(chunk)])

  assert endpoint.frames(context, data)
    == Error(ResolveFailed(MessageTooLarge(size: 3000, limit: 2048)))
}

pub fn a_message_at_the_limit_is_accepted_test() {
  let context = endpoint.with_limits(endpoint.server(), 16_384, 3000)
  let chunk = frame.filler(1000)
  let data =
    frame.join([first(chunk, frame.Binary), middle(chunk), last(chunk)])

  assert endpoint.frames(context, data)
    == Ok([Binary(bit_array.concat([chunk, chunk, chunk]))])
}

/// A fragment on its own carries no message, so `next_frame` must keep draining
/// rather than report `MoreData` while whole frames are still buffered. Getting
/// this wrong strands the trailing frame until the next read, possibly forever.
pub fn a_frame_after_a_fragmented_message_is_not_stranded_test() {
  let ping = frame.new(frame.Ping) |> frame.masked |> frame.build
  let data =
    frame.join([
      first(<<"Hel":utf8>>, frame.Text),
      middle(<<"l":utf8>>),
      last(<<"o":utf8>>),
      ping,
    ])

  assert endpoint.frames(endpoint.server(), data)
    == Ok([Text(<<"Hello":utf8>>), Control(Ping(<<>>))])
}

pub fn more_data_means_the_buffer_holds_no_whole_frame_test() {
  let data =
    frame.join([
      first(<<"Hel":utf8>>, frame.Text),
      middle(<<"l":utf8>>),
      last(<<"o":utf8>>),
    ])

  let assert Ok(#(frames, context)) = endpoint.drain(endpoint.server(), data)

  assert frames == [Text(<<"Hello":utf8>>)]
  assert websocks.extract_buffer(context) == <<>>
  assert websocks.is_empty_context(context)
}

pub fn a_partial_fragment_reports_more_data_test() {
  let assert Ok(decoded) =
    websocks.next_frame(websocks.push_data(
      endpoint.server(),
      first(<<"Hel":utf8>>, frame.Text),
    ))

  assert case decoded {
    MoreData(..) -> True
    Decoded(..) -> False
  }
}

pub fn fragments_arriving_one_byte_at_a_time_test() {
  let data =
    frame.join([
      first(<<"He":utf8>>, frame.Text),
      middle(<<"ll":utf8>>),
      last(<<"o":utf8>>),
      frame.new(frame.Ping) |> frame.masked |> frame.build,
    ])

  let assert Ok(#(frames, _context)) =
    endpoint.drain_bytewise(endpoint.server(), data)

  assert frames == [Text(<<"Hello":utf8>>), Control(Ping(<<>>))]
}

pub fn one_read_and_many_reads_agree_test() {
  let data =
    frame.join([
      first(frame.utf8_filler(300), frame.Text),
      middle(frame.utf8_filler(300)),
      last(frame.utf8_filler(300)),
    ])

  let assert Ok(#(at_once, _context)) = endpoint.drain(endpoint.server(), data)
  let assert Ok(#(bytewise, _context)) =
    endpoint.drain_bytewise(endpoint.server(), data)

  assert at_once == bytewise
}

pub fn the_accumulated_message_can_be_inspected_mid_flight_test() {
  let assert Ok(#(_frames, context)) =
    endpoint.drain(endpoint.server(), first(<<"Hel":utf8>>, frame.Text))

  assert websocks.extract_accumulating_frame(context)
    == Ok(Text(<<"Hel":utf8>>))

  let assert Ok(#(_frames, context)) =
    endpoint.drain(context, middle(<<"l":utf8>>))

  assert websocks.extract_accumulating_frame(context)
    == Ok(Text(<<"Hell":utf8>>))
}

pub fn a_settled_context_has_nothing_accumulated_test() {
  assert websocks.extract_accumulating_frame(endpoint.server()) == Error(Nil)
}

pub fn a_fragmented_control_frame_never_reaches_reassembly_test() {
  // decoding rejects it, so the fragmentation state machine never sees it
  let data =
    frame.new(frame.Ping) |> frame.fin(False) |> frame.masked |> frame.build

  assert endpoint.frames(endpoint.server(), data)
    == Error(DecodeFailed(InvalidFrame))
}
