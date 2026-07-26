import gleam/list
import gleam/option.{None, Some}
import websocks.{type Context, type Frame, type ProcessError}

pub fn server() -> Context {
  websocks.create_context(None, websocks.Server)
}

pub fn client() -> Context {
  websocks.create_context(None, websocks.Client)
}

/// A context with `permessage-deflate` negotiated and context takeover left on.
///
pub fn deflating(role: websocks.Role) -> Context {
  websocks.create_context(
    Some(websocks.get_compression_extensions("permessage-deflate")),
    role,
  )
}

pub fn with_limits(context: Context, frame: Int, message: Int) -> Context {
  websocks.with_limits(
    context,
    websocks.Limits(max_frame_size: frame, max_message_size: message),
  )
}

/// Buffers `data`, then pulls every frame it completes.
///
pub fn drain(
  context: Context,
  data: BitArray,
) -> Result(#(List(Frame), Context), ProcessError) {
  do_drain(websocks.push_data(context, data), [])
}

fn do_drain(
  context: Context,
  acc: List(Frame),
) -> Result(#(List(Frame), Context), ProcessError) {
  case websocks.next_frame(context) {
    Error(error) -> Error(error)
    Ok(websocks.MoreData(context:)) -> Ok(#(list.reverse(acc), context))
    Ok(websocks.Decoded(frame:, context:)) -> do_drain(context, [frame, ..acc])
  }
}

/// Just the frames, for tests that do not care about the resulting context.
///
pub fn frames(
  context: Context,
  data: BitArray,
) -> Result(List(Frame), ProcessError) {
  case drain(context, data) {
    Ok(#(frames, _context)) -> Ok(frames)
    Error(error) -> Error(error)
  }
}

/// Delivers `data` one byte per read, the worst case for buffering.
///
pub fn drain_bytewise(
  context: Context,
  data: BitArray,
) -> Result(#(List(Frame), Context), ProcessError) {
  do_drain_bytewise(single_bytes(data), context, [])
}

fn do_drain_bytewise(
  reads: List(BitArray),
  context: Context,
  acc: List(Frame),
) -> Result(#(List(Frame), Context), ProcessError) {
  case reads {
    [] -> Ok(#(list.reverse(acc), context))
    [read, ..rest] ->
      case drain(context, read) {
        Error(error) -> Error(error)
        Ok(#(frames, context)) ->
          do_drain_bytewise(rest, context, list.fold(frames, acc, list.prepend))
      }
  }
}

fn single_bytes(data: BitArray) -> List(BitArray) {
  do_single_bytes(data, [])
}

fn do_single_bytes(data: BitArray, acc: List(BitArray)) -> List(BitArray) {
  case data {
    <<byte:8, rest:bits>> -> do_single_bytes(rest, [<<byte:8>>, ..acc])
    _remainder -> list.reverse(acc)
  }
}
