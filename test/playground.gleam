import gleam/option.{type Option, None}
import gleam/result
import websocks

pub fn main() {
  // Frame parts:
  // Incomplete text frame:
  // 0x01 : fin=0, rsv1-3=0, opcode=1
  // 0x04 : mask=0, payload length=4
  let text = <<0x01, 0x04>>
  // 0x00 : fin=0, rsv1-3=0, opcode=0
  // 0x04 : mask=0, payload length=4
  let continuation_complete = <<0x80, 0x04>>
  // Complete continuation frame:
  // 0x80 : fin=1, rsv1-3=0, opcode=0
  // 0x04 : mask=0, payload length=4
  let continuation_incomplete = <<0x00, 0x04>>
  // 0x48 0x65 0x6c 0x6c : "Hell"
  let payload1 = <<0x48, 0x65, 0x6c, 0x6c>>
  // 0x6f 0x20 0x57 0x6f : "o Wo"
  let payload2 = <<0x6f, 0x20, 0x57, 0x6f>>
  // 0x72 0x6c 0x64 0x21 : "rld!"
  let payload3 = <<0x72, 0x6c, 0x64, 0x21>>

  // Let's say we have this buffer:
  let frames = <<
    text:bits,
    payload1:bits,
    continuation_incomplete:bits,
    payload2:bits,
    continuation_complete:bits,
    payload3:bits,
  >>

  let context = websocks.create_context(None)

  // We assume that the frames were successfully decoded.
  let assert Ok(#(decoded_frames, context)) =
    websocks.decode_many_frames(frames, context)

  // Resolve the decoded frames
  echo websocks.resolve_fragments(decoded_frames, context)
  // => Ok(#([Text("Hello World!")], Context)
}
