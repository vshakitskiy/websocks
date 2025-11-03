import websocks

pub fn main() {
  let decoded_1 =
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hello, World!":utf8>>),
      final: True,
      compressed: False,
    )
  let decoded_2 =
    websocks.to_decoded_frame(
      websocks.Text(payload: <<"Hello, World!":utf8>>),
      final: True,
      compressed: False,
    )

  echo decoded_1 == decoded_2
  // echo websocks.compare_decoded_frames(decoded_1, decoded_2)
}
