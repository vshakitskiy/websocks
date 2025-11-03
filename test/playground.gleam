import websocks

pub fn main() {
  let original = <<"Hello, World!":utf8>>
  let compressed = websocks.compress_payload_for_test(original)
  echo compressed
}
