extern crate rand;
use rand::prelude::*;

use std::fs;
use std::env;
use std::path::Path;

fn main() {
  let out_dir = env::var("OUT_DIR").unwrap();
  
  let out_dir_path = Path::new(&out_dir);
  let content = fs::read_to_string("./assets/code_guild.py").unwrap();
  let content_bytes = content.as_bytes();
  let mut rng = rand::thread_rng();
  let lines: Vec<(u8, String)> = content_bytes.iter().enumerate()
    .map(|(i, b)| {
      let k: u8 = rng.gen();
      (*b ^ k, format!("bytes[{}] = bytes[{}] ^ 0x{:x};", i, i, k))
    })
    .collect();
  let (obf_bytes, lines): (Vec<u8>, Vec<String>) = lines.into_iter().unzip();

  let lines = lines.join("\n");

  let mod_code = format!(r#"
pub fn get_code() -> String {{
  let mut bytes = include_bytes!("./code_bytes.bin").to_vec();

  {lines}

  unsafe {{
    String::from_utf8_unchecked(bytes)
  }}
}}
  "#, lines = lines);

  fs::write(out_dir_path.join("code_bytes.bin"), &obf_bytes).unwrap();
  fs::write(out_dir_path.join("assets.rs"), mod_code).unwrap();
}