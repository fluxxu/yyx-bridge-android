#![feature(rustc_private)]

extern crate cc;

#[cfg(not(feature = "android"))]
fn main() {
}

#[cfg(feature = "android")]
fn main() {
  use std::env;

  let path = env::var("PATH").unwrap();
  env::set_var("PATH", format!("/Users/fluxxu/Projects/android-rust/NDK/x86/bin:{}", path));

  cc::Build::new()
    .file("src/errno.c")
    .compile("errno");
}