use std::fs;
use std::path::PathBuf;
use std::env;

fn main() {
    let mut bridge = cxx_build::bridge("src/lib.rs");
    let mut build = bridge
            .flag_if_supported("-std=c++17")
            .flag("-Isrc")
            .flag("-I.")
            .flag("-I..")
            .flag("-I../..");
    let generated_headers_dir_env = env::var("generatedheadersdir");
    if generated_headers_dir_env.is_ok() {
      let generated_headers_dir = PathBuf::from(generated_headers_dir_env.unwrap());
      let generated_headers_dir_canon = fs::canonicalize(&generated_headers_dir);
      if generated_headers_dir_canon.is_ok() {
        build = build.flag(format!("-I{}", generated_headers_dir_canon.unwrap().display()))
      }
    }

    build.compile("dnsdist_rust");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/helpers.rs");
}