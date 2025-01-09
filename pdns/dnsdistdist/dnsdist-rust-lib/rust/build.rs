fn main() {
    cxx_build::bridge("src/lib.rs")
        .flag_if_supported("-std=c++17")
        .flag("-Isrc")
        .flag("-I.")
        .flag("-I..")
        .flag("-I../..")
        .compile("dnsdist_rust");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/helpers.rs");
}