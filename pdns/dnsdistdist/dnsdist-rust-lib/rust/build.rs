fn main() {
    cxx_build::bridge("src/lib.rs")
        .flag_if_supported("-std=c++17")
        .flag("-Isrc")
        .compile("dnsdist_rust");
}