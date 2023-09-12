fn main() {
    cxx_build::bridge("src/lib.rs")
        // .file("src/source.cc") at the moment no C++ code callable from Rust
        .flag_if_supported("-std=c++17")
        .compile("settings");
}
