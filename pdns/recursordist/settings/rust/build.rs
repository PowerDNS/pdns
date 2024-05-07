fn main() {
    cxx_build::bridge("src/lib.rs")
        // .file("src/source.cc") Code callable from Rust is in ../cxxsupport.cc
        .flag_if_supported("-std=c++17")
        .flag("-Isrc")
        .compile("settings");
}
