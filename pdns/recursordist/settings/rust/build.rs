fn main() {
    let sources = vec!["src/lib.rs", "src/web.rs"];
    cxx_build::bridges(sources)
        // .file("src/source.cc") Code callable from Rust is in ../cxxsupport.cc
        .flag_if_supported("-std=c++17")
        .flag("-Isrc")
        .flag("-I../../..")
        .compile("settings");
}
