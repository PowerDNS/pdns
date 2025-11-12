fn main() {
    let sources = vec!["src/lib.rs", "src/web.rs", "src/misc.rs"];
    cxx_build::bridges(sources)
        // .file("src/source.cc") Code callable from Rust is in ../cxxsupport.cc
        .std("c++17")
        .flag("-Isrc")
        .flag("-I../..")
        .compile("recrust");

    // lib.rs is generated and taken care of by parent Makefile
    println!("cargo:rerun-if-changed=src/misc.rs");
    println!("cargo:rerun-if-changed=src/web.rs");
}
