use std::io::Result;

fn main() -> Result<()> {
    let mut prost_build = prost_build::Config::new();

    prost_build.default_package_filename("pdns");
    prost_build.compile_protos(&["dnsmessage.proto"], &["../../pdns"])?;

    #[cfg(feature = "opentelemetry")]
    todo!();

    Ok(())
}
