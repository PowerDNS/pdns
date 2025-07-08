use anyhow::Result;
use clap::Parser;
use log::error;
use std::net::IpAddr;
use std::ops::RangeInclusive;

mod display;
mod listener;
mod pdns {
    #![allow(clippy::all, clippy::pedantic)]
    include!(concat!(env!("OUT_DIR"), "/pdns.rs"));
}

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(value_parser = ip_address)]
    listen_address: IpAddr,
    #[arg(value_parser = port_in_range)]
    listen_port: u16,
    #[command(flatten)]
    verbosity: clap_verbosity_flag::Verbosity,
}

fn ip_address(s: &str) -> Result<IpAddr, String> {
    let addr: IpAddr = s
        .parse()
        .map_err(|_| format!("`{s}` isn't a valid IP address"))?;

    Ok(addr)
}

const PORT_RANGE: RangeInclusive<usize> = 1..=65535;

fn port_in_range(s: &str) -> Result<u16, String> {
    let port: usize = s
        .parse()
        .map_err(|_| format!("`{s}` isn't a port number"))?;
    if PORT_RANGE.contains(&port) {
        Ok(u16::try_from(port).unwrap())
    } else {
        Err(format!(
            "port not in range {}-{}",
            PORT_RANGE.start(),
            PORT_RANGE.end()
        ))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    env_logger::Builder::new()
        .filter_level(args.verbosity.into())
        .init();

    if let Err(e) = listener::listen(args.listen_address, args.listen_port).await {
        error!("Listener failed with error: `{e}`");
    }

    Ok(())
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Cli::command().debug_assert();
}
