use crate::display::ClientMessage;
use anyhow::Result;
use byteorder::{BigEndian, ByteOrder};
use log::{debug, error, info, warn};
use prost::Message;
use std::net::IpAddr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

pub async fn listen(address: IpAddr, port: u16) -> Result<()> {
    let listener = TcpListener::bind((address, port)).await?;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            print!("{message}");
        }
    });

    info!("Ready to accept connections on {address}:{port}");

    loop {
        let (mut socket, client_addr) = listener.accept().await?;
        let task_tx = tx.clone();

        tokio::spawn(async move {
            let mut length_buf = [0; 2];
            info!("{client_addr}: connection accepted");

            loop {
                if let Err(e) = socket.read_exact(&mut length_buf).await {
                    error!("{client_addr}: error reading message length: {e}");
                    return;
                }
                let message_length = BigEndian::read_u16(&length_buf) as usize;
                debug!("{client_addr}: message is {message_length} bytes");

                let mut message_buf = vec![0u8; message_length];
                if let Err(e) = socket.read_exact(&mut message_buf).await {
                    error!("{client_addr}: error reading message: {e}");
                    return;
                }

                match crate::pdns::PbdnsMessage::decode(&message_buf[..]) {
                    Ok(msg) => {
                        debug!("{client_addr}: {msg:?}");
                        task_tx
                            .send(format!("{}", ClientMessage { client_addr, msg }))
                            .unwrap();
                    }
                    Err(e) => {
                        warn!("{client_addr}: error decoding message: {e}");
                    }
                }
            }
        });
    }
}
