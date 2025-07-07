use crate::pdns::{PbdnsMessage, pbdns_message};
use byteorder::{ByteOrder, NetworkEndian};
use chrono::DateTime;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub struct ClientMessage {
    pub client_addr: SocketAddr,
    pub msg: PbdnsMessage,
}

#[derive(Clone, Copy)]
enum Direction {
    In,
    Out,
}

fn make_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}").to_string())
        .collect::<String>()
}

fn make_addr_port(
    msg_family: Option<i32>,
    msg_addr: Option<&Vec<u8>>,
    msg_port: Option<u32>,
) -> String {
    match (msg_family, msg_addr) {
        (Some(family), Some(addr)) => {
            match (pbdns_message::SocketFamily::try_from(family), msg_port) {
                (Ok(pbdns_message::SocketFamily::Inet), Some(port)) => SocketAddrV4::new(
                    Ipv4Addr::from_bits(NetworkEndian::read_u32(&addr[0..4])),
                    u16::try_from(port).unwrap(),
                )
                .to_string(),
                (Ok(pbdns_message::SocketFamily::Inet6), Some(port)) => SocketAddrV6::new(
                    Ipv6Addr::from_bits(NetworkEndian::read_u128(&addr[0..16])),
                    u16::try_from(port).unwrap(),
                    0,
                    0,
                )
                .to_string(),
                (Ok(pbdns_message::SocketFamily::Inet), None) => {
                    Ipv4Addr::from_bits(NetworkEndian::read_u32(&addr[0..4])).to_string()
                }
                (Ok(pbdns_message::SocketFamily::Inet6), None) => {
                    Ipv6Addr::from_bits(NetworkEndian::read_u128(&addr[0..16])).to_string()
                }
                (Err(_), _) => "unsupported".into(),
            }
        }
        (_, _) => "unknown".into(),
    }
}

#[allow(clippy::too_many_lines)]
fn print_summary(cmsg: &ClientMessage, dir: Direction, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", cmsg.client_addr)?;

    write!(
        f,
        " {}",
        match cmsg.msg.time_sec {
            Some(epoch_secs) => {
                let mut micros = i64::from(epoch_secs) * 1_000_000;
                if let Some(epoch_usec) = cmsg.msg.time_usec {
                    micros += i64::from(epoch_usec);
                }
                DateTime::from_timestamp_micros(micros)
                    .unwrap()
                    .to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
            }
            None => "unknown".into(),
        }
    )?;

    write!(
        f,
        " {} ({})",
        match cmsg.msg.r#type() {
            pbdns_message::Type::DnsQueryType | pbdns_message::Type::DnsOutgoingQueryType =>
                "Query",
            pbdns_message::Type::DnsResponseType | pbdns_message::Type::DnsIncomingResponseType =>
                "Response",
        },
        match dir {
            Direction::In => "I",
            Direction::Out => "O",
        }
    )?;

    write!(
        f,
        " {}",
        match cmsg.msg.in_bytes {
            Some(bytes) => bytes.to_string(),
            None => "unknown".into(),
        }
    )?;

    write!(
        f,
        " {} {}",
        make_addr_port(
            cmsg.msg.socket_family,
            cmsg.msg.from.as_ref(),
            cmsg.msg.from_port
        ),
        make_addr_port(
            cmsg.msg.socket_family,
            cmsg.msg.to.as_ref(),
            cmsg.msg.to_port
        ),
    )?;

    write!(
        f,
        " {}",
        match &cmsg.msg.original_requestor_subnet {
            Some(addr) => match addr.len() {
                4 => Ipv4Addr::from_bits(NetworkEndian::read_u32(&addr[0..4])).to_string(),
                16 => format!(
                    "[{}]",
                    Ipv6Addr::from_bits(NetworkEndian::read_u128(&addr[0..16]))
                ),
                _ => "unsupported".into(),
            },
            None => "N/A".into(),
        }
    )?;

    write!(
        f,
        " {}",
        match cmsg.msg.socket_protocol {
            Some(proto) => match pbdns_message::SocketProtocol::try_from(proto) {
                Ok(p) => p.as_str_name(),
                Err(_) => "unsupported",
            },
            None => "unknown",
        }
    )?;

    write!(
        f,
        " {}",
        // msg.id and message_id are optional in the protobuf schema, but will always be present
        match (
            cmsg.msg.id,
            &cmsg.msg.message_id,
            &cmsg.msg.initial_request_id
        ) {
            (Some(id), Some(msg_id), None) => format!("id: {id} uuid: {}", make_hex_string(msg_id)),
            (Some(id), Some(msg_id), Some(initial_id)) => format!(
                "id: {id} uuid: {}, initial uuid: {}",
                make_hex_string(msg_id),
                make_hex_string(initial_id)
            ),
            (_, _, _) => unreachable!(),
        }
    )?;

    write!(
        f,
        " requestorid: {}",
        match &cmsg.msg.requestor_id {
            Some(id) => id.clone(),
            None => "N/A".into(),
        }
    )?;

    write!(
        f,
        " deviceid: {}",
        match &cmsg.msg.device_id {
            Some(id) => make_hex_string(id),
            None => "N/A".into(),
        }
    )?;

    write!(
        f,
        " devicename: {}",
        match &cmsg.msg.device_name {
            Some(name) => name.clone(),
            None => "N/A".into(),
        }
    )?;

    write!(
        f,
        " serverid: {}",
        // server_identity is not a string in the protobuf schema, but should be
        match &cmsg.msg.server_identity {
            Some(id) => String::from_utf8_lossy(id),
            None => "N/A".into(),
        }
    )?;

    write!(
        f,
        " nod: {}",
        match cmsg.msg.newly_observed_domain {
            Some(nod) => nod.to_string(),
            None => "N/A".into(),
        }
    )?;

    write!(
        f,
        " workerId: {}",
        match &cmsg.msg.worker_id {
            Some(id) => id.to_string(),
            None => "N/A".into(),
        }
    )?;

    write!(
        f,
        " pcCacheHit: {}",
        match cmsg.msg.packet_cache_hit {
            Some(hit) => hit.to_string(),
            None => "N/A".into(),
        }
    )?;

    write!(
        f,
        " outgoingQueries: {}",
        match cmsg.msg.outgoing_queries {
            Some(queries) => queries.to_string(),
            None => "N/A".into(),
        }
    )?;

    write!(
        f,
        " headerFlags: {}",
        match cmsg.msg.header_flags {
            Some(flags) => format!("{:#08X}", u32::from_be(flags)),
            None => "N/A".into(),
        }
    )?;

    write!(
        f,
        " ednsVersion: {}",
        match cmsg.msg.edns_version {
            Some(version) => format!("{:#08X}", u32::from_be(version)),
            None => "N/A".into(),
        }
    )?;

    write!(f, " openTelemetryData: len N/A")?;

    writeln!(f)?;

    Ok(())
}

fn print_meta(cmsg: &ClientMessage, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for m in &cmsg.msg.meta {
        let values = m
            .value
            .string_val
            .clone()
            .into_iter()
            .chain(m.value.int_val.clone().into_iter().map(|v| v.to_string()))
            .collect::<Vec<String>>()
            .join(", ");
        writeln!(f, "{} - meta {} -> {}", cmsg.client_addr, m.key, values)?;
    }

    Ok(())
}

fn print_query(cmsg: &ClientMessage, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match &cmsg.msg.question {
        Some(q) => writeln!(
            f,
            "{} - Question {}, {}. {}",
            cmsg.client_addr,
            q.q_class.unwrap_or(1),
            match q.q_type {
                Some(t) => t.to_string(),
                None => "unknown".into(),
            },
            match q.q_name.clone() {
                Some(n) => n,
                None => "unknown".into(),
            }
        ),
        None => Ok(()),
    }
}

impl fmt::Display for ClientMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.msg.r#type() {
            pbdns_message::Type::DnsQueryType | pbdns_message::Type::DnsIncomingResponseType => {
                print_summary(self, Direction::In, f)?;
            }
            pbdns_message::Type::DnsResponseType | pbdns_message::Type::DnsOutgoingQueryType => {
                print_summary(self, Direction::Out, f)?;
            }
        }
        print_meta(self, f)?;
        print_query(self, f)
    }
}
