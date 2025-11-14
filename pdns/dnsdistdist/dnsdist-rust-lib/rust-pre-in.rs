use serde::{Deserialize, Serialize};

mod helpers;
use helpers::*;

#[derive(Debug)]
pub struct ValidationError {
    msg: String,
}

#[cxx::bridge(namespace = dnsdist::rust::settings)]
mod dnsdistsettings {
    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct ResponseConfig {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        set_aa: bool,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        set_ad: bool,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        set_ra: bool,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        ttl: u32,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct SOAParams {
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct SVCRecordAdditionalParams {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        key: u16,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        value: String,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct SVCRecordParameters {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        mandatory_params: Vec<u16>,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        alpns: Vec<String>,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        ipv4_hints: Vec<String>,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        ipv6_hints: Vec<String>,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        additional_params: Vec<SVCRecordAdditionalParams>,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        target: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        port: u16,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        priority: u16,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        no_default_alpn: bool,
    }

    struct SharedDNSSelector {
        selector: SharedPtr<DNSSelector>,
    }

    struct SharedDNSAction {
        action: SharedPtr<DNSActionWrapper>,
    }

    struct SharedDNSResponseAction {
        action: SharedPtr<DNSResponseActionWrapper>,
    }
