use serde::{Deserialize, Serialize};

mod helpers;
use helpers::*;

// Suppresses "Deserialize unused" warning
#[derive(Deserialize, Serialize)]
struct UnusedStruct {}

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
        non_default_alpn: bool,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct TCPSelectorConfig {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        tcp: bool,
    }

    #[derive(Default)]
    struct AndSelectorConfig {
        name: String,
        selectors: Vec<SharedDNSSelector>,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct AllSelector {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct ByNameSelector {
        name: String,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct NetmaskGroupSelectorConfig {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(
            default,
            rename = "netmask-group",
            skip_serializing_if = "crate::is_default"
        )]
        netmask_group: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        netmasks: Vec<String>,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        source: bool,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        quiet: bool,
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
