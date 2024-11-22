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

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct PoolActionConfig {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        pool: String,
        #[serde(default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
        stop_processing: bool,
    }

    struct SharedDNSAction {
        action: SharedPtr<DNSActionWrapper>,
    }
