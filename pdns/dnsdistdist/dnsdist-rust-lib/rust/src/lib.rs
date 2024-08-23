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
mod dnsdistsetttings {

    #[derive(Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct CarbonConfiguration {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        address: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        interval: u16
    }

    /*
     * Functions callable from C++
     */
    extern "Rust" {
        fn parse_yaml_string(str: &str) -> Result<CarbonConfiguration>;
    }
}

pub fn parse_yaml_string(str: &str) -> Result<dnsdistsetttings::CarbonConfiguration, serde_yaml::Error> {
    serde_yaml::from_str(str)
}
