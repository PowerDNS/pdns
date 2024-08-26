use serde::{Deserialize, Serialize};

mod helpers;
use helpers::*;

use std::collections::HashMap;

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
    struct ConsoleConfiguration {
        #[serde(default, rename = "listen-address", skip_serializing_if = "crate::is_default")]
        listenAddress: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        key: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        acl: Vec<String>
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct WebServerConfiguration {
        #[serde(default, rename = "listen-addresses", skip_serializing_if = "crate::is_default")]
        listenAddresses: Vec<String>,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        password: String,
        #[serde(default, rename = "api-key", skip_serializing_if = "crate::is_default")]
        apiKey: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        acl: Vec<String>
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct CarbonConfiguration {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        address: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        interval: u16
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct MetricsConfiguration {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        carbon: Vec<CarbonConfiguration>,
    }

    #[derive(Default, Debug, PartialEq)]
    struct ExtraValue {
        key: String,
        value: String
    }

    #[derive(Default, Debug, PartialEq)]
    struct RuleSelector {
        name: String,
        selector_type: String,
        selectors: Vec<RuleSelector>,
        extra: Vec<ExtraValue>
    }

    #[derive(Default, Debug, PartialEq)]
    struct ResponseRule {
        name: String,
        selector: RuleSelector,
        extra: Vec<ExtraValue>
    }

    #[derive(Default, Debug, PartialEq)]
    struct GlobalConfiguration {
        metrics: MetricsConfiguration,
        webserver: WebServerConfiguration,
        console: ConsoleConfiguration,
        response_rules: Vec<ResponseRule>
    }

    /*
     * Functions callable from C++
     */
    extern "Rust" {
        fn parse_yaml_string(str: &str) -> Result<GlobalConfiguration>;
    }
}

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct RuleSelectorConfiguration {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(default, rename = "type", skip_serializing_if = "crate::is_default")]
        selector_type: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        selectors: Vec<RuleSelectorConfiguration>,
        #[serde(flatten)]
        extra: HashMap<String, String>
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    struct ResponseActionConfiguration {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(default, rename = "type", skip_serializing_if = "crate::is_default")]
        action_type: String,
        #[serde(flatten)]
        extra: HashMap<String, String>
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    struct ResponseRuleConfiguration {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        uuid: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        selector: RuleSelectorConfiguration,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        action: ResponseActionConfiguration
    }


    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct GlobalConfigurationSerde {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        metrics: dnsdistsettings::MetricsConfiguration,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        webserver: dnsdistsettings::WebServerConfiguration,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        console: dnsdistsettings::ConsoleConfiguration,
        #[serde(default, rename = "response-rules", skip_serializing_if = "crate::is_default")]
        response_rules: Vec<ResponseRuleConfiguration>
    }

fn get_selector_from_serde(serde: RuleSelectorConfiguration) -> dnsdistsettings::RuleSelector {
   let mut selector = dnsdistsettings::RuleSelector{name: serde.name, selector_type: serde.selector_type, ..Default::default() };
   for sub in serde.selectors {
     selector.selectors.push(get_selector_from_serde(sub));
   }
   selector
}

fn get_response_rule_from_serde(serde: ResponseRuleConfiguration) -> dnsdistsettings::ResponseRule {
     let mut config: dnsdistsettings::ResponseRule = Default::default();
     config.name = serde.name;
     //config.uuid = serde.uuid;
     config.selector.name = serde.selector.name;
     config.selector.selector_type = serde.selector.selector_type;
     for selector in serde.selector.selectors {
         config.selector.selectors.push(get_selector_from_serde(selector));
     }
     for (key, value) in serde.selector.extra.into_iter() {
         config.extra.push(dnsdistsettings::ExtraValue{key: key, value: value});
     }
     config
}

fn get_global_configuration_from_serde(serde: GlobalConfigurationSerde) -> dnsdistsettings::GlobalConfiguration {
  let mut config: dnsdistsettings::GlobalConfiguration = Default::default();
  config.metrics = serde.metrics;
  config.webserver = serde.webserver;
  config.console = serde.console;
  for rule in serde.response_rules {
      config.response_rules.push(get_response_rule_from_serde(rule));
  }
  config
}

pub fn parse_yaml_string(str: &str) -> Result<dnsdistsettings::GlobalConfiguration, serde_yaml::Error> {
    let serde_config: Result<GlobalConfigurationSerde, serde_yaml::Error> = serde_yaml::from_str(str);
    let config: dnsdistsettings::GlobalConfiguration = get_global_configuration_from_serde(serde_config?);
    return Ok(config);
}
