use cxx::let_cxx_string;
use dnsdistsettings::DNSSelector;
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
        #[serde(
            default,
            rename = "listen-address",
            skip_serializing_if = "crate::is_default"
        )]
        listenAddress: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        key: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        acl: Vec<String>,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct WebServerConfiguration {
        #[serde(
            default,
            rename = "listen-addresses",
            skip_serializing_if = "crate::is_default"
        )]
        listenAddresses: Vec<String>,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        password: String,
        #[serde(default, rename = "api-key", skip_serializing_if = "crate::is_default")]
        apiKey: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        acl: Vec<String>,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct CarbonConfiguration {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        address: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        interval: u16,
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
        value: String,
    }

    #[derive(Default, Debug, PartialEq)]
    struct RuleSelector {
        name: String,
        selector_type: String,
        selectors: Vec<RuleSelector>,
        extra: Vec<ExtraValue>,
    }

    #[derive(Default, Debug, PartialEq)]
    struct ResponseRule {
        name: String,
        selector: RuleSelector,
        extra: Vec<ExtraValue>,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct MaxQPSIPRuleConfig {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        qps: u32,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        burst: u32,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        ipv4trunc: u8,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct TCPSelector {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        tcp: bool,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct AndSelectorConfig {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        selectors: Vec<String>,
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
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
    }

    #[derive(Default, Debug, PartialEq)]
    struct TestSelector {
        selector_type: String,
        all: AllSelector,
        andSel: AndSelectorConfig,
        byname: ByNameSelector,
        tcp: TCPSelector,
    }

    struct SharedDNSSelector {
        selector: SharedPtr<DNSSelector>,
    }

    #[derive(Default)]
    struct GlobalConfiguration {
        metrics: MetricsConfiguration,
        webserver: WebServerConfiguration,
        console: ConsoleConfiguration,
        response_rules: Vec<ResponseRule>,
        testselectors: Vec<TestSelector>,
        realselectors: Vec<SharedDNSSelector>,
    }

    /*
     * Functions callable from C++
     */
    extern "Rust" {
        fn from_yaml_string(str: &str) -> Result<GlobalConfiguration>;
    }
    /*
     * Functions callable from Rust
     */
    unsafe extern "C++" {
        include!("dnsdist-rust-bridge.hh");
        type DNSSelector;
        fn getNameFromSelector(selector: &DNSSelector) -> &CxxString;
        fn getSelectorByName(name: &String) -> SharedPtr<DNSSelector>;
        fn getMaxIPQPSSelector(config: &MaxQPSIPRuleConfig) -> SharedPtr<DNSSelector>;
        fn getAllSelector() -> SharedPtr<DNSSelector>;
        fn getAndSelector(config: &AndSelectorConfig) -> SharedPtr<DNSSelector>;
    }
}

impl Default for dnsdistsettings::SharedDNSSelector {
    fn default() -> dnsdistsettings::SharedDNSSelector {
        dnsdistsettings::SharedDNSSelector {
            selector: cxx::SharedPtr::null(),
        }
    }
}

#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
struct RuleSelectorConfiguration {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    name: String,
    #[serde(default, rename = "type", skip_serializing_if = "crate::is_default")]
    selector_type: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    selectors: Vec<RuleSelectorConfiguration>,
    #[serde(flatten)]
    extra: HashMap<String, String>,
}

#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
struct ResponseActionConfiguration {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    name: String,
    #[serde(default, rename = "type", skip_serializing_if = "crate::is_default")]
    action_type: String,
    #[serde(flatten)]
    extra: HashMap<String, String>,
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
    action: ResponseActionConfiguration,
}

#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct AndSelectorSerde {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    selectors: Vec<Selector>,
}

#[derive(Default, Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "type")]
enum Selector {
    #[default]
    None,
    All(dnsdistsettings::AllSelector),
    And(AndSelectorSerde),
    ByName(dnsdistsettings::ByNameSelector),
    TCP(dnsdistsettings::TCPSelector),
    MaxQPSIP(dnsdistsettings::MaxQPSIPRuleConfig),
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
    #[serde(
        default,
        rename = "response-rules",
        skip_serializing_if = "crate::is_default"
    )]
    response_rules: Vec<ResponseRuleConfiguration>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    testselectors: Vec<Selector>,
}

fn get_selector_from_serde(serde: RuleSelectorConfiguration) -> dnsdistsettings::RuleSelector {
    let mut selector = dnsdistsettings::RuleSelector {
        name: serde.name,
        selector_type: serde.selector_type,
        ..Default::default()
    };
    for sub in serde.selectors {
        selector.selectors.push(get_selector_from_serde(sub));
    }
    for (key, value) in serde.extra.into_iter() {
        selector.extra.push(dnsdistsettings::ExtraValue {
            key: key,
            value: value,
        });
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
        config
            .selector
            .selectors
            .push(get_selector_from_serde(selector));
    }
    for (key, value) in serde.selector.extra.into_iter() {
        config.extra.push(dnsdistsettings::ExtraValue {
            key: key,
            value: value,
        });
    }
    config
}

fn get_one_selector_from_serde(selector: &Selector) -> Option<dnsdistsettings::SharedDNSSelector> {
    println!("hello get_one_selector_from_serde!");
    match selector {
        Selector::None => {
            println!("returning none");
        }
        Selector::All(_) => {
            println!("returning all");
            return Some(dnsdistsettings::SharedDNSSelector {
                selector: dnsdistsettings::getAllSelector(),
            });
        }
        Selector::ByName(sel) => {
            println!("returning by name {}", sel.name);
            return Some(dnsdistsettings::SharedDNSSelector {
                selector: dnsdistsettings::getSelectorByName(&sel.name),
            });
        }
        Selector::TCP(_) => {
            println!("returning none for TCP");
        }
        Selector::And(sel) => {
            let mut config: dnsdistsettings::AndSelectorConfig = Default::default();
            for subSelector in &sel.selectors {
                match subSelector {
                    Selector::ByName(subSel) => {
                        println!("pushing by name {}", subSel.name);
                        config.selectors.push(subSel.name.clone());
                    }
                    subSel => {
                        let newSelector = get_one_selector_from_serde(&subSel);
                        println!("pushing by selector");
                        if newSelector.is_some() {
                            println!("really pushing by selector");
                            config.selectors.push(
                                dnsdistsettings::getNameFromSelector(
                                    &newSelector.unwrap().selector,
                                )
                                .to_string(),
                            );
                        }
                    }
                }
            }
            return Some(dnsdistsettings::SharedDNSSelector {
                selector: dnsdistsettings::getAndSelector(&config),
            });
        }
        Selector::MaxQPSIP(conf) => {
            println!("returning maxqpsip");
            return Some(dnsdistsettings::SharedDNSSelector {
                selector: dnsdistsettings::getMaxIPQPSSelector(&conf),
            });
        }
    }
    None
}

fn get_selectors_from_serde(
    selectors_from_serde: &Vec<Selector>,
) -> Vec<dnsdistsettings::SharedDNSSelector> {
    println!("hello get_selectors_from_serde!");
    let mut results: Vec<dnsdistsettings::SharedDNSSelector> = Vec::new();

    for rule in selectors_from_serde {
        let selector = get_one_selector_from_serde(&rule);
        if selector.is_some() {
            results.push(selector.unwrap());
        }
    }
    results
}

fn get_global_configuration_from_serde(
    serde: GlobalConfigurationSerde,
) -> dnsdistsettings::GlobalConfiguration {
    let mut config: dnsdistsettings::GlobalConfiguration = Default::default();
    config.metrics = serde.metrics;
    config.webserver = serde.webserver;
    config.console = serde.console;
    for rule in serde.response_rules {
        config
            .response_rules
            .push(get_response_rule_from_serde(rule));
    }
    config.realselectors = get_selectors_from_serde(&serde.testselectors);
    println!("parsing test selectors now!");
    for rule in serde.testselectors {
        match rule {
            Selector::None => {}
            Selector::All(_) => {
                config.testselectors.push(dnsdistsettings::TestSelector {
                    selector_type: String::from("All"),
                    ..Default::default()
                });
            }
            Selector::And(_) => {
                //config.testselectors.push(dnsdistsettings::TestSelector {
                //    selector_type: String::from("And"),
                //    andSel: dnsdistsettings::AndSelector {
                //        selectors: sel.selectors,
                //    },
                //    ..Default::default()
                //});
            }
            Selector::ByName(sel) => {
                config.testselectors.push(dnsdistsettings::TestSelector {
                    selector_type: String::from("ByName"),
                    byname: dnsdistsettings::ByNameSelector { name: sel.name },
                    ..Default::default()
                });
            }
            Selector::TCP(tcp) => {
                config.testselectors.push(dnsdistsettings::TestSelector {
                    selector_type: String::from("TCP"),
                    tcp: dnsdistsettings::TCPSelector {
                        tcp: tcp.tcp,
                        ..Default::default()
                    },
                    ..Default::default()
                });
            }
            Selector::MaxQPSIP(_) => {}
        }
    }
    config
}

pub fn from_yaml_string(
    str: &str,
) -> Result<dnsdistsettings::GlobalConfiguration, serde_yaml::Error> {
    let serde_config: Result<GlobalConfigurationSerde, serde_yaml::Error> =
        serde_yaml::from_str(str);
    let config: dnsdistsettings::GlobalConfiguration =
        get_global_configuration_from_serde(serde_config?);
    return Ok(config);
}
