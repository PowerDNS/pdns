// START INCLUDE dnsdist-rust-lib/rust-pre-in.rs
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
// END INCLUDE dnsdist-rust-lib/rust-pre-in.rs
    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct TlsConfiguration {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        provider: String,
        certificate: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        key: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        password: String,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct OutgoingTlsConfiguration {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        provider: String,
        #[serde(rename = "subject-name", default, skip_serializing_if = "crate::is_default")]
        subject_name: String,
        #[serde(rename = "validate-certificate", default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
        validate_certificate: bool,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct OutgoingDohConfiguration {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        path: String,
        #[serde(rename = "add-x-forwarded-for-headers", default, skip_serializing_if = "crate::is_default")]
        add_x_forwarded_for_headers: bool,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct CarbonConfiguration {
        address: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        #[serde(default = "crate::U32::<30>::value", skip_serializing_if = "crate::U32::<30>::is_equal")]
        interval: u32,
        #[serde(rename = "namespace", default, skip_serializing_if = "crate::is_default")]
        name_space: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        instance: String,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct ProtobufLoggerConfiguration {
        address: String,
        #[serde(default = "crate::U16::<2>::value", skip_serializing_if = "crate::U16::<2>::is_equal")]
        timeout: u16,
        #[serde(rename = "max-queued-entries", default = "crate::U64::<100>::value", skip_serializing_if = "crate::U64::<100>::is_equal")]
        max_queued_entries: u64,
        #[serde(rename = "reconnect-wait-time", default = "crate::U8::<1>::value", skip_serializing_if = "crate::U8::<1>::is_equal")]
        reconnect_wait_time: u8,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct MetricsConfiguration {
        carbon: Vec<CarbonConfiguration>,
        protobuf_logger: Vec<ProtobufLoggerConfiguration>,
    }
    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct WebserverConfiguration {
        #[serde(rename = "listen-addresses", default, skip_serializing_if = "crate::is_default")]
        listen_addresses: Vec<String>,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        password: String,
        #[serde(rename = "api-key", default, skip_serializing_if = "crate::is_default")]
        api_key: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        acl: Vec<String>,
        #[serde(rename = "api-requires-authentication", default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
        api_requires_authentication: bool,
        #[serde(rename = "dashboard-requires-authentication", default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
        dashboard_requires_authentication: bool,
        #[serde(rename = "max-concurrent-connections", default = "crate::U32::<100>::value", skip_serializing_if = "crate::U32::<100>::is_equal")]
        max_concurrent_connections: u32,
        #[serde(rename = "hash-plaintext-credentials", default, skip_serializing_if = "crate::is_default")]
        hash_plaintext_credentials: bool,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct ConsoleConfiguration {
        listen_address: String,
        key: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        acl: Vec<String>,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct EdnsClientSubnetConfiguration {
        #[serde(rename = "override-existing", default, skip_serializing_if = "crate::is_default")]
        override_existing: bool,
        #[serde(rename = "source-prefix-v4", default = "crate::U8::<32>::value", skip_serializing_if = "crate::U8::<32>::is_equal")]
        source_prefix_v4: u8,
        #[serde(rename = "source-prefix-v6", default = "crate::U8::<48>::value", skip_serializing_if = "crate::U8::<48>::is_equal")]
        source_prefix_v6: u8,
    }


    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct RingBufferConfiguration {
        #[serde(default = "crate::U64::<10000>::value", skip_serializing_if = "crate::U64::<10000>::is_equal")]
        size: u64,
        #[serde(default = "crate::U64::<10>::value", skip_serializing_if = "crate::U64::<10>::is_equal")]
        shards: u64,
        #[serde(rename = "lock-retries", default = "crate::U64::<5>::value", skip_serializing_if = "crate::U64::<5>::is_equal")]
        lock_retries: u64,
        #[serde(rename = "record-queries", default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
        record_queries: bool,
        #[serde(rename = "record-responses", default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
        record_responses: bool,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct BindsConfiguration {
        listen_address: String,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        reuseport: bool,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        protocol: String,
        #[serde(default = "crate::U32::<1>::value", skip_serializing_if = "crate::U32::<1>::is_equal")]
        threads: u32,
        tls: TlsConfiguration,
        doh: DohConfiguration,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct BackendsConfiguration {
        address: String,
        protocol: String,
        tls: OutgoingTlsConfiguration,
        doh: OutgoingDohConfiguration,
        #[serde(rename = "max-in-flight", default = "crate::U16::<1>::value", skip_serializing_if = "crate::U16::<1>::is_equal")]
        max_in_flight: u16,
        #[serde(rename = "use-client-subnet", default, skip_serializing_if = "crate::is_default")]
        use_client_subnet: bool,
        #[serde(rename = "use-proxy-protocol", default, skip_serializing_if = "crate::is_default")]
        use_proxy_protocol: bool,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct PacketCachesConfiguration {
        name: String,
        size: u64,
        #[serde(rename = "min-ttl", default, skip_serializing_if = "crate::is_default")]
        min_ttl: u32,
        shards: u32,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct PoolsConfiguration {
        name: String,
        packet_cache: String,
        policy: String,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct DohConfiguration {
        #[serde(rename = "outgoing-worker-threads", default = "crate::U32::<10>::value", skip_serializing_if = "crate::U32::<10>::is_equal")]
        outgoing_worker_threads: u32,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct TcpConfiguration {
        #[serde(rename = "worker-threads", default = "crate::U32::<10>::value", skip_serializing_if = "crate::U32::<10>::is_equal")]
        worker_threads: u32,
        #[serde(rename = "receive-timeout", default = "crate::U32::<2>::value", skip_serializing_if = "crate::U32::<2>::is_equal")]
        receive_timeout: u32,
        #[serde(rename = "send-timeout", default = "crate::U32::<2>::value", skip_serializing_if = "crate::U32::<2>::is_equal")]
        send_timeout: u32,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct TuningConfiguration {
        doh: DohConfiguration,
        tcp: TcpConfiguration,
    }
    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct MaxQPSIPRuleConfiguration {
        #[serde(default, skip_serializing_if = "crate::is_default")]
        name: String,
        qps: u32,
        #[serde(rename = "ipv4-mask", default = "crate::U8::<32>::value", skip_serializing_if = "crate::U8::<32>::is_equal")]
        ipv4_mask: u8,
        #[serde(rename = "ipv6-mask", default = "crate::U8::<64>::value", skip_serializing_if = "crate::U8::<64>::is_equal")]
        ipv6_mask: u8,
        #[serde(default, skip_serializing_if = "crate::is_default")]
        burst: u32,
        #[serde(default = "crate::U32::<300>::value", skip_serializing_if = "crate::U32::<300>::is_equal")]
        expiration: u32,
        #[serde(rename = "cleanup-delay", default = "crate::U32::<60>::value", skip_serializing_if = "crate::U32::<60>::is_equal")]
        cleanup_delay: u32,
        #[serde(rename = "scan-fraction", default = "crate::U32::<10>::value", skip_serializing_if = "crate::U32::<10>::is_equal")]
        scan_fraction: u32,
        #[serde(default = "crate::U32::<10>::value", skip_serializing_if = "crate::U32::<10>::is_equal")]
        shards: u32,
    }

    #[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct SelectorsConfiguration {
        maxqpsiprule: MaxQPSIPRuleConfiguration,
    }
    #[derive(Default)]
    struct GlobalConfiguration {
        metrics: MetricsConfiguration,
        webserver: WebserverConfiguration,
        console: ConsoleConfiguration,
        edns_client_subnet: EdnsClientSubnetConfiguration,
        acl: Vec<String>,
        ring_buffer: RingBufferConfiguration,
        binds: Vec<BindsConfiguration>,
        backends: Vec<BackendsConfiguration>,
        packet_caches: Vec<PacketCachesConfiguration>,
        pools: Vec<PoolsConfiguration>,
        tuning: TuningConfiguration,
        selectors: Vec<SharedDNSSelector>,
    }
// START INCLUDE dnsdist-rust-lib/rust-middle-in.rs
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
        fn getMaxIPQPSSelector(config: &MaxQPSIPRuleConfiguration) -> SharedPtr<DNSSelector>;
        fn getTCPSelector(config: &TCPSelectorConfig) -> SharedPtr<DNSSelector>;
        fn getAllSelector() -> SharedPtr<DNSSelector>;
        fn getAndSelector(config: &AndSelectorConfig) -> SharedPtr<DNSSelector>;
        fn getNetmaskGroupSelector(config: &NetmaskGroupSelectorConfig) -> SharedPtr<DNSSelector>;
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
    TCP(dnsdistsettings::TCPSelectorConfig),
    MaxQPSIP(dnsdistsettings::MaxQPSIPRuleConfiguration),
    NetmaskGroup(dnsdistsettings::NetmaskGroupSelectorConfig),
}
// END INCLUDE dnsdist-rust-lib/rust-middle-in.rs
#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct GlobalConfigurationSerde {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    metrics: dnsdistsettings::MetricsConfiguration,
    #[serde(rename = "Webserver", default, skip_serializing_if = "crate::is_default")]
    webserver: dnsdistsettings::WebserverConfiguration,
    #[serde(rename = "Console", default, skip_serializing_if = "crate::is_default")]
    console: dnsdistsettings::ConsoleConfiguration,
    #[serde(rename = "edns-client-subnet", default, skip_serializing_if = "crate::is_default")]
    edns_client_subnet: dnsdistsettings::EdnsClientSubnetConfiguration,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    acl: Vec<String>,
    #[serde(rename = "ring-buffer", default, skip_serializing_if = "crate::is_default")]
    ring_buffer: dnsdistsettings::RingBufferConfiguration,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    binds: Vec<dnsdistsettings::BindsConfiguration>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    backends: Vec<dnsdistsettings::BackendsConfiguration>,
    #[serde(rename = "packet-caches", default, skip_serializing_if = "crate::is_default")]
    packet_caches: Vec<dnsdistsettings::PacketCachesConfiguration>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    pools: Vec<dnsdistsettings::PoolsConfiguration>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    tuning: dnsdistsettings::TuningConfiguration,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    selectors: Vec<Selector>,
}
// START INCLUDE dnsdist-rust-lib/rust-post-in.rs
fn get_one_selector_from_serde(selector: &Selector) -> Option<dnsdistsettings::SharedDNSSelector> {
    match selector {
        Selector::None => {}
        Selector::All(_) => {
            return Some(dnsdistsettings::SharedDNSSelector {
                selector: dnsdistsettings::getAllSelector(),
            });
        }
        Selector::ByName(sel) => {
            let selector_from_name = dnsdistsettings::getSelectorByName(&sel.name);
            if selector_from_name.is_null() {
                panic!("Unable to find a selector named {}", sel.name);
            }
            return Some(dnsdistsettings::SharedDNSSelector {
                selector: selector_from_name,
            });
        }
        Selector::TCP(config) => {
            return Some(dnsdistsettings::SharedDNSSelector {
                selector: dnsdistsettings::getTCPSelector(&config),
            });
        }
        Selector::And(sel) => {
            let mut config: dnsdistsettings::AndSelectorConfig = Default::default();
            for sub_selector in &sel.selectors {
                match sub_selector {
                    Selector::ByName(sub_sel) => {
                        config.selectors.push(sub_sel.name.clone());
                    }
                    sub_sel => {
                        let new_selector = get_one_selector_from_serde(&sub_sel);
                        if new_selector.is_some() {
                            config.selectors.push(
                                dnsdistsettings::getNameFromSelector(
                                    &new_selector.unwrap().selector,
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
            return Some(dnsdistsettings::SharedDNSSelector {
                selector: dnsdistsettings::getMaxIPQPSSelector(&conf),
            });
        }
        Selector::NetmaskGroup(conf) => {
            return Some(dnsdistsettings::SharedDNSSelector {
                selector: dnsdistsettings::getNetmaskGroupSelector(&conf),
            });
        }
    }
    None
}

fn get_selectors_from_serde(
    selectors_from_serde: &Vec<Selector>,
) -> Vec<dnsdistsettings::SharedDNSSelector> {
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
    config.selectors = get_selectors_from_serde(&serde.selectors);
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
// END INCLUDE dnsdist-rust-lib/rust-post-in.rs
