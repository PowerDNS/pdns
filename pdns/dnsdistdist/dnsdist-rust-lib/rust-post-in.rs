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
    config.edns_client_subnet = serde.edns_client_subnet;
    config.acl = serde.acl;
    config.ring_buffers = serde.ring_buffers;
    config.binds = serde.binds;
    config.backends = serde.backends;
    config.packet_caches = serde.packet_caches;
    config.pools = serde.pools;
    config.tuning = serde.tuning;
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
