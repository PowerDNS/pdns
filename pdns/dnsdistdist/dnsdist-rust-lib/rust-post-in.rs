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

fn get_one_action_from_serde(action: &Action) -> Option<dnsdistsettings::SharedDNSAction> {
    match action {
        Action::None => {}
        Action::Pool(pool) => {
            let pool_action = dnsdistsettings::getPoolAction(&pool);
            return Some(dnsdistsettings::SharedDNSAction {
                action: pool_action,
            });
        }
    }
    None
}

fn get_query_rules_from_serde(
    rules_from_serde: &Vec<QueryRulesConfigurationSerde>,
) -> Vec<dnsdistsettings::QueryRulesConfiguration> {
    let mut results: Vec<dnsdistsettings::QueryRulesConfiguration> = Vec::new();

    for rule in rules_from_serde {
        let selector = get_one_selector_from_serde(&rule.selector);
        let action = get_one_action_from_serde(&rule.action);
        if selector.is_some() && action.is_some() {
            results.push(dnsdistsettings::QueryRulesConfiguration {
              name: rule.name.clone(),
              uuid: rule.uuid.clone(),
              selector: selector.unwrap(),
              action: action.unwrap(),
            });
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
    config.query_rules = get_query_rules_from_serde(&serde.query_rules);
    config.selectors = get_selectors_from_serde(&serde.selectors);
    config
}

pub fn from_yaml_string(
    str: &str,
) -> Result<dnsdistsettings::GlobalConfiguration, serde_yaml::Error> {
    let serde_config: Result<GlobalConfigurationSerde, serde_yaml::Error> =
        serde_yaml::from_str(str);

    if !serde_config.is_err() {
      let validation_result = serde_config.as_ref().unwrap().validate();
      if let Err(e) = validation_result {
          println!("Error validating the configuration loaded from {}: {}", str, e);
      }
    }
    let config: dnsdistsettings::GlobalConfiguration =
        get_global_configuration_from_serde(serde_config?);
    return Ok(config);
}
