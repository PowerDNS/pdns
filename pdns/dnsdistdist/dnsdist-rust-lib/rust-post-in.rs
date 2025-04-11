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

fn get_query_rules_from_serde(
    rules_from_serde: &Vec<QueryRuleConfigurationSerde>,
) -> Vec<dnsdistsettings::QueryRuleConfiguration> {
    let mut results: Vec<dnsdistsettings::QueryRuleConfiguration> = Vec::new();

    for rule in rules_from_serde {
        let selector = get_one_selector_from_serde(&rule.selector);
        let action = get_one_action_from_serde(&rule.action);
        if selector.is_some() && action.is_some() {
            results.push(dnsdistsettings::QueryRuleConfiguration {
              name: rule.name.clone(),
              uuid: rule.uuid.clone(),
              selector: selector.unwrap(),
              action: action.unwrap(),
            });
        }
    }
    results
}

fn get_response_rules_from_serde(
    rules_from_serde: &Vec<ResponseRuleConfigurationSerde>,
) -> Vec<dnsdistsettings::ResponseRuleConfiguration> {
    let mut results: Vec<dnsdistsettings::ResponseRuleConfiguration> = Vec::new();

    for rule in rules_from_serde {
        let selector = get_one_selector_from_serde(&rule.selector);
        let action = get_one_response_action_from_serde(&rule.action);
        if selector.is_some() && action.is_some() {
            results.push(dnsdistsettings::ResponseRuleConfiguration {
              name: rule.name.clone(),
              uuid: rule.uuid.clone(),
              selector: selector.unwrap(),
              action: action.unwrap(),
            });
        }
    }
    results
}

fn register_remote_loggers(
  config: &dnsdistsettings::RemoteLoggingConfiguration,
) {
  for logger in &config.protobuf_loggers {
    dnsdistsettings::registerProtobufLogger(&logger);
  }
  for logger in &config.dnstap_loggers {
    dnsdistsettings::registerDnstapLogger(&logger);
  }
}

fn get_global_configuration_from_serde(
    serde: GlobalConfigurationSerde,
) -> dnsdistsettings::GlobalConfiguration {
    let mut config: dnsdistsettings::GlobalConfiguration = Default::default();
    config.key_value_stores = serde.key_value_stores;
    config.webserver = serde.webserver;
    config.console = serde.console;
    config.edns_client_subnet = serde.edns_client_subnet;
    config.dynamic_rules_settings = serde.dynamic_rules_settings;
    config.dynamic_rules = serde.dynamic_rules;
    config.acl = serde.acl;
    config.ring_buffers = serde.ring_buffers;
    config.binds = serde.binds;
    config.backends = serde.backends;
    config.cache_settings = serde.cache_settings;
    config.security_polling = serde.security_polling;
    config.general = serde.general;
    config.packet_caches = serde.packet_caches;
    config.proxy_protocol = serde.proxy_protocol;
    config.snmp = serde.snmp;
    config.query_count = serde.query_count;
    config.load_balancing_policies = serde.load_balancing_policies;
    config.pools = serde.pools;
    config.metrics = serde.metrics;
    config.remote_logging = serde.remote_logging;
    config.tuning = serde.tuning;
    // this needs to be done before the rules so that they can refer to the loggers
    register_remote_loggers(&config.remote_logging);
    // this needs to be done before the rules so that they can refer to the KVS objects
    dnsdistsettings::registerKVSObjects(&config.key_value_stores);
    // this needs to be done BEFORE the rules so that they can refer to the selectors
    // by name
    config.selectors = get_selectors_from_serde(&serde.selectors);
    config.query_rules = get_query_rules_from_serde(&serde.query_rules);
    config.cache_miss_rules = get_query_rules_from_serde(&serde.cache_miss_rules);
    config.response_rules = get_response_rules_from_serde(&serde.response_rules);
    config.cache_hit_response_rules = get_response_rules_from_serde(&serde.cache_hit_response_rules);
    config.cache_inserted_response_rules = get_response_rules_from_serde(&serde.cache_inserted_response_rules);
    config.self_answered_response_rules = get_response_rules_from_serde(&serde.self_answered_response_rules);
    config.xfr_response_rules = get_response_rules_from_serde(&serde.xfr_response_rules);
    config.timeout_response_rules = get_response_rules_from_serde(&serde.timeout_response_rules);
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
