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
        type DNSActionWrapper;
        type DNSResponseActionWrapper;
        fn registerProtobufLogger(config: &ProtobufLoggerConfiguration);
        fn registerDnstapLogger(config: &DnstapLoggerConfiguration);
        fn registerKVSObjects(config: &KeyValueStoresConfiguration);
        fn registerNMGObjects(nmgs: &Vec<NetmaskGroupConfiguration>);
        fn registerTimedIPSetObjects(sets: &Vec<TimedIpSetConfiguration>);
    }
}

impl Default for dnsdistsettings::SharedDNSAction {
    fn default() -> dnsdistsettings::SharedDNSAction {
        dnsdistsettings::SharedDNSAction {
            action: cxx::SharedPtr::null(),
        }
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
struct AndSelectorConfigurationSerde {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    selectors: Vec<Selector>,
}

#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct OrSelectorConfigurationSerde {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    selectors: Vec<Selector>,
}

#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct NotSelectorConfigurationSerde {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    selector: Box<Selector>,
}

#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct ContinueActionConfigurationSerde {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    action: Box<Action>,
}

#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct QueryRuleConfigurationSerde {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    name: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    uuid: String,
    selector: Selector,
    action: Action,
}

impl QueryRuleConfigurationSerde {
  fn validate(&self) -> Result<(), ValidationError> {
    Ok(())
  }
}

#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct ResponseRuleConfigurationSerde {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    name: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    uuid: String,
    selector: Selector,
    action: ResponseAction,
}

impl ResponseRuleConfigurationSerde {
  fn validate(&self) -> Result<(), ValidationError> {
    Ok(())
  }
}
