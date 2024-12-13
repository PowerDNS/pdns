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
        fn registerProtobufLogger(config: &ProtobufLoggersConfiguration);
        fn registerDnstapLogger(config: &DnstapLoggersConfiguration);
        fn registerKVSObjects(config: &KeyValueStoresConfiguration);
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

impl Selector {
  fn validate(&self) -> Result<(), ValidationError> {
    Ok(())
  }
}

impl Action {
  fn validate(&self) -> Result<(), ValidationError> {
    Ok(())
  }
}

impl ResponseAction {
  fn validate(&self) -> Result<(), ValidationError> {
    Ok(())
  }
}

#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct QueryRulesConfigurationSerde {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    name: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    uuid: String,
    selector: Selector,
    action: Action,
}

impl QueryRulesConfigurationSerde {
  fn validate(&self) -> Result<(), ValidationError> {
    Ok(())
  }
}

#[derive(Default, Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct ResponseRulesConfigurationSerde {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    name: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    uuid: String,
    selector: Selector,
    action: ResponseAction,
}

impl ResponseRulesConfigurationSerde {
  fn validate(&self) -> Result<(), ValidationError> {
    Ok(())
  }
}

impl dnsdistsettings::SharedDNSAction {
  fn validate(&self) -> Result<(), ValidationError> {
    Ok(())
  }
}

impl dnsdistsettings::SharedDNSResponseAction {
  fn validate(&self) -> Result<(), ValidationError> {
    Ok(())
  }
}
