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
        fn getSelectorByName(name: &String) -> SharedPtr<DNSSelector>;
        type DNSActionWrapper;
        fn getActionByName(name: &String) -> SharedPtr<DNSActionWrapper>;
        type DNSResponseActionWrapper;

        fn getMaxIPQPSSelector(config: &MaxQPSIPSelectorConfiguration) -> SharedPtr<DNSSelector>;
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
    MaxQPSIP(dnsdistsettings::MaxQPSIPSelectorConfiguration),
    NetmaskGroup(dnsdistsettings::NetmaskGroupSelectorConfig),
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
