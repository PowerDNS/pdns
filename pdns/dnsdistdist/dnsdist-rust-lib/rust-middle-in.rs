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
