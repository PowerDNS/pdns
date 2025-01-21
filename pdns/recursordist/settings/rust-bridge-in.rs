// This file (rust-bridge-in.rs) is included into lib.rs inside the bridge module
/*
 * Implement non-generated structs that need to be handled by Serde and CXX
 */

// A single forward zone
#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ForwardZone {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    zone: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    forwarders: Vec<String>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    recurse: bool,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    notify_allowed: bool,
}

// A single auth zone
#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthZone {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    zone: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    file: String,
}

// A single trust anchor
#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchor {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    name: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    dsrecords: Vec<String>,
}

// A single negative trust anchor
#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NegativeTrustAnchor {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    name: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    reason: String,
}

// A protobuf logging server
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtobufServer {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    servers: Vec<String>,
    #[serde(default = "crate::U64::<2>::value", skip_serializing_if = "crate::U64::<2>::is_equal")]
    timeout: u64,
    #[serde(default = "crate::U64::<100>::value", skip_serializing_if = "crate::U64::<100>::is_equal")]
    maxQueuedEntries: u64,
    #[serde(default = "crate::U64::<1>::value", skip_serializing_if = "crate::U64::<1>::is_equal")]
    reconnectWaitTime: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    taggedOnly: bool,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    asyncConnect: bool,
    #[serde(default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
    logQueries: bool,
    #[serde(default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
    logResponses: bool,
    #[serde(default = "crate::def_pb_export_qtypes", skip_serializing_if = "crate::default_value_equal_pb_export_qtypes")]
    exportTypes: Vec<String>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    logMappedFrom: bool,
}

// A dnstap logging server
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DNSTapFrameStreamServer {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    servers: Vec<String>,
    #[serde(default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
    logQueries: bool,
    #[serde(default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
    logResponses: bool,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    bufferHint: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    flushTimeout: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    inputQueueSize: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    outputQueueSize: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    queueNotifyThreshold: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    reopenInterval: u64,
}

// A dnstap logging NOD server
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DNSTapNODFrameStreamServer {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    servers: Vec<String>,
    #[serde(default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
    logNODs: bool,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    logUDRs: bool,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    bufferHint: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    flushTimeout: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    inputQueueSize: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    outputQueueSize: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    queueNotifyThreshold: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    reopenInterval: u64,
}

#[derive(Default, Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TSIGTriplet {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    name: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    algo: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    secret: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RPZ {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    name: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    defcontent: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    defpol: String,
    #[serde(default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
    defpolOverrideLocalData: bool,
    #[serde(default = "crate::U32::<{u32::MAX}>::value", skip_serializing_if = "crate::U32::<{u32::MAX}>::is_equal")]
    defttl: u32,
    #[serde(default = "crate::U32::<{u32::MAX}>::value", skip_serializing_if = "crate::U32::<{u32::MAX}>::is_equal")]
    extendedErrorCode: u32,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    extendedErrorExtra: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    includeSOA: bool,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    ignoreDuplicates: bool,
    #[serde(default = "crate::U32::<{u32::MAX}>::value", skip_serializing_if = "crate::U32::<{u32::MAX}>::is_equal")]
    maxTTL: u32,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    policyName: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    tags: Vec<String>,
    #[serde(default = "crate::Bool::<true>::value", skip_serializing_if = "crate::if_true")]
    overridesGettag: bool,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    zoneSizeHint: u32,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    tsig: TSIGTriplet,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    refresh: u32,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    maxReceivedMBytes: u32,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    localAddress: String,
    #[serde(default = "crate::U32::<20>::value", skip_serializing_if = "crate::U32::<20>::is_equal")]
    axfrTimeout: u32,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    dumpFile: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    seedFile: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ZoneToCache {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    zone: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    method: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    sources: Vec<String>,
    #[serde(default = "crate::U64::<20>::value", skip_serializing_if = "crate::U64::<20>::is_equal")]
    timeout: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    tsig: TSIGTriplet,
    #[serde(default = "crate::U64::<86400>::value", skip_serializing_if = "crate::U64::<86400>::is_equal")]
    refreshPeriod: u64,
    #[serde(default = "crate::U64::<60>::value", skip_serializing_if = "crate::U64::<60>::is_equal")]
    retryOnErrorPeriod: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    maxReceivedMBytes: u64,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    localAddress: String,
    #[serde(default = "crate::def_ztc_validate", skip_serializing_if = "crate::def_value_equals_ztc_validate")]
    zonemd: String,
    #[serde(default = "crate::def_ztc_validate", skip_serializing_if = "crate::def_value_equals_ztc_validate")]
    dnssec: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubnetOrder {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    subnet: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    order: u32,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SortList {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    key: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    subnets: Vec<SubnetOrder>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AllowedAdditionalQType {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    qtype: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    targets: Vec<String>,
    #[serde(default = "crate::def_additional_mode", skip_serializing_if = "crate::default_value_equals_additional_mode")]
    mode: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProxyMapping {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    subnet: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    address: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    domains: Vec<String>,
}

// A struct holding both a vector of forward zones and a vector of auth zones, used by REST API code
#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApiZones {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    auth_zones: Vec<AuthZone>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    forward_zones: Vec<ForwardZone>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XFR {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    zoneSizeHint: u32,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    tsig: TSIGTriplet,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    refresh: u32,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    maxReceivedMBytes: u32,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    localAddress: String,
    #[serde(default = "crate::U32::<20>::value", skip_serializing_if = "crate::U32::<20>::is_equal")]
    axfrTimeout: u32,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FCZDefault {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    name: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    forwarders: Vec<String>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    recurse: bool,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    notify_allowed: bool,
 }

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ForwardingCatalogZone {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    zone: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    notify_allowed: bool,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    xfr: XFR,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    groups: Vec<FCZDefault>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IncomingTLS {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    certificate: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    key: String,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    password: String,
}
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IncomingWSConfig {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    tls: IncomingTLS,
}

// Two structs used to generated YAML based on a vector of name to value mappings
// Cannot use Enum as CXX has only very basic Enum support
struct Value {
    bool_val: bool,
    u64_val: u64,
    f64_val: f64,
    string_val: String,
    vec_string_val: Vec<String>,
    vec_forwardzone_val: Vec<ForwardZone>,
    vec_authzone_val: Vec<AuthZone>,
    vec_trustanchor_val: Vec<TrustAnchor>,
    vec_negativetrustanchor_val: Vec<NegativeTrustAnchor>,
    vec_protobufserver_val: Vec<ProtobufServer>,
    vec_dnstap_framestream_server_val: Vec<DNSTapFrameStreamServer>,
    vec_dnstap_nod_framestream_server_val: Vec<DNSTapNODFrameStreamServer>,
    vec_rpz_val: Vec<RPZ>,
    vec_sortlist_val: Vec<SortList>,
    vec_zonetocache_val: Vec<ZoneToCache>,
    vec_allowedadditionalqtype_val: Vec<AllowedAdditionalQType>,
    vec_proxymapping_val: Vec<ProxyMapping>,
    vec_forwardingcatalogzone_val: Vec<ForwardingCatalogZone>,
}

struct OldStyle {
    section: String,
    name: String,
    old_name: String,
    type_name: String,
    value: Value,
    overriding: bool,
}

/*
 * Functions callable from C++
 */
extern "Rust" {
    // Parse a string representing YAML text and produce the corresponding data structure known to Serde
    // The settings that can be stored in individual files get their own parse function
    // Main recursor settings
    fn parse_yaml_string(str: &str) -> Result<Recursorsettings>;
    // Allow from sequence
    fn parse_yaml_string_to_allow_from(str: &str) -> Result<Vec<String>>;
    // Forward zones sequence
    fn parse_yaml_string_to_forward_zones(str: &str) -> Result<Vec<ForwardZone>>;
    // Allow notify for sequence
    fn parse_yaml_string_to_allow_notify_for(str: &str) -> Result<Vec<String>>;
    // REST API zones
    fn parse_yaml_string_to_api_zones(str: &str) -> Result<ApiZones>;

    // Prdoduce a YAML formatted string given a data structure known to Serde
    fn to_yaml_string(self: &Recursorsettings) -> Result<String>;
    // When doing a conversion of old-style to YAML style we use a vector of OldStyle structs
    fn map_to_yaml_string(map: &Vec<OldStyle>) -> Result<String>;
    fn forward_zones_to_yaml_string(vec: &Vec<ForwardZone>) -> Result<String>;
    fn allow_from_to_yaml_string(vec: &Vec<String>) -> Result<String>;
    fn allow_from_to_yaml_string_incoming(key: &String, filekey: &String, vec: &Vec<String>) -> Result<String>;
    fn allow_for_to_yaml_string(vec: &Vec<String>) -> Result<String>;

    // Merge a string representing YAML settings into a existing setttings struct
    fn merge(lhs: &mut Recursorsettings, rhs: &str) -> Result<()>;

    // Validate the sections inside the main settings struct, sections themselves will validate their fields
    fn validate(self: &Recursorsettings) -> Result<()>;
    // The validate function below are "hand-crafted" as their structs are not generated
    fn validate(self: &AuthZone, field: &str) -> Result<()>;
    fn validate(self: &ForwardZone, field: &str) -> Result<()>;
    fn validate(self: &TrustAnchor, field: &str) -> Result<()>;
    fn validate(self: &NegativeTrustAnchor, field: &str) -> Result<()>;
    fn validate(self: &ApiZones, field: &str) -> Result<()>;

    // Helper functions to call the proper validate function on vectors of various kinds
    fn validate_auth_zones(field: &str, vec: &Vec<AuthZone>) -> Result<()>;
    fn validate_forward_zones(field: &str, vec: &Vec<ForwardZone>) -> Result<()>;
    fn validate_allow_for(field: &str, vec: &Vec<String>) -> Result<()>;
    fn validate_allow_notify_for(field: &str, vec: &Vec<String>) -> Result<()>;
    fn validate_allow_from(field: &str, vec: &Vec<String>) -> Result<()>;

    // The functions to maintain REST API managed zones
    fn api_read_zones(path: &str) ->  Result<UniquePtr<ApiZones>>;
    fn api_add_auth_zone(file: &str, authzone: AuthZone) -> Result<()>;
    fn api_add_forward_zone(file: &str, forwardzone: ForwardZone) -> Result<()>;
    fn api_add_forward_zones(file: &str, forwardzones: &mut Vec<ForwardZone>) -> Result<()>;
    fn validate_trustanchors(field: &str, vec: &Vec<TrustAnchor>) -> Result<()>;
    fn validate_negativetrustanchors(field: &str, vec: &Vec<NegativeTrustAnchor>) -> Result<()>;
    fn api_delete_zone(file: &str, zone: &str) -> Result<()>;
    fn api_delete_zones(file: &str) -> Result<()>;
}

unsafe extern "C++" {
    include!("bridge.hh");
    fn qTypeStringToCode(name: &str) -> u16;
    fn isValidHostname(name: &str) -> bool;
}
