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

// A struct holding bot a vector of forward zones and a vector o auth zones, used by REST API code
#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct ApiZones {
    #[serde(default, skip_serializing_if = "crate::is_default")]
    auth_zones: Vec<AuthZone>,
    #[serde(default, skip_serializing_if = "crate::is_default")]
    forward_zones: Vec<ForwardZone>,
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
    // REST APIU zones
    fn parse_yaml_string_to_api_zones(str: &str) -> Result<ApiZones>;

    // Prdoduce a YAML formatted sting given a data structure known to Serde
    fn to_yaml_string(self: &Recursorsettings) -> Result<String>;
    // When doing a conversion of old-style to YAML style we use a vector of OldStyle structs
    fn map_to_yaml_string(map: &Vec<OldStyle>) -> Result<String>;
    fn forward_zones_to_yaml_string(vec: &Vec<ForwardZone>) -> Result<String>;
    fn allow_from_to_yaml_string(vec: &Vec<String>) -> Result<String>;
    fn allow_from_to_yaml_string_incoming(key: &String, filekey: &String, vec: &Vec<String>) -> Result<String>;
    fn allow_for_to_yaml_string(vec: &Vec<String>) -> Result<String>;

    // Merge a string representing YAML settings into a existing setttings struct
    fn merge(lhs: &mut Recursorsettings, rhs: &str) -> Result<()>;

    // Validate the sections inside the main settings struct, sections themselves will valdiate their fields
    fn validate(self: &Recursorsettings) -> Result<()>;
    // The validate function bewlo are "hand-crafted" as their structs afre mnot generated
    fn validate(self: &AuthZone, field: &str) -> Result<()>;
    fn validate(self: &ForwardZone, field: &str) -> Result<()>;
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
    fn api_delete_zone(file: &str, zone: &str) -> Result<()>;
}
