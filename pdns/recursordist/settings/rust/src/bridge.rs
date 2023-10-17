/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

use once_cell::sync::Lazy;
use std::fs::File;
use std::io::{BufReader, BufWriter, ErrorKind, Write};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Mutex;

use crate::helpers::OVERRIDE_TAG;
use crate::recsettings::*;
use crate::{Merge, ValidationError};

impl Default for ForwardZone {
    fn default() -> Self {
        let deserialized: ForwardZone = serde_yaml::from_str("").unwrap();
        deserialized
    }
}

impl Default for AuthZone {
    fn default() -> Self {
        let deserialized: AuthZone = serde_yaml::from_str("").unwrap();
        deserialized
    }
}

impl Default for ApiZones {
    fn default() -> Self {
        let deserialized: ApiZones = serde_yaml::from_str("").unwrap();
        deserialized
    }
}

pub fn validate_socket_address(field: &str, val: &String) -> Result<(), ValidationError> {
    let sa = SocketAddr::from_str(val);
    if sa.is_err() {
        let ip = IpAddr::from_str(val);
        if ip.is_err() {
            let msg = format!(
                "{}: value `{}' is not an IP or IP:port combination",
                field, val
            );
            return Err(ValidationError { msg });
        }
    }
    Ok(())
}

fn validate_name(field: &str, val: &String) -> Result<(), ValidationError> {
    if val.is_empty() {
        let msg = format!("{}: value may not be empty", field);
        return Err(ValidationError { msg });
    }
    if val == "." {
        return Ok(());
    }
    // Strip potential dot at end
    let mut testval = val.as_str();
    if testval.ends_with('.') {
        testval = &testval[0..testval.len() - 1];
    }
    for label in testval.split('.') {
        if label.is_empty() {
            let msg = format!("{}: `{}' has empty label", field, val);
            return Err(ValidationError { msg });
        }
        // XXX Too liberal, should check for alnum, - and proper \ddd
        if !label.chars().all(|ch| ch.is_ascii()) {
            let msg = format!("{}: `{}' contains non-ascii character", field, val);
            return Err(ValidationError { msg });
        }
    }
    Ok(())
}

pub fn validate_subnet(field: &str, val: &String) -> Result<(), ValidationError> {
    if val.is_empty() {
        let msg = format!("{}: value `{}' is not a subnet or IP", field, val);
        return Err(ValidationError { msg });
    }
    let mut ip = val.as_str();
    if val.starts_with('!') {
        ip = &ip[1..];
    }
    let subnet = ipnet::IpNet::from_str(ip);
    if subnet.is_err() {
        let ip = IpAddr::from_str(ip);
        if ip.is_err() {
            let msg = format!("{}: value `{}' is not a subnet or IP", field, val);
            return Err(ValidationError { msg });
        }
    }
    Ok(())
}

pub fn validate_vec<T, F>(field: &str, vec: &[T], func: F) -> Result<(), ValidationError>
where
    F: Fn(&str, &T) -> Result<(), ValidationError>,
{
    vec.iter().try_for_each(|element| func(field, element))
}

pub fn parse_yaml_string(str: &str) -> Result<Recursorsettings, serde_yaml::Error> {
    serde_yaml::from_str(str)
}

pub fn parse_yaml_string_to_allow_from(str: &str) -> Result<Vec<String>, serde_yaml::Error> {
    serde_yaml::from_str(str)
}

pub fn parse_yaml_string_to_forward_zones(
    str: &str,
) -> Result<Vec<ForwardZone>, serde_yaml::Error> {
    serde_yaml::from_str(str)
}

pub fn parse_yaml_string_to_api_zones(str: &str) -> Result<ApiZones, serde_yaml::Error> {
    serde_yaml::from_str(str)
}

pub fn parse_yaml_string_to_allow_notify_for(
    str: &str,
) -> Result<Vec<String>, serde_yaml::Error> {
    serde_yaml::from_str(str)
}

pub fn forward_zones_to_yaml_string(vec: &Vec<ForwardZone>) -> Result<String, serde_yaml::Error> {
    serde_yaml::to_string(vec)
}

impl ForwardZone {
    pub fn validate(&self, field: &str) -> Result<(), ValidationError> {
        validate_name(&(field.to_owned() + ".zone"), &self.zone)?;
        if self.forwarders.is_empty() {
            let msg = format!("{}.forwarders cannot be empty", field);
            return Err(ValidationError { msg });
        }
        validate_vec(
            &(field.to_owned() + ".forwarders"),
            &self.forwarders,
            validate_socket_address,
        )
    }

    fn to_yaml_map(&self) -> serde_yaml::Value {
        let mut seq = serde_yaml::Sequence::new();
        for entry in &self.forwarders {
            seq.push(serde_yaml::Value::String(entry.to_owned()));
        }

        let mut map = serde_yaml::Mapping::new();
        map.insert(
            serde_yaml::Value::String("zone".to_owned()),
            serde_yaml::Value::String(self.zone.to_owned()),
        );
        map.insert(
            serde_yaml::Value::String("recurse".to_owned()),
            serde_yaml::Value::Bool(self.recurse),
        );
        map.insert(
            serde_yaml::Value::String("forwarders".to_owned()),
            serde_yaml::Value::Sequence(seq),
        );
        serde_yaml::Value::Mapping(map)
    }
}

impl AuthZone {
    pub fn validate(&self, field: &str) -> Result<(), ValidationError> {
        validate_name(&(field.to_owned() + ".zone"), &self.zone)?;
        if self.file.is_empty() {
            let msg = format!("{}.file cannot be empty", field);
            return Err(ValidationError { msg });
        }
        Ok(())
    }

    fn to_yaml_map(&self) -> serde_yaml::Value {
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            serde_yaml::Value::String("zone".to_owned()),
            serde_yaml::Value::String(self.zone.to_owned()),
        );
        map.insert(
            serde_yaml::Value::String("file".to_owned()),
            serde_yaml::Value::String(self.file.to_owned()),
        );
        serde_yaml::Value::Mapping(map)
    }
}

#[allow(clippy::ptr_arg)] //# Avoids creating a rust::Slice object on the C++ side.
pub fn validate_auth_zones(field: &str, vec: &Vec<AuthZone>) -> Result<(), ValidationError> {
    validate_vec(field, vec, |field, element| element.validate(field))
}

#[allow(clippy::ptr_arg)] //# Avoids creating a rust::Slice object on the C++ side.
pub fn validate_forward_zones(
    field: &str,
    vec: &Vec<ForwardZone>,
) -> Result<(), ValidationError> {
    validate_vec(field, vec, |field, element| element.validate(field))
}

pub fn allow_from_to_yaml_string(vec: &Vec<String>) -> Result<String, serde_yaml::Error> {
    let mut seq = serde_yaml::Sequence::new();
    for entry in vec {
        seq.push(serde_yaml::Value::String(entry.to_owned()));
    }
    let val = serde_yaml::Value::Sequence(seq);

    serde_yaml::to_string(&val)
}

pub fn allow_from_to_yaml_string_incoming(
    key: &String,
    filekey: &String,
    vec: &Vec<String>,
) -> Result<String, serde_yaml::Error> {
    // Produce
    // incoming:
    //   allow-from-file: ''
    //   allow-from: !override
    //    - ...
    let mut seq = serde_yaml::Sequence::new();
    for entry in vec {
        seq.push(serde_yaml::Value::String(entry.to_owned()));
    }

    let mut innermap = serde_yaml::Mapping::new();
    innermap.insert(
        serde_yaml::Value::String(filekey.to_owned()),
        serde_yaml::Value::String("".to_owned()),
    );
    let af = Box::new(serde_yaml::value::TaggedValue {
        tag: serde_yaml::value::Tag::new(OVERRIDE_TAG),
        value: serde_yaml::Value::Sequence(seq),
    });
    innermap.insert(
        serde_yaml::Value::String(key.to_owned()),
        serde_yaml::Value::Tagged(af),
    );

    let mut outermap = serde_yaml::Mapping::new();
    outermap.insert(
        serde_yaml::Value::String("incoming".to_owned()),
        serde_yaml::Value::Mapping(innermap),
    );
    let outerval = serde_yaml::Value::Mapping(outermap);

    serde_yaml::to_string(&outerval)
}

#[allow(clippy::ptr_arg)] //# Avoids creating a rust::Slice object on the C++ side.
pub fn validate_allow_from(field: &str, vec: &Vec<String>) -> Result<(), ValidationError> {
    validate_vec(field, vec, validate_subnet)
}

pub fn allow_for_to_yaml_string(vec: &Vec<String>) -> Result<String, serde_yaml::Error> {
    // For purpose of generating yaml allow-for is no different than allow-from as we're handling a
    // vector of Strings
    allow_from_to_yaml_string(vec)
}

#[allow(clippy::ptr_arg)] //# Avoids creating a rust::Slice object on the C++ side.
pub fn validate_allow_for(field: &str, vec: &Vec<String>) -> Result<(), ValidationError> {
    validate_vec(field, vec, validate_name)
}

#[allow(clippy::ptr_arg)] //# Avoids creating a rust::Slice object on the C++ side.
pub fn validate_allow_notify_for(field: &str, vec: &Vec<String>) -> Result<(), ValidationError> {
    validate_vec(field, vec, validate_name)
}

impl Recursorsettings {
    pub fn to_yaml_string(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }

    // validate() is implemented in the (generated) lib.rs
}

pub static DEFAULT_CONFIG: Lazy<Recursorsettings> = Lazy::new(Recursorsettings::default);

pub fn merge_vec<T>(lhs: &mut Vec<T>, rhs: &mut Vec<T>) {
    lhs.append(rhs);
}

// This is used for conversion, where we want to have !override tags in some cases, so we craft a YAML Mapping by hand
pub fn map_to_yaml_string(vec: &Vec<OldStyle>) -> Result<String, serde_yaml::Error> {
    let mut map = serde_yaml::Mapping::new();
    for entry in vec {
        let section = entry.section.as_str();
        if !map.contains_key(section) {
            let newmap = serde_yaml::Mapping::new();
            map.insert(
                serde_yaml::Value::String(section.to_string()),
                serde_yaml::Value::Mapping(newmap),
            );
        }
        if let Some(mapentry) = map.get_mut(section) {
            if let Some(mapping) = mapentry.as_mapping_mut() {
                let val = match entry.type_name.as_str() {
                    "bool" => serde_yaml::Value::Bool(entry.value.bool_val),
                    "u64" => {
                        serde_yaml::Value::Number(serde_yaml::Number::from(entry.value.u64_val))
                    }
                    "f64" => {
                        serde_yaml::Value::Number(serde_yaml::Number::from(entry.value.f64_val))
                    }
                    "String" => serde_yaml::Value::String(entry.value.string_val.to_owned()),
                    "Vec<String>" => {
                        let mut seq = serde_yaml::Sequence::new();
                        for element in &entry.value.vec_string_val {
                            seq.push(serde_yaml::Value::String(element.to_owned()))
                        }
                        serde_yaml::Value::Sequence(seq)
                    }
                    "Vec<ForwardZone>" => {
                        let mut seq = serde_yaml::Sequence::new();
                        for element in &entry.value.vec_forwardzone_val {
                            seq.push(element.to_yaml_map());
                        }
                        serde_yaml::Value::Sequence(seq)
                    }
                    "Vec<AuthZone>" => {
                        let mut seq = serde_yaml::Sequence::new();
                        for element in &entry.value.vec_authzone_val {
                            seq.push(element.to_yaml_map());
                        }
                        serde_yaml::Value::Sequence(seq)
                    }
                    other => serde_yaml::Value::String("map_to_yaml_string: Unknown type: ".to_owned() + other),
                };
                if entry.overriding {
                    let tagged_value = Box::new(serde_yaml::value::TaggedValue {
                        tag: serde_yaml::value::Tag::new(OVERRIDE_TAG),
                        value: val,
                    });
                    mapping.insert(
                        serde_yaml::Value::String(entry.name.to_owned()),
                        serde_yaml::Value::Tagged(tagged_value),
                    );
                } else {
                    mapping.insert(serde_yaml::Value::String(entry.name.to_owned()), val);
                }
            }
        }
    }
    serde_yaml::to_string(&map)
}

pub fn merge(lhs: &mut Recursorsettings, yaml_str: &str) -> Result<(), serde_yaml::Error> {
    // Parse the yaml for the values
    let mut rhs: Recursorsettings = serde_yaml::from_str(yaml_str)?;
    // Parse again for the map containing the keys present, which is used to only override specific values,
    // taking into account !override tags
    let map: serde_yaml::Value = serde_yaml::from_str(yaml_str)?;
    if map.is_mapping() {
        lhs.merge(&mut rhs, map.as_mapping());
    }

    Ok(())
}

// API zones maintenance. In contrast to the old settings code, which creates a settings file per
// zone, we maintain a single yaml file with all settings. File locking is no issue, as we are the
// single process managing this dir. So we only use process specific locking.

impl ApiZones {
    pub fn validate(&self, field: &str) -> Result<(), ValidationError> {
        validate_auth_zones(&(field.to_owned() + ".auth_zones"), &self.auth_zones)?;
        validate_forward_zones(&(field.to_owned() + ".forward_zones"), &self.forward_zones)?;
        Ok(())
    }
}

static LOCK: Mutex<bool> = Mutex::new(false);

// Assume we hold the lock
fn api_read_zones_locked(
    path: &str,
    create: bool,
) -> Result<cxx::UniquePtr<ApiZones>, std::io::Error> {
    let zones = match File::open(path) {
        Ok(file) => {
            let data: Result<ApiZones, serde_yaml::Error> =
                serde_yaml::from_reader(BufReader::new(file));
            match data {
                Err(error) => return Err(std::io::Error::new(ErrorKind::Other, error.to_string())),
                Ok(yaml) => yaml,
            }
        }
        Err(error) => match error.kind() {
            // If the file does not exist we return an empty struct
            ErrorKind::NotFound => {
                if create {
                    ApiZones::default()
                } else {
                    return Err(error);
                }
            }
            // Any other error is fatal
            _ => return Err(error),
        },
    };
    Ok(cxx::UniquePtr::new(zones))
}

// This function is called from C++, it needs to acquire the lock
pub fn api_read_zones(path: &str) -> Result<cxx::UniquePtr<ApiZones>, std::io::Error> {
    let _lock = LOCK.lock().unwrap();
    api_read_zones_locked(path, false)
}

// Assume we hold the lock
fn api_write_zones(path: &str, zones: &ApiZones) -> Result<(), std::io::Error> {
    let mut tmpfile = path.to_owned();
    tmpfile.push_str(".tmp");

    let file = File::create(tmpfile.as_str())?;
    let mut buffered_writer = BufWriter::new(&file);
    if let Err(error) = serde_yaml::to_writer(&mut buffered_writer, &zones) {
        return Err(std::io::Error::new(ErrorKind::Other, error.to_string()));
    }
    buffered_writer.flush()?;
    file.sync_all()?;
    drop(buffered_writer);
    std::fs::rename(tmpfile.as_str(), path)
}

// This function is called from C++, it needs to acquire the lock
pub fn api_add_auth_zone(path: &str, authzone: AuthZone) -> Result<(), std::io::Error> {
    let _lock = LOCK.lock().unwrap();
    let mut zones = api_read_zones_locked(path, true)?;
    zones.auth_zones.push(authzone);
    api_write_zones(path, &zones)
}

// This function is called from C++, it needs to acquire the lock
pub fn api_add_forward_zone(path: &str, forwardzone: ForwardZone) -> Result<(), std::io::Error> {
    let _lock = LOCK.lock().unwrap();
    let mut zones = api_read_zones_locked(path, true)?;
    zones.forward_zones.push(forwardzone);
    api_write_zones(path, &zones)
}

// This function is called from C++, it needs to acquire the lock
pub fn api_add_forward_zones(path: &str, forwardzones: &mut Vec<ForwardZone>) -> Result<(), std::io::Error> {
    let _lock = LOCK.lock().unwrap();
    let mut zones = api_read_zones_locked(path, true)?;
    zones.forward_zones.append(forwardzones);
    api_write_zones(path, &zones)
}

// This function is called from C++, it needs to acquire the lock
pub fn api_delete_zone(path: &str, zone: &str) -> Result<(), std::io::Error> {
    let _lock = LOCK.lock().unwrap();
    let mut zones = api_read_zones_locked(path, true)?;
    zones.auth_zones.retain(|x| x.zone != zone);
    // Zone data file is unlinked in the C++ caller ws-recursor.cc:doDeleteZone()
    zones.forward_zones.retain(|x| x.zone != zone);
    api_write_zones(path, &zones)
}
