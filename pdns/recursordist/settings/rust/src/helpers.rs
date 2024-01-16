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

use crate::ValidationError;
use std::{error::Error, fmt};

/* Helper code for validation  */
impl Error for ValidationError {}
impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

// Generic helpers

// A helper to define a function returning a constant value and an equal function as a Rust path */
pub struct U64<const U: u64>;
impl<const U: u64> U64<U> {
    pub const fn value() -> u64 {
        U
    }
    pub fn is_equal(v: &u64) -> bool {
        v == &U
    }
}

pub struct U32<const U: u32>;
impl<const U: u32> U32<U> {
    pub const fn value() -> u32 {
        U
    }
    pub fn is_equal(v: &u32) -> bool {
        v == &U
    }
}

// A helper to define constant value as a Rust path */
pub struct Bool<const U: bool>;
impl<const U: bool> Bool<U> {
    pub const fn value() -> bool {
        U
    }
}

// A helper used to decide if a bool value should be skipped
pub fn if_true(v: &bool) -> bool {
    *v
}

/* Helper to decide if a value has a default value, as defined by Default trait */
pub fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

pub const OVERRIDE_TAG: &str = "!override";

pub fn is_overriding(m: &serde_yaml::Mapping, key: &str) -> bool {
    if let Some(serde_yaml::Value::Tagged(vvv)) = m.get(key) {
        return vvv.tag == OVERRIDE_TAG;
    }
    false
}
