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

#[cxx::bridge(namespace = "pdns::rust::misc")]
pub mod rustmisc {

    pub enum LogLevel {
        None,
        Normal,
        Detailed,
    }
    enum Priority {
        Absent = 0,
        Alert = 1,
        Critical = 2,
        Error = 3,
        Warning = 4,
        Notice = 5,
        Info = 6,
        Debug = 7,
    }
    struct KeyValue {
        key: String,
        value: String,
    }

    extern "C++" {
        type NetmaskGroup;
        type ComboAddress;
        type Logger;
    }

    unsafe extern "C++" {
        include!("bridge.hh");
        fn qTypeStringToCode(name: &str) -> u16;
        fn isValidHostname(name: &str) -> bool;
        fn comboaddress(address: &str) -> UniquePtr<ComboAddress>;
        fn matches(nmg: &UniquePtr<NetmaskGroup>, address: &UniquePtr<ComboAddress>) -> bool; // match is a keyword
        fn withValue(logger: &SharedPtr<Logger>, key: &str, val: &str) -> SharedPtr<Logger>;
        fn log(logger: &SharedPtr<Logger>, prio: Priority, msg: &str, values: &Vec<KeyValue>);
        fn error(
            logger: &SharedPtr<Logger>,
            prio: Priority,
            err: &str,
            msg: &str,
            values: &Vec<KeyValue>,
        );
    }
}
