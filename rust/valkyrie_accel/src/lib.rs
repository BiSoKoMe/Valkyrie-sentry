//! Native accelerators for Valkyrie.
//!
//! Currently one export: `IpSet`, a drop-in for the pure-Python
//! `valkyrie.firewall._PyIPSet`. It answers "is this IPv4 address inside any of
//! the loaded host IPs / CIDR ranges?" — the check the DNS answer-screening path
//! runs on every allowed reply. The algorithm mirrors the Python one exactly
//! (prefix-length bucketing), so results are identical; this just removes the
//! interpreter overhead on a hot path.
//!
//! Semantics are matched to the Python reference on purpose:
//!   * load() accepts a set of strings; "a.b.c.d/n" is a network (host bits are
//!     masked off, matching IPv4Network(strict=False)); "a.b.c.d" is an exact
//!     host; anything unparParseable is silently skipped.
//!   * contains() returns false for malformed/IPv6 input, never errors.
//!   * count() == number_of_host_strings + number_of_network_strings (networks
//!     are counted per input string, matching Python's len(hosts)+net_count).

use pyo3::prelude::*;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::RwLock;

#[inline]
fn mask_for(plen: u8) -> u32 {
    if plen == 0 {
        0
    } else {
        u32::MAX << (32 - plen as u32)
    }
}

#[inline]
fn parse_ipv4(s: &str) -> Option<u32> {
    Ipv4Addr::from_str(s.trim()).ok().map(u32::from)
}

struct Data {
    hosts: HashSet<u32>,
    by_len: HashMap<u8, HashSet<u32>>,
    net_count: usize,
}

/// Fast IPv4 membership over a mixed set of host IPs and CIDR ranges.
#[pyclass]
struct IpSet {
    data: RwLock<Data>,
}

#[pymethods]
impl IpSet {
    #[new]
    fn new() -> Self {
        IpSet {
            data: RwLock::new(Data {
                hosts: HashSet::new(),
                by_len: HashMap::new(),
                net_count: 0,
            }),
        }
    }

    /// Replace the set's contents from an iterable of CIDR/host strings.
    fn load(&self, cidrs: HashSet<String>) {
        let mut hosts: HashSet<u32> = HashSet::new();
        let mut by_len: HashMap<u8, HashSet<u32>> = HashMap::new();
        let mut net_count: usize = 0;

        for c in cidrs.iter() {
            let c = c.trim();
            if let Some(idx) = c.find('/') {
                let addr_s = &c[..idx];
                let plen_s = c[idx + 1..].trim();
                let plen: u8 = match plen_s.parse() {
                    Ok(p) if p <= 32 => p,
                    _ => continue, // invalid prefix length -> skip (like IPv4Network)
                };
                let addr = match parse_ipv4(addr_s) {
                    Some(a) => a,
                    None => continue,
                };
                let net = addr & mask_for(plen);
                by_len.entry(plen).or_default().insert(net);
                net_count += 1;
            } else if let Some(addr) = parse_ipv4(c) {
                hosts.insert(addr);
            }
        }

        let mut d = self.data.write().unwrap();
        d.hosts = hosts;
        d.by_len = by_len;
        d.net_count = net_count;
    }

    /// True if `ip` is an exact host or falls in any loaded network.
    fn contains(&self, ip: &str) -> bool {
        let addr = match parse_ipv4(ip) {
            Some(a) => a,
            None => return false,
        };
        let d = self.data.read().unwrap();
        if d.hosts.contains(&addr) {
            return true;
        }
        for (plen, set) in d.by_len.iter() {
            if set.contains(&(addr & mask_for(*plen))) {
                return true;
            }
        }
        false
    }

    /// Number of host + network entries loaded (matches the Python reference).
    fn count(&self) -> usize {
        let d = self.data.read().unwrap();
        d.hosts.len() + d.net_count
    }

    fn __repr__(&self) -> String {
        format!("<valkyrie_accel.IpSet count={}>", self.count())
    }
}

#[pymodule]
fn valkyrie_accel(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<IpSet>()?;
    m.add("__doc__", "Optional native accelerators for Valkyrie.")?;
    m.add("__accel__", true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn membership_and_count() {
        let s = IpSet::new();
        s.load(set(&["10.0.0.0/8", "185.220.101.0/24", "203.0.113.5"]));
        assert!(s.contains("10.1.2.3"));
        assert!(s.contains("185.220.101.99"));
        assert!(s.contains("203.0.113.5"));
        assert!(!s.contains("11.0.0.1"));
        assert!(!s.contains("203.0.113.6"));
        assert!(!s.contains("not-an-ip"));
        assert_eq!(s.count(), 3);
    }

    #[test]
    fn host_bits_masked_like_strict_false() {
        let s = IpSet::new();
        s.load(set(&["192.0.2.55/24"])); // host bits set
        assert!(s.contains("192.0.2.0"));
        assert!(s.contains("192.0.2.255"));
        assert!(!s.contains("192.0.3.0"));
    }
}
