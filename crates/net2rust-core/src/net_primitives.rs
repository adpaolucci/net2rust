use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::NetError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    pub fn parse(input: &str) -> Result<Self, NetError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(NetError::ParseError("empty MAC address".to_string()));
        }

        let bytes = if trimmed.contains(':') {
            parse_delimited_octets(trimmed, ':')?
        } else if trimmed.contains('-') {
            parse_delimited_octets(trimmed, '-')?
        } else if trimmed.contains('.') {
            parse_cisco_mac(trimmed)?
        } else {
            parse_bare_mac(trimmed)?
        };

        Ok(Self(bytes))
    }

    pub fn to_colon_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }

    pub fn to_dash_string(&self) -> String {
        format!(
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }

    pub const fn oui_prefix(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    pub fn oui_hex(&self) -> String {
        format!("{:02X}{:02X}{:02X}", self.0[0], self.0[1], self.0[2])
    }

    pub const fn is_multicast(&self) -> bool {
        (self.0[0] & 0x01) != 0
    }

    pub const fn is_locally_administered(&self) -> bool {
        (self.0[0] & 0x02) != 0
    }

    pub const fn is_broadcast(&self) -> bool {
        matches!(self.0, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }

    pub const fn is_zero(&self) -> bool {
        matches!(self.0, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    }
}

fn parse_hex_byte(pair: &str, original: &str) -> Result<u8, NetError> {
    if pair.len() != 2 || !pair.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NetError::ParseError(format!("invalid MAC address: {original}")));
    }
    u8::from_str_radix(pair, 16).map_err(|_| NetError::ParseError(format!("invalid MAC address: {original}")))
}

fn parse_delimited_octets(input: &str, sep: char) -> Result<[u8; 6], NetError> {
    let parts: Vec<&str> = input.split(sep).collect();
    if parts.len() != 6 {
        return Err(NetError::ParseError(format!("invalid MAC address: {input}")));
    }
    let mut out = [0u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        out[idx] = parse_hex_byte(part, input)?;
    }
    Ok(out)
}

fn parse_cisco_mac(input: &str) -> Result<[u8; 6], NetError> {
    let parts: Vec<&str> = input.split('.').collect();
    if parts.len() != 3 {
        return Err(NetError::ParseError(format!("invalid MAC address: {input}")));
    }
    let mut out = [0u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        if part.len() != 4 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(NetError::ParseError(format!("invalid MAC address: {input}")));
        }
        out[idx * 2] = parse_hex_byte(&part[0..2], input)?;
        out[idx * 2 + 1] = parse_hex_byte(&part[2..4], input)?;
    }
    Ok(out)
}

fn parse_bare_mac(input: &str) -> Result<[u8; 6], NetError> {
    if input.len() != 12 || !input.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NetError::ParseError(format!("invalid MAC address: {input}")));
    }
    let mut out = [0u8; 6];
    for idx in 0..6 {
        out[idx] = parse_hex_byte(&input[idx * 2..idx * 2 + 2], input)?;
    }
    Ok(out)
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_colon_string())
    }
}

impl FromStr for MacAddr {
    type Err = NetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_colon_string())
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CidrV4 {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl CidrV4 {
    pub fn new(ip: Ipv4Addr, prefix_len: u8) -> Result<Self, NetError> {
        if prefix_len > 32 {
            return Err(NetError::InvalidInput(format!(
                "IPv4 CIDR prefix length {prefix_len} exceeds 32"
            )));
        }
        let mask = ipv4_mask_u32(prefix_len);
        let net = Ipv4Addr::from(u32::from(ip) & mask);
        Ok(Self {
            network: net,
            prefix_len,
        })
    }

    pub fn parse(input: &str) -> Result<Self, NetError> {
        let trimmed = input.trim();
        let (ip_str, prefix_str) = trimmed
            .split_once('/')
            .ok_or_else(|| NetError::ParseError(format!("invalid IPv4 CIDR (missing '/'): {trimmed}")))?;
        let ip: Ipv4Addr = ip_str
            .parse()
            .map_err(|_| NetError::ParseError(format!("invalid IPv4 address in CIDR: {trimmed}")))?;
        if prefix_str.is_empty() || !prefix_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(NetError::ParseError(format!("invalid IPv4 prefix length: {trimmed}")));
        }
        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|_| NetError::ParseError(format!("invalid IPv4 prefix length: {trimmed}")))?;
        Self::new(ip, prefix_len)
    }

    pub const fn network(&self) -> Ipv4Addr {
        self.network
    }

    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(ipv4_mask_u32(self.prefix_len))
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        let mask = ipv4_mask_u32(self.prefix_len);
        let net = u32::from(self.network);
        Ipv4Addr::from(net | !mask)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = ipv4_mask_u32(self.prefix_len);
        (u32::from(ip) & mask) == u32::from(self.network)
    }

    pub const fn host_count(&self) -> u64 {
        1u64 << (32 - self.prefix_len)
    }
}

const fn ipv4_mask_u32(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

impl fmt::Display for CidrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for CidrV4 {
    type Err = NetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for CidrV4 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CidrV4 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CidrV6 {
    network: Ipv6Addr,
    prefix_len: u8,
}

impl CidrV6 {
    pub fn new(ip: Ipv6Addr, prefix_len: u8) -> Result<Self, NetError> {
        if prefix_len > 128 {
            return Err(NetError::InvalidInput(format!(
                "IPv6 CIDR prefix length {prefix_len} exceeds 128"
            )));
        }
        let mask = ipv6_mask_u128(prefix_len);
        let net = Ipv6Addr::from(u128::from(ip) & mask);
        Ok(Self {
            network: net,
            prefix_len,
        })
    }

    pub fn parse(input: &str) -> Result<Self, NetError> {
        let trimmed = input.trim();
        let (ip_str, prefix_str) = trimmed
            .split_once('/')
            .ok_or_else(|| NetError::ParseError(format!("invalid IPv6 CIDR (missing '/'): {trimmed}")))?;
        let ip: Ipv6Addr = ip_str
            .parse()
            .map_err(|_| NetError::ParseError(format!("invalid IPv6 address in CIDR: {trimmed}")))?;
        if prefix_str.is_empty() || !prefix_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(NetError::ParseError(format!("invalid IPv6 prefix length: {trimmed}")));
        }
        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|_| NetError::ParseError(format!("invalid IPv6 prefix length: {trimmed}")))?;
        Self::new(ip, prefix_len)
    }

    pub const fn network(&self) -> Ipv6Addr {
        self.network
    }

    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn netmask(&self) -> Ipv6Addr {
        Ipv6Addr::from(ipv6_mask_u128(self.prefix_len))
    }

    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        let mask = ipv6_mask_u128(self.prefix_len);
        (u128::from(ip) & mask) == u128::from(self.network)
    }
}

const fn ipv6_mask_u128(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

impl fmt::Display for CidrV6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for CidrV6 {
    type Err = NetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for CidrV6 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CidrV6 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}
