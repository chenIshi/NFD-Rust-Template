extern crate ipnet;

use std::collections::{HashMap, BTreeMap};
use std::collections::{BTreeSet};
use std::mem::discriminant;
use std::net::{Ipv4Addr, Ipv6Addr};
use ipnet::{Ipv4Net};

pub type PacketMap = BTreeMap<PacketField, PacketInfo>;

pub type RuleMap = BTreeMap<String, (PacketField, Ipv4Net)>;

/* express the relationship between [ID] and [Type] with hashmap */
pub type SymbolTable = HashMap<String, Variable>;

/* Specify field like source IP, source port to look for */
#[derive(PartialEq, Eq, Hash, Clone, Ord, PartialOrd)]
pub enum PacketField {
    /* Source IP */
    Sip,
    /* Destination IP */
    Dip,
    /* Source port */
    Sport,
    /* Destination port*/
    Dport,
    FlagTcp,
    FlagUdp,
    /* Syn in tcp flag */
    FlagSyn,
    /* Ack in tcp flag */
    FlagAck,
    /* Fin in tcp flag */
    FlagFin,
    IpLen,
}

/* C union like enum structure  */
#[derive(Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum PacketInfo {
    IP(Option<Ipv4Addr>),
    Port(Option<u32>),
    Flag(bool),
}

/* enum for different NFD primitive type */
/* recursive enum require Box to get actual mem consumption */
/* use Option to be able to express NULL when init without val binding */
#[derive(Hash, Eq, Ord, PartialOrd)]
pub enum Variable {
    /* init with IP(None, None) */
    IP(Option<Ipv4Net>),
    /* init with Int(None) */
    Int(Option<i32>),
    /* init with Rule(None) */
    Rule(Option<(PacketField, Ipv4Net)>),
    Map(BTreeMap<Box<Variable>, Box<Variable>>),
    Set(BTreeSet<Box<Variable>>),
    Packet(PacketMap),
}

/* we only want to compare the type of the variable instead of its value */
/* the mem::discriminant only support after rust 1.21 */
impl PartialEq for Variable {
    fn eq(&self, other: &Self) -> bool {
        discriminant(self) == discriminant(other)
    }
}