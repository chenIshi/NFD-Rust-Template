extern crate pnet;

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/* enum for different NFD primitive type */
enum VarType {
    /* IP: [addr] + [mask] */
    IP(Ipv4Addr, Ipv4Addr),
}

/* express the relationship between [ID] and [Type] with hashmap */
pub type SymbolTable = HashMap<String, VarType>;