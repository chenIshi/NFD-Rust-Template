extern crate pnet;

use std::collections::{HashMap, BTreeMap};
use std::collections::{HashSet, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use super::obj::{PacketMap, Variable};

/* express the relationship between [ID] and [Type] with hashmap */
pub type SymbolTable = HashMap<String, Variable>;

/*TODO: it should be a impl method for SymbolTable */
pub fn insert_symbol(table: &mut SymbolTable, id: String, content: Variable) {
    table.insert(id, content);
}

/* change symbol's value is exactly the opposite logic to init
    we declined any value change to un-init variable */
pub fn change_symbol(table: &mut SymbolTable, id: String, update_data: Variable) -> bool {
    if table.contains_key(&id) {
        if *table.get(&id).unwrap() == update_data {
            table.insert(id, update_data);
            return true;
        }
    }
    /* both (1) un-init variable and (2) assign wrong type value are illegal */
    return false;
}

/* launch user-defined mapping relationship and store it in symbol table */
pub fn launch_mapping(id: String, key: Variable, value: Variable, table: &mut SymbolTable) {
    let mut mapping = BTreeMap::new();
    mapping.insert(Box::new(key), Box::new(value));
    let lookup = Variable::Map(mapping);
    insert_symbol(table, id, lookup);
}