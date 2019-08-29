extern crate pnet;
extern crate ipnet;

use std::collections::{HashMap, BTreeMap};
use std::collections::{HashSet, BTreeSet};
use std::collections::btree_set::Union;
use std::net::{Ipv4Addr, Ipv6Addr};
use ipnet::{Ipv4Net};
use super::obj::{PacketMap, Variable, PacketField, RuleMap};

/* express the relationship between [ID] and [Type] with hashmap */
pub type SymbolTable = HashMap<String, Variable>;

pub fn init_table(packet_table: PacketMap) -> SymbolTable {
    let mut table = SymbolTable::new();
    insert_symbol(&mut table, "f".to_owned(), Variable::Packet(packet_table));
    table
}

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

pub fn insert_mapping(id: String, key: Variable, val: Variable, table: &mut SymbolTable) {
    let map = table.get_mut(&id).unwrap();
    match map {
        Variable::Map(m) => { m.insert(Box::new(key), Box::new(val)); },
         _ => { panic!("Error :: Duplicated ID name with other different type variable"); },
    }
}

/* set-related function */

pub fn create_set(id: String, var_type: Variable, table: &mut SymbolTable) {
    let mut set = BTreeSet::new();
    set.insert(Box::new(var_type));
    table.insert(id, Variable::Set(set));
}

pub fn insert_set(set_name: String, val: Variable, table: &mut SymbolTable) {
    let set = table.get_mut(&set_name).unwrap();
    match set {
        Variable::Set(bt_set) => { bt_set.insert(Box::new(val)); },
        _ => { panic!("Error :: Duplicated ID name with other different type variable"); },
    }
}

pub fn set_union<'a>(first: &'a Variable, second: &'a Variable) -> Union<'a, Box<Variable>> {
    match (first, second) {
        (Variable::Set(f), Variable::Set(s)) => {
            f.union(s)
        } ,
        _ => {
            panic!("Error :: Uncaptable item of union operator");
        },
    }
}