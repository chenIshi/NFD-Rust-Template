use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::symbol_table::SymbolTable;

/* Specify field like source IP, source port to look for */
#[derive(PartialEq, Eq, Hash, Clone)]
pub enum PacketField {
    /* Source IP */
    Sip,
    /* Destination IP */
    Dip,
    /* Source port */
    Sport,
    /* Destination port*/
    Dport,
    /* Syn in tcp flag */
    FlagSyn,
    /* Ack in tcp flag */
    FlagAck,
    /* Fin in tcp flag */
    FlagFin,
    IpLen,
}

type FieldMap = HashMap<PacketField, Ipv4Addr>;
type PortMap = HashMap<PacketField, u16>;
type FlagMap = HashMap<PacketField, bool>;
type RuleMap = HashMap<String, (PacketField, Ipv4Addr, Ipv4Addr)>;

/* Extract packet field to a lookup table
    Ipv6 is not available since generic function isn't completed yet */
pub fn extract_packet_info(packet: &EthernetPacket, addr_table:  &mut FieldMap, port_table: &mut PortMap, flag_table: &mut FlagMap) -> bool {
    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_header = Ipv4Packet::new(packet.payload());

            if let Some(ipv4_header) = ipv4_header {
                /* insert source/destination IP to table */
                /* while IP info resides in layer 3 (ex: ipv4/ipv6) */
                addr_table.insert(PacketField::Sip, ipv4_header.get_source());
                addr_table.insert(PacketField::Dip, ipv4_header.get_destination());
                match ipv4_header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_header = TcpPacket::new(ipv4_header.payload());
                        if let Some(tcp_header) = tcp_header {
                            /* now we are in layer 4, which contains port and flag info */
                            port_table.insert(PacketField::Sport, tcp_header.get_source());
                            port_table.insert(PacketField::Dport, tcp_header.get_destination());
                            flag_table.insert(PacketField::FlagAck, (tcp_header.get_flags() & 0b0001_0000) != 0);
                            flag_table.insert(PacketField::FlagSyn, (tcp_header.get_flags() & 0b0000_0010) != 0);
                            flag_table.insert(PacketField::FlagFin, (tcp_header.get_flags() & 0b0000_0001) != 0);
                            return true;
                        }
                    },
                    IpNextHeaderProtocols::Udp => {
                        let udp_header = UdpPacket::new(ipv4_header.payload());
                        if let Some(udp_header) = udp_header {
                            port_table.insert(PacketField::Sport, udp_header.get_source());
                            port_table.insert(PacketField::Dport, udp_header.get_source());
                            /* udp packet doesn't have flags */
                            return true;
                        }
                    },
                    _ => {
                        unimplemented!();
                    }
                }
            }
            /* if execute til here, it means that tcp packet isn't captured */
            return false;
        },
        EtherTypes::Ipv6 => {
            /* TODO: add support for ipv6 */
            unimplemented!();
        },
        _ => return false,
    }
}

/* insert user-defined rule to lookup table */
/* Consume the parse result since it's not used furthermore */
pub fn insert_rule(id: String, field: PacketField, ip: Ipv4Addr, mask: Ipv4Addr, table: &mut RuleMap) {
    let _already_contained_same_key = table.insert(id.to_string(), (field, ip, mask));
    /* I am not sure if we have to prohibit the rule update */
}

pub fn create_set(id: String) {

}