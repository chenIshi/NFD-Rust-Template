use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::symbol_table::{SymbolTable, insert_symbol};
use super::obj::{PacketMap, RuleMap, PacketField, PacketInfo, Variable};

pub fn init_table(packet_map: PacketMap) -> SymbolTable {
    let mut table = SymbolTable::new();

    insert_symbol(&mut table, "f".to_owned(), Variable::Packet(packet_map));
    table
}

/* Extract packet field to a lookup table
    Ipv6 is not available since generic function isn't completed yet */
pub fn extract_packet_info(packet: &EthernetPacket, table: &mut PacketMap) -> bool {
    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_header = Ipv4Packet::new(packet.payload());

            if let Some(ipv4_header) = ipv4_header {
                /* insert source/destination IP to table */
                /* while IP info resides in layer 3 (ex: ipv4/ipv6) */
                table.insert(PacketField::Sip, PacketInfo::IP(ipv4_header.get_source()));
                table.insert(PacketField::Dip, PacketInfo::IP(ipv4_header.get_destination()));
                match ipv4_header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_header = TcpPacket::new(ipv4_header.payload());
                        if let Some(tcp_header) = tcp_header {
                            /* now we are in layer 4, which contains port and flag info */
                            table.insert(PacketField::Sport, PacketInfo::Port(tcp_header.get_source() as u32));
                            table.insert(PacketField::Dport, PacketInfo::Port(tcp_header.get_destination() as u32));
                            table.insert(PacketField::FlagAck, PacketInfo::Flag((tcp_header.get_flags() & 0b0001_0000) != 0));
                            table.insert(PacketField::FlagSyn, PacketInfo::Flag((tcp_header.get_flags() & 0b0000_0010) != 0));
                            table.insert(PacketField::FlagFin, PacketInfo::Flag((tcp_header.get_flags() & 0b0000_0001) != 0));
                            return true;
                        }
                    },
                    IpNextHeaderProtocols::Udp => {
                        let udp_header = UdpPacket::new(ipv4_header.payload());
                        if let Some(udp_header) = udp_header {
                            table.insert(PacketField::Sport, PacketInfo::Port(udp_header.get_source() as u32));
                            table.insert(PacketField::Dport, PacketInfo::Port(udp_header.get_source() as u32));
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