extern crate ipnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use ipnet::{Ipv4Net};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::collections::{BTreeMap, BTreeSet};

use ipnet::IpBitAnd;

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
                table.insert(PacketField::Sip, PacketInfo::IP(Some(ipv4_header.get_source())));
                table.insert(PacketField::Dip, PacketInfo::IP(Some(ipv4_header.get_destination())));
                match ipv4_header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_header = TcpPacket::new(ipv4_header.payload());
                        if let Some(tcp_header) = tcp_header {
                            /* now we are in layer 4, which contains port and flag info */
                            table.insert(PacketField::Sport, PacketInfo::Port(Some(tcp_header.get_source() as u32)));
                            table.insert(PacketField::Dport, PacketInfo::Port(Some(tcp_header.get_destination() as u32)));
                            table.insert(PacketField::FlagTcp, PacketInfo::Flag(true));
                            table.insert(PacketField::FlagUdp, PacketInfo::Flag(false));
                            table.insert(PacketField::FlagAck, PacketInfo::Flag((tcp_header.get_flags() & 0b0001_0000) != 0));
                            table.insert(PacketField::FlagSyn, PacketInfo::Flag((tcp_header.get_flags() & 0b0000_0010) != 0));
                            table.insert(PacketField::FlagFin, PacketInfo::Flag((tcp_header.get_flags() & 0b0000_0001) != 0));
                            return true;
                        }
                    },
                    IpNextHeaderProtocols::Udp => {
                        let udp_header = UdpPacket::new(ipv4_header.payload());
                        if let Some(udp_header) = udp_header {
                            table.insert(PacketField::Sport, PacketInfo::Port(Some(udp_header.get_source() as u32)));
                            table.insert(PacketField::Dport, PacketInfo::Port(Some(udp_header.get_source() as u32)));
                            table.insert(PacketField::FlagTcp, PacketInfo::Flag(false));
                            table.insert(PacketField::FlagUdp, PacketInfo::Flag(true));
                            /* UDP packets have no tcp flags */
                            table.insert(PacketField::FlagAck, PacketInfo::Flag(false));
                            table.insert(PacketField::FlagSyn, PacketInfo::Flag(false));
                            table.insert(PacketField::FlagFin, PacketInfo::Flag(false));
                            /* udp packet doesn't have flags */
                            return true;
                        }
                    },
                    _ => {
                        table.insert(PacketField::Sport, PacketInfo::Port(None));
                        table.insert(PacketField::Dport, PacketInfo::Port(None));
                        table.insert(PacketField::FlagTcp, PacketInfo::Flag(false));
                        table.insert(PacketField::FlagUdp, PacketInfo::Flag(false));
                        table.insert(PacketField::FlagAck, PacketInfo::Flag(false));
                        table.insert(PacketField::FlagFin, PacketInfo::Flag(false));
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
