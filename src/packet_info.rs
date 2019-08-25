extern crate pnet;

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

/* Specify field like source IP, source port to look for */
#[derive(PartialEq, Eq, Hash)]
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

/* Extract packet field to a lookup table
    Ipv6 is not available since generic function isn't completed yet */
pub fn extract_packet_info(packet: &EthernetPacket, addr_table:  &mut HashMap<PacketField, Ipv4Addr>,port_table: &mut HashMap<PacketField, u16>, flag_table: &mut HashMap<PacketField, u32>) -> bool {
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
                            flag_table.insert(PacketField::FlagAck, (tcp_header.get_flags() & 0b0001_0000) as u32);
                            flag_table.insert(PacketField::FlagSyn, (tcp_header.get_flags() & 0b0000_0010) as u32);
                            flag_table.insert(PacketField::FlagFin, (tcp_header.get_flags() & 0b0000_0001) as u32);
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