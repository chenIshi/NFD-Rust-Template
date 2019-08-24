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

use std::env;

/* Specify field like source IP, source port to look for */
#[derive(PartialEq, Eq, Hash)]
enum PacketField {
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

fn main() {
    /* Setup the default basic environment */
    /* take the second argument as the forwarding node */
    let host_interface_name = env::args().nth(1).unwrap();
    let host_interface_match = | iface: &NetworkInterface | iface.name == host_interface_name;

    let host_interface = datalink::interfaces().into_iter()
                                            .filter(host_interface_match)
                                            .next()
                                            .unwrap();

    /* take the third argument as the receiving node */
    let client_interface_name = env::args().nth(2).unwrap();
    let client_interface_match = | iface: &NetworkInterface | iface.name == client_interface_name;

    let client_interface = datalink::interfaces().into_iter()
                                                .filter(client_interface_match)
                                                .next()
                                                .unwrap();

    let (mut tx, mut rx) = match datalink::channel(&host_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethpacket = EthernetPacket::new(packet).unwrap();

                /* init packet info lookup table */

                let mut addr_table = HashMap::new();
                let mut port_table = HashMap::new();
                let mut flag_table = HashMap::new();
                let init_success = extract_packet_info(& ethpacket, &mut addr_table, &mut port_table, &mut flag_table);
                if !init_success {
                    println!("Not a supported packet type, Skip!");
                    continue;
                }
            },
            Err(e) => {
                /* If an error occurs, we can handle it here */
                panic!("An error occurred while reading: {}", e);
            }
        }
    }

}

/* Extract packet field to a lookup table
    Ipv6 is not available since generic function isn't completed yet */
fn extract_packet_info(packet: &EthernetPacket, addr_table:  &mut HashMap<PacketField, Ipv4Addr>,port_table: &mut HashMap<PacketField, u16>, flag_table: &mut HashMap<PacketField, u32>) -> bool {
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
