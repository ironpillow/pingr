/*
This file is part of pingr.

Pingr is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Pingr is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Pingr.  If not, see <http://www.gnu.org/licenses/>.
*/

#![feature(ip_addr)]
extern crate time;
extern crate pnet;

mod icmp;

use std::thread;
use std::sync::{Arc, Mutex};
use std::net::Ipv4Addr;
use std::net::IpAddr::V4;
use pnet::transport::TransportChannelType::Layer3;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use std::str::FromStr;
use std::collections::HashMap;
use icmp::Icmp;

struct Ping {
    pub addr: String,
    pub time_sent: time::Tm,
    pub time_received: time::Tm,
}


fn process_packet(p: &Ipv4Packet, pings: &Arc<Mutex<HashMap<String, Ping>>>) {
    let mut pings = pings.lock().unwrap();

    let ip: String = format!("{}", p.get_source());
    let start = pings.get(&ip).unwrap().time_sent;
    let end = time::now();
    pings.get_mut(&ip).unwrap().time_received = end;

    let t = p.get_icmp_type();
    match t {
        0 => println!("{} bytes from {:<15} : icmp_seq={} ttl={} time={} ms",
                      p.get_total_length(), ip, p.get_icmp_sequence(),
                      p.get_ttl(), (end - start).num_milliseconds()),
        8 => {println!("ignore - request packet")},
        _ => println!("unexpected packet. type={}", t),

    }
}

fn exit_now(pings: &Arc<Mutex<HashMap<String, Ping>>>) -> bool {

    let t = time::now();

    let pings = pings.lock().unwrap();

    for (_, ping) in pings.iter() {
        if ping.time_received == time::empty_tm() && (t - ping.time_sent).num_milliseconds() < 1000 {
            return false;
        }
    }

    // handle timeouts
    for (ip, ping) in pings.iter() {
        if ping.time_received == time::empty_tm() {
            println!("00 bytes from {:<15} : * timeout *", ip);
        }
    }

    true
}

fn main() {
    let mut args = std::env::args();
    if args.len() < 2 {
        println!("usage: rp <ip> ...");
        return;
    }

    args.next();
    let mut ips: Vec<String> = Vec::new();
    for x in args {
        ips.push(x);
    }

    let protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (mut tx, mut rx) = match pnet::transport::transport_channel(1024, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("An error occurred when creating the transport channel: {}", e),
    };

    // track pings
    let pings: Arc<Mutex<HashMap<String, Ping>>> = Arc::new(Mutex::new(HashMap::new()));

    // set up listener
    let pings_copy = pings.clone();
    thread::spawn(move || {
        let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);
        loop {
            match iter.next() {
                Ok((p, _)) => process_packet(&p, &pings_copy),
                Err(e) => panic!("error: {}", e),
            }
        }
    });

    for ip in ips {

        let ping = Ping { addr: ip.to_string(), time_sent: time::now(), time_received: time::empty_tm() };
        {
            let mut pings = pings.lock().unwrap();
            pings.insert(ip.to_string(), ping);
        }

        let addr_v4 = Ipv4Addr::from_str(&ip).unwrap();
        let mut vec: Vec<u8> = vec![0; 64];
        let packet = icmp::packet(&mut vec, addr_v4, 0, 1);
        let l = packet.get_total_length();

        // send ping
        match tx.send_to(packet, V4(addr_v4)) {
            Ok(n) => assert_eq!(n, l as usize),
            Err(e) => panic!("failed to send packet: {}", e)
        };
    }

    // wait
    loop {
        thread::sleep_ms(1);

        if exit_now(&pings) {
            break;
        }
    }
}
