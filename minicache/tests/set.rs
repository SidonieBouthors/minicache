use anyhow::Context;
use byteorder::{BigEndian, WriteBytesExt};
use std::net::UdpSocket;
use std::time::Duration;

use minicache::server::{Opt, run};
use minicache_common::protocol::{REQUEST_HEADER_LEN, UDP_PREAMBLE_LEN};

// --- Test Constants ---
const TEST_PORT: u32 = 18112;
const MEMCACHED_IFACE: &str = "lo";

// --- Memcached Binary Constants ---
const MAGIC_REQUEST: u8 = 0x80;
const OPCODE_SET: u8 = 0x01;
const KEY: [u8; 64] = {
    let mut array = [0; 64];
    array[0] = b'f';
    array[1] = b'o';
    array[2] = b'o';
    array
};
const VALUE: [u8; 64] = {
    let mut array = [0; 64];
    array[0] = b'b';
    array[1] = b'a';
    array[2] = b'r';
    array
};

// --- Packet Lengths ---
const PREAMBLE_LEN: usize = UDP_PREAMBLE_LEN;
const HEADER_LEN: usize = REQUEST_HEADER_LEN;
const KEY_LEN: usize = KEY.len();
const TOTAL_PACKET_LEN: usize = PREAMBLE_LEN + HEADER_LEN + KEY_LEN;

fn get_test_opt() -> Opt {
    Opt {
        iface: MEMCACHED_IFACE.to_string(),
        port: TEST_PORT,
    }
}

#[tokio::test]
async fn test_get() -> anyhow::Result<()> {
    let opt = get_test_opt();
    let _server_handle = tokio::spawn(run(opt));

    // let _server_handle = tokio::task::spawn_blocking(move || {
    //     let rt = tokio::runtime::Builder::new_current_thread()
    //         .enable_all()
    //         .build()
    //         .unwrap();

    //     rt.block_on(run(opt))
    // });

    tokio::time::sleep(Duration::from_millis(2000)).await;

    let target_addr = format!("127.0.0.1:{}", TEST_PORT);
    let sender_socket = UdpSocket::bind("127.0.0.1:0").context("Failed to bind sender socket")?;
    sender_socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("Failed to set read timeout")?;

    let mut packet: Vec<u8> = Vec::with_capacity(TOTAL_PACKET_LEN);

    // Preamble
    packet.write_u16::<BigEndian>(0x0001).unwrap(); // Request ID
    packet.write_u16::<BigEndian>(0).unwrap(); // Seq No
    packet.write_u16::<BigEndian>(1).unwrap(); // Total Dgrams
    packet.write_u16::<BigEndian>(0).unwrap(); // Reserved

    // Header
    packet.push(MAGIC_REQUEST);
    packet.push(OPCODE_SET);
    packet.write_u32::<BigEndian>(0).unwrap(); 

    // Body (Key + Value)
    packet.extend_from_slice(&KEY);
    packet.extend_from_slice(&VALUE);

    println!(
        "[Test] Injecting {} byte packet to {}",
        packet.len(),
        target_addr
    );
    let _bytes_sent = sender_socket
        .send_to(&packet, &target_addr)
        .context("Failed to send UDP packet")?;

    // Attempt to receive server response (not functional)

    // let mut received_buffer = [0u8; 1024];
    // let (bytes_received, src_addr) = sender_socket
    //     .recv_from(&mut received_buffer)
    //     .context("Failed to receive server response")?;
    
    Ok(())
}