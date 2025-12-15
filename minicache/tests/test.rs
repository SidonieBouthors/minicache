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
const OPCODE_GET: u8 = 0x00;
const KEY: &[u8] = b"foo";

// --- Packet Lengths ---
const PREAMBLE_LEN: usize = UDP_PREAMBLE_LEN;
const HEADER_LEN: usize = REQUEST_HEADER_LEN;
const KEY_LEN: usize = KEY.len();
const TOTAL_PACKET_LEN: usize = PREAMBLE_LEN + HEADER_LEN + KEY_LEN;

/// Helper function to create the Option struct for the test listener
fn get_test_opt() -> Opt {
    Opt {
        iface: MEMCACHED_IFACE.to_string(),
        port: TEST_PORT,
    }
}

#[tokio::test]
async fn test_full_udp_cycle() -> anyhow::Result<()> {
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
        .set_read_timeout(Some(Duration::from_secs(10)))
        .context("Failed to set read timeout")?;

    let mut packet: Vec<u8> = Vec::with_capacity(TOTAL_PACKET_LEN);

    // Preamble (8 bytes)
    packet.write_u16::<BigEndian>(0x0001).unwrap(); // Request ID
    packet.write_u16::<BigEndian>(0).unwrap(); // Seq No
    packet.write_u16::<BigEndian>(1).unwrap(); // Total Dgrams
    packet.write_u16::<BigEndian>(0).unwrap(); // Reserved

    // Header (24 bytes)
    packet.push(MAGIC_REQUEST);
    packet.push(OPCODE_GET);
    packet.write_u16::<BigEndian>(KEY_LEN as u16).unwrap(); // Key Length = 3
    packet.push(0x00);
    packet.push(0x00);
    packet.write_u16::<BigEndian>(0).unwrap(); // VBucket ID
    packet.write_u32::<BigEndian>(KEY_LEN as u32).unwrap(); // Body Length = 3
    packet.write_u32::<BigEndian>(0).unwrap(); // Opaque
    packet.write_u64::<BigEndian>(0).unwrap(); // CAS 

    // Key Body
    packet.extend_from_slice(KEY);

    println!(
        "[Test] Injecting {} byte packet to {}",
        packet.len(),
        target_addr
    );
    let bytes_sent = sender_socket
        .send_to(&packet, &target_addr)
        .context("Failed to send UDP packet")?;

    assert_eq!(
        bytes_sent, TOTAL_PACKET_LEN,
        "Did not send the full packet size"
    );

    let mut received_buffer = [0u8; 1024];
    let (bytes_received, src_addr) = sender_socket
        .recv_from(&mut received_buffer)
        .context("Failed to receive echoed UDP packet. Is the server running and configured to echo?")?;

    println!(
        "[Test] Received {} byte echo from {}",
        bytes_received,
        src_addr
    );

    // The source address of the response should be the server's address
    assert_eq!(
        src_addr.to_string(), target_addr,
        "The response came from an unexpected address"
    );

    // The size of the received packet must match the size of the sent packet
    assert_eq!(
        bytes_received, TOTAL_PACKET_LEN,
        "Received packet size does not match sent packet size"
    );
    
    // Crucial: The received bytes must be identical to the sent bytes (the echo)
    let received_packet = &received_buffer[..bytes_received];
    assert_eq!(
        received_packet, packet,
        "The received packet is not an exact echo of the sent packet."
    );
    
    Ok(())
}