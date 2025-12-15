use anyhow::Context;
use byteorder::{BigEndian, WriteBytesExt};
use std::net::UdpSocket;
use std::time::Duration;

// --- Test Constants ---
const TEST_PORT: u32 = 11211;

// --- Memcached Binary Constants ---
const MAGIC_REQUEST: u8 = 0x80;
const OPCODE_GET: u8 = 0x00;
const KEY: [u8; 64] = {
    let mut array = [0; 64];
    array[0] = b'f';
    array[1] = b'o';
    array[2] = b'o';
    array
};

// --- Packet Lengths ---
const PREAMBLE_LEN: usize = 8;
const HEADER_LEN: usize = 24;
const KEY_LEN: usize = KEY.len();
const TOTAL_PACKET_LEN: usize = PREAMBLE_LEN + HEADER_LEN + KEY_LEN;

fn main() -> anyhow::Result<()> {
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
    packet.push(OPCODE_GET);
    packet.write_u32::<BigEndian>(0).unwrap();

    // Body (Key)
    packet.extend_from_slice(&KEY);

    println!(
        "[Test] Injecting {} byte packet to {}",
        packet.len(),
        target_addr
    );
    let _bytes_sent = sender_socket
        .send_to(&packet, &target_addr)
        .context("Failed to send UDP packet")?;

    // Attempt to receive server response (not functional)

    let mut received_buffer = [0u8; 1024];
    let (bytes_received, src_addr) = sender_socket
        .recv_from(&mut received_buffer)
        .context("Failed to receive server response")?;

    Ok(())
}
