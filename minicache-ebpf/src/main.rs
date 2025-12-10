#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use minicache_common::{
    cache::{EbpfKey, EbpfValue},
    protocol::{
        MAGIC_REQUEST, OPCODE_GET, REQUEST_HEADER_LEN, RequestHeader, UDP_PREAMBLE_LEN, UdpPreamble,
    },
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

static MAX_ENTRIES: u32 = 1024 * 1024;

#[map]
static CACHE_MAP: HashMap<EbpfKey, EbpfValue> = HashMap::with_max_entries(
    MAX_ENTRIES,
    0, // flags
);

#[map]
static CONFIG_PORT: Array<u32> = Array::with_max_entries(
    1, // single port value
    0, // flags
);

#[xdp]
pub fn minicache(ctx: XdpContext) -> u32 {
    match try_minicache(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_minicache(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS), // Ignore non-IPv4 packets
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let ipv4_header_len = (unsafe { (*ipv4hdr).ihl() } as usize);
    let transport_header_offset = EthHdr::LEN + ipv4_header_len;

    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });

    // Ignore non-UDP packets
    let IpProto::Udp = (unsafe { (*ipv4hdr).proto }) else {
        return Ok(xdp_action::XDP_PASS);
    };

    let udphdr: *const UdpHdr = ptr_at(&ctx, transport_header_offset)?;
    let udp_header_len = UdpHdr::LEN;

    let payload_offset = transport_header_offset + udp_header_len;
    let source_port = unsafe { (*udphdr).src_port() };
    let dest_port = unsafe { (*udphdr).dst_port() };

    let map_port_ref = CONFIG_PORT.get(0);
    let memcached_port: u16 = match map_port_ref {
        Some(port_value) => (*port_value) as u16,
        None => 11211,
    };

    if dest_port != memcached_port {
        return Ok(xdp_action::XDP_PASS); // Ignore packets not destined for memcached port
    }

    let payload_len = ctx.data_end() - (ctx.data() + payload_offset);
    if payload_len < UDP_PREAMBLE_LEN + REQUEST_HEADER_LEN {
        info!(
            &ctx,
            "XDP: Packet too short for memcached header: {} bytes", payload_len
        );
        return Ok(xdp_action::XDP_PASS); // Ignore packets that are too short to contain memcached header
    }

    let udp_header: *const UdpPreamble = ptr_at(&ctx, payload_offset)?;
    let request_offset = payload_offset + UDP_PREAMBLE_LEN;
    let req_hdr: *const RequestHeader = ptr_at(&ctx, request_offset)?;

    let is_binary_request = unsafe { (*req_hdr).magic == MAGIC_REQUEST };
    let is_get_command = unsafe { (*req_hdr).opcode == OPCODE_GET };

    info!(
        &ctx,
        "XDP: Packet from {}:{} to {}:{} - Payload Length: {} bytes",
        source_addr,
        source_port,
        dest_addr,
        dest_port,
        payload_len
    );

    // Log all the request header fields
    info!(
        &ctx,
        "XDP: Memcached Request Header - Magic: {}, Opcode: {}, Key Length: {}, Extras Length: {}, Data Type: {}, VBucket ID: {}, Total Body Length: {}, Opaque: {}, CAS: {}",
        unsafe { (*req_hdr).magic },
        unsafe { (*req_hdr).opcode },
        unsafe { (*req_hdr).key_length() },
        unsafe { (*req_hdr).extras_length },
        unsafe { (*req_hdr).data_type },
        unsafe { (*req_hdr).vbucket_id() },
        unsafe { (*req_hdr).body_length() },
        unsafe { (*req_hdr).opaque },
        unsafe { (*req_hdr).cas },
    );

    if is_binary_request && is_get_command {
        info!(
            &ctx,
            "XDP: Detected Binary TCP GET (Opcode: {}) on port {}", OPCODE_GET, dest_port
        );
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
