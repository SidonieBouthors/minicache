#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap, PerCpuArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use minicache_common::{
    cache::{CacheKey, CacheValue},
    protocol::{
        MAGIC_REQUEST, OPCODE_GET, OPCODE_SET, REQUEST_HEADER_LEN, RequestHeader, UDP_PREAMBLE_LEN,
        UdpPreamble,
    },
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

static MAX_ENTRIES: u32 = 1024 * 1024;

#[map]
static CACHE_MAP: HashMap<CacheKey, CacheValue> = HashMap::with_max_entries(
    MAX_ENTRIES,
    0, // flags
);

#[map]
static CONFIG_PORT: Array<u32> = Array::with_max_entries(
    1, // single port value
    0, // flags
);

#[map]
static KEY_BUF: PerCpuArray<CacheKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static VALUE_BUF: PerCpuArray<CacheValue> = PerCpuArray::with_max_entries(1, 0);

#[xdp]
pub fn minicache(ctx: XdpContext) -> u32 {
    match try_minicache(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_minicache(mut ctx: XdpContext) -> Result<u32, ()> {
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

    let _udp_header: *const UdpPreamble = ptr_at(&ctx, payload_offset)?;
    let request_offset = payload_offset + UDP_PREAMBLE_LEN;
    let req_hdr: *const RequestHeader = ptr_at(&ctx, request_offset)?;

    let is_binary_request = unsafe { (*req_hdr).magic == MAGIC_REQUEST };

    info!(
        &ctx,
        "XDP: Packet from {}:{} to {}:{} - Payload Length: {} bytes",
        source_addr,
        source_port,
        dest_addr,
        dest_port,
        payload_len
    );

    // info!(
    //     &ctx,
    //     "XDP: Memcached Request Header - Magic: {}, Opcode: {}, Key Length: {}, Extras Length: {}, Data Type: {}, VBucket ID: {}, Total Body Length: {}, Opaque: {}, CAS: {}",
    //     unsafe { (*req_hdr).magic },
    //     unsafe { (*req_hdr).opcode },
    //     unsafe { (*req_hdr).key_length() },
    //     unsafe { (*req_hdr).extras_length },
    //     unsafe { (*req_hdr).data_type },
    //     unsafe { (*req_hdr).vbucket_id() },
    //     unsafe { (*req_hdr).body_length() },
    //     unsafe { (*req_hdr).opaque },
    //     unsafe { (*req_hdr).cas },
    // );

    if !is_binary_request {
        return Ok(xdp_action::XDP_PASS);
    }

    // Perform cache operations
    let opcode = unsafe { (*req_hdr).opcode };

    if opcode == OPCODE_GET {
        return handle_get_command(&mut ctx, request_offset);
    } else if opcode == OPCODE_SET {
        return handle_set_command(&ctx, request_offset);
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn handle_get_command(ctx: &mut XdpContext, request_offset: usize) -> Result<u32, ()> {
    let key_offset = request_offset + REQUEST_HEADER_LEN;
    let mut ebpf_key = CacheKey::default();
    let key_length = ebpf_key.data.len();

    let data_ptr = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    let key_ptr = unsafe { data_ptr.add(key_offset) };

    if unsafe { key_ptr.add(key_length) } > data_end {
        info!(&ctx, "GET: Key pointer out of bounds");
        return Ok(xdp_action::XDP_PASS);
    }
    unsafe { core::ptr::copy_nonoverlapping(key_ptr, ebpf_key.data.as_mut_ptr(), key_length) };

    // read first byte
    info!(&ctx, "GET: Looking up key: {}", ebpf_key.data[0]);

    if let Some(value) = unsafe { CACHE_MAP.get(ebpf_key) } {
        info!(&ctx, "GET: Cache hit - value {}", value.data[0]);
        rewrite_headers(ctx)?;
        Ok(xdp_action::XDP_TX)
    } else {
        info!(&ctx, "GET: Cache miss.");
        rewrite_headers(ctx)?;
        Ok(xdp_action::XDP_TX)
    }
}

#[inline(always)]
fn handle_set_command(ctx: &XdpContext, request_offset: usize) -> Result<u32, ()> {
    let key_offset = request_offset + REQUEST_HEADER_LEN;
    let ebpf_key = CacheKey::default();
    let ebpf_data = CacheValue::default();
    let key_length = ebpf_key.data.len();
    let value_length = ebpf_data.data.len();

    let key_offset = key_offset + REQUEST_HEADER_LEN;
    let value_offset = key_offset + key_length;

    let mut ebpf_key = CacheKey::default();
    let mut ebpf_value = CacheValue::default();

    if key_length == 0 || key_length > ebpf_key.data.len() || value_length > ebpf_value.data.len() {
        info!(&ctx, "SET: Data size out of bounds or zero key");
        return Ok(xdp_action::XDP_PASS);
    }

    let data_ptr = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    let key_ptr = unsafe { data_ptr.add(key_offset) };
    let value_ptr = unsafe { data_ptr.add(value_offset) };

    if unsafe { key_ptr.add(key_length.min(1).max(ebpf_key.data.len())) } >= data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    unsafe { core::ptr::copy_nonoverlapping(key_ptr, ebpf_key.data.as_mut_ptr(), key_length) };

    if unsafe { value_ptr.add(value_length.min(1).max(ebpf_value.data.len())) } >= data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(value_ptr, ebpf_value.data.as_mut_ptr(), value_length)
    };
    ebpf_value.len = value_length as u16;

    // update
    match CACHE_MAP.insert(ebpf_key, ebpf_value, 0) {
        Ok(_) => {
            info!(&ctx, "SET: Cache SET successful.");
            // Send back some acknowledgment ?
            Ok(xdp_action::XDP_PASS)
        }
        Err(_) => {
            info!(&ctx, "SET: Cache SET failed.");
            // Send back some error
            Ok(xdp_action::XDP_PASS)
        }
    }
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

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[inline(always)]
fn rewrite_headers(ctx: &mut XdpContext) -> Result<(), ()> {
    let prev_checksum = compute_ip_checksum(ptr_at_mut::<Ipv4Hdr>(ctx, EthHdr::LEN)?);
    let true_checksum = unsafe {
        (*(ptr_at_mut::<Ipv4Hdr>(ctx, EthHdr::LEN)?)).check[0] as u16
            | ((*(ptr_at_mut::<Ipv4Hdr>(ctx, EthHdr::LEN)?)).check[1] as u16) << 8
    };
    info!(
        &ctx,
        "Rewriting headers, computed IP checksum: {}, true IP checksum {}",
        prev_checksum,
        true_checksum
    );

    // Ethernet
    let ethhdr: *mut EthHdr = ptr_at_mut(ctx, 0)?;
    unsafe {
        // Swap MAC addresses
        core::ptr::swap_nonoverlapping(&mut (*ethhdr).src_addr, &mut (*ethhdr).dst_addr, 1);
    }

    // IPv4
    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(ctx, EthHdr::LEN)?;
    unsafe {
        // Swap IP addresses
        core::ptr::swap_nonoverlapping(&mut (*ipv4hdr).src_addr, &mut (*ipv4hdr).dst_addr, 1);

        let checksum = compute_ip_checksum(ipv4hdr);
        (*ipv4hdr).check = checksum.to_be_bytes();
    }

    // UDP Header
    let transport_header_offset = EthHdr::LEN + Ipv4Hdr::LEN;
    let udphdr: *mut UdpHdr = ptr_at_mut(ctx, transport_header_offset)?;
    unsafe {
        // Swap UDP ports
        core::ptr::swap_nonoverlapping(&mut (*udphdr).src, &mut (*udphdr).dst, 1);

        // Should be recalculated by the kernel ? According to BMC
        (*udphdr).check = [0, 0];
    }

    Ok(())
}

#[inline(always)]
fn compute_ip_checksum(ip: *mut Ipv4Hdr) -> u16 {
    let ip_hdr: &mut Ipv4Hdr = unsafe { &mut *ip };

    ip_hdr.check = [0, 0];
    let mut next_ip_u16: *const u16 = ip as *const u16;

    let mut csum: u32 = 0;

    const IPV4_HEADER_U16_COUNT: usize = mem::size_of::<Ipv4Hdr>() / mem::size_of::<u16>();

    for _ in 0..IPV4_HEADER_U16_COUNT {
        let word = unsafe { *next_ip_u16 };
        csum += u32::from(word);
        next_ip_u16 = unsafe { next_ip_u16.add(1) };
    }

    csum = (csum & 0xFFFF) + (csum >> 16);

    !(csum as u16)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
