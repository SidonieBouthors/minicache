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

    if !is_binary_request {
        return Ok(xdp_action::XDP_PASS);
    }

    // Perform cache operations
    let opcode = unsafe { (*req_hdr).opcode };

    if opcode == OPCODE_GET {
        return handle_get_command(&ctx, request_offset, req_hdr);
    } else if opcode == OPCODE_SET {
        return handle_set_command(&ctx, request_offset, req_hdr);
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn handle_get_command(
    ctx: &XdpContext,
    request_offset: usize,
    req_hdr: *const RequestHeader,
) -> Result<u32, ()> {
    let key_length = unsafe { (*req_hdr).key_length() } as usize;
    let key_offset = request_offset + REQUEST_HEADER_LEN;

    let mut ebpf_key = CacheKey::default();

    if key_length == 0 || key_length > ebpf_key.data.len() {
        info!(&ctx, "GET: Key length {} out of bounds", key_length);
        return Ok(xdp_action::XDP_PASS);
    }

    info!(&ctx, "GET: Looking up key: {}", ebpf_key.data[0]);

    let data_ptr = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    let key_ptr = unsafe { data_ptr.add(key_offset) };

    if unsafe { key_ptr.add(key_length.min(1).max(ebpf_key.data.len())) } >= data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    unsafe { core::ptr::copy_nonoverlapping(key_ptr, ebpf_key.data.as_mut_ptr(), key_length) };
    ebpf_key.len = key_length as u16;

    // read first byte
    info!(&ctx, "GET: Looking up key: {}", ebpf_key.data[0]);

    if let Some(value) = unsafe { CACHE_MAP.get(ebpf_key) } {
        info!(&ctx, "GET: Cache hit - value {}", value.data[0])
        // ...
    } else {
        info!(&ctx, "GET: Cache miss.");
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn handle_set_command(
    ctx: &XdpContext,
    request_offset: usize,
    req_hdr: *const RequestHeader,
) -> Result<u32, ()> {
    let key_length = unsafe { (*req_hdr).key_length() } as usize;
    let extras_length = unsafe { (*req_hdr).extras_length } as usize;
    let body_length = unsafe { (*req_hdr).body_length() } as usize;

    let value_length = body_length
        .checked_sub(key_length)
        .and_then(|x| x.checked_sub(extras_length))
        .ok_or(())?;

    // Key starts after Header + Extras
    let extras_offset = request_offset + REQUEST_HEADER_LEN;
    let key_offset = extras_offset + extras_length;
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
    ebpf_key.len = key_length as u16;

    if unsafe { value_ptr.add(value_length.min(1).max(ebpf_value.data.len())) } >= data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(value_ptr, ebpf_value.data.as_mut_ptr(), value_length)
    };
    ebpf_value.len = value_length as u16;

    let extras_ptr = unsafe { data_ptr.add(extras_offset) } as *const u32;

    if unsafe { extras_ptr.add(2) } >= data_end as *const u32 {
        return Ok(xdp_action::XDP_PASS);
    }

    ebpf_value.flags = unsafe { *extras_ptr };
    ebpf_value.time_to_live = unsafe { *extras_ptr.add(1) };

    // update
    match CACHE_MAP.insert(ebpf_key, ebpf_value, 0) {
        Ok(_) => {
            // ...
            Ok(xdp_action::XDP_PASS)
        }
        Err(_) => {
            info!(&ctx, "SET: Cache SET failed.");
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
