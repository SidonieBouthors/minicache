use anyhow::Context as _;
use aya::{
    maps::{Array, HashMap, MapData},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use log::{debug, warn};
use minicache_common::{
    cache::{CacheKey, CacheValue},
    protocol::{REQUEST_HEADER_LEN, RequestHeader, UDP_PREAMBLE_LEN, UdpPreamble},
};

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "lo")]
    pub iface: String,
    #[clap(short, long, default_value = "11211")]
    pub port: u32,
}

const BUFFER_SIZE: usize = 1024;

pub async fn run(opt: Opt) -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/minicache"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface, port } = opt;

    // Cache Map
    let cache_map_handle = ebpf
        .take_map("CACHE_MAP")
        .context("eBPF map CACHE_MAP not found".to_string())?;
    let _cache_map: HashMap<MapData, CacheKey, CacheValue> = cache_map_handle
        .try_into()
        .context("Failed to convert map handle to HashMap")?;

    // Configure the port in the eBPF map
    let config_map_handle = ebpf
        .map_mut("CONFIG_PORT")
        .context("eBPF map CONFIG_PORT not found")?;
    let mut port_map: Array<_, u32> = config_map_handle
        .try_into()
        .context("Failed to convert map handle to Array<u32>")?;
    port_map
        .set(0, port, 0)
        .context("Failed to set port in configuration map")?;

    let program: &mut Xdp = ebpf.program_mut("minicache").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let bind_address = format!("0.0.0.0:{}", port);
    let socket = tokio::net::UdpSocket::bind(&bind_address).await?;
    println!("UDP listener started on {}", bind_address);

    loop {
        let mut buffer = [0; BUFFER_SIZE];
        let (number_of_bytes, src_addr) = match socket.recv_from(&mut buffer).await {
            Ok(result) => result,
            Err(e) => {
                eprintln!("An error occurred while receiving: {}", e);
                continue; // Continue loop on error
            }
        };

        // In the final version, this should not be needed:
        // All get and set requests should be handled in eBPF
        println!("Received {} bytes", number_of_bytes);
        let data = &buffer[..number_of_bytes];

        // Process it as RequestHeader
        if number_of_bytes >= UDP_PREAMBLE_LEN + REQUEST_HEADER_LEN {
            let _udp_preamble: UdpPreamble =
                unsafe { std::ptr::read_unaligned(data.as_ptr() as *const _) };
            let _header: RequestHeader =
                unsafe { std::ptr::read_unaligned(data[UDP_PREAMBLE_LEN..].as_ptr() as *const _) };
            // println!("Request Header: {:?}", header);

            // socket.send_to(data, src_addr).await?;
        } else {
            println!("Received data is too small");
        }
    }
}
