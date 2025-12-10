const MAX_KEY_LEN: usize = 250;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CacheKey {
    pub data: [u8; MAX_KEY_LEN],
    pub len: u16,
}

pub const MAX_VALUE_SIZE: usize = 1024;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct CacheValue {
    pub flags: u32,
    pub time_to_live: u32,

    pub len: u16,
    pub padding: u16,

    pub data: [u8; MAX_VALUE_SIZE],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CacheValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for CacheKey {}
