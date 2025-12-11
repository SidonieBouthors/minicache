const MAX_KEY_LEN: usize = 64;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct CacheKey {
    pub data: [u8; MAX_KEY_LEN],
    pub len: u16,
}

impl Default for CacheKey {
    fn default() -> Self {
        Self {
            data: [0; MAX_KEY_LEN],
            len: 0,
        }
    }
}

pub const MAX_VALUE_SIZE: usize = 64;

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct CacheValue {
    pub flags: u32,
    pub time_to_live: u32,

    pub len: u16,
    pub padding: u16,

    pub data: [u8; MAX_VALUE_SIZE],
}

impl Default for CacheValue {
    fn default() -> Self {
        Self {
            flags: 0,
            time_to_live: 0,
            len: 0,
            padding: 0,
            data: [0; MAX_VALUE_SIZE],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CacheValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for CacheKey {}
