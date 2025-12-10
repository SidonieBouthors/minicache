#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UdpPreamble {
    pub request_id: u16,
    pub sequence_number: u16,
    pub total_datagrams: u16,
    pub reserved: u16,
}

pub const UDP_PREAMBLE_LEN: usize = core::mem::size_of::<UdpPreamble>();


pub const MAGIC_REQUEST: u8 = 0x80;
pub const MAGIC_RESPONSE: u8 = 0x81;

pub const OPCODE_GET: u8 = 0x00;
pub const OPCODE_SET: u8 = 0x01;

pub const STATUS_SUCCESS: u16 = 0x0000;
pub const STATUS_KEY_NOT_EXISTS: u16 = 0x0001;

pub const DATATYPE_RAW_BYTES: u8 = 0x00;

pub const REQUEST_HEADER_LEN: usize = core::mem::size_of::<RequestHeader>();

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestHeader {
    pub magic: u8,
    pub opcode: u8,
    key_length: u16, // Network byte order
    pub extras_length: u8,
    pub data_type: u8,
    vbucket_id: u16,  // Network byte order
    body_length: u32, // Network byte order (Total body: key+extras+value)
    pub opaque: u32,  // Host byte order (opaque token)
    pub cas: u64,     // Host byte order (CAS token)
}

impl RequestHeader {
    pub fn key_length(&self) -> u16 {
        u16::from_be(self.key_length)
    }

    pub fn vbucket_id(&self) -> u16 {
        u16::from_be(self.vbucket_id)
    }

    pub fn body_length(&self) -> u32 {
        u32::from_be(self.body_length)
    }
}

pub const RESPONSE_HEADER_LEN: usize = core::mem::size_of::<ResponseHeader>();

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ResponseHeader {
    pub magic: u8,
    pub opcode: u8,
    pub key_length: u16, // Network byte order
    pub extras_length: u8,
    pub data_type: u8,
    pub status: u16,      // Network byte order
    pub body_length: u32, // Network byte order
    pub opaque: u32,
    pub cas: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SetExtras {
    pub flags: u32,      // Host byte order
    pub expiration: u32, // Host byte order
}
