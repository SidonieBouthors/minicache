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
}

pub const RESPONSE_HEADER_LEN: usize = core::mem::size_of::<ResponseHeader>();

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ResponseHeader {
    pub magic: u8,
    pub opcode: u8,
    pub status: u16,      // Network byte order
}
