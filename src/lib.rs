#![crate_type = "cdylib"]
use std::slice;

#[no_mangle]
pub extern "C" fn vivar_operator_engine(
    data: *mut u8, 
    len: usize,
    key: *const u8, 
    key_len: usize
) -> i32 {
    if data.is_null() || key.is_null() || len == 0 { return 1; }
    
    unsafe {
        let data_slice = slice::from_raw_parts_mut(data, len);
        let key_slice = slice::from_raw_parts(key, key_len);
        let constant: u64 = 0x9E3779B9;

        for (i, val) in data_slice.iter_mut().enumerate() {
            let mask = (constant ^ (i as u64) ^ (key_slice[i % key_len] as u64)) as u8;
            *val ^= mask;
        }
    }
    0
}
