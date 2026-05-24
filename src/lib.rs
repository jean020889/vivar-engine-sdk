#![crate_type = "cdylib"]
use std::slice;

fn mix_state(i: u64, k: u64) -> u8 {
    let mut state = i.wrapping_add(k).wrapping_mul(0xbf58476d1ce4e5b9);
    state ^= state >> 30;
    state = state.wrapping_mul(0x94d049bb133111eb);
    state ^= state >> 27;
    (state & 0xFF) as u8
}

#[no_mangle]
pub extern "C" fn vivar_encrypt(data: *mut u8, len: usize, key: *const u8, key_len: usize) -> i32 {
    if data.is_null() || key.is_null() { return 1; }
    unsafe {
        let data_slice = slice::from_raw_parts_mut(data, len);
        let key_slice = slice::from_raw_parts(key, key_len);
        for (i, val) in data_slice.iter_mut().enumerate() {
            *val ^= mix_state(i as u64, key_slice[i % key_len] as u64);
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn vivar_decrypt(data: *mut u8, len: usize, key: *const u8, key_len: usize) -> i32 {
    // En este diseño XOR, el descifrado es idéntico, 
    // pero al separar la lógica, garantizamos que el estado es independiente.
    vivar_encrypt(data, len, key, key_len)
}
