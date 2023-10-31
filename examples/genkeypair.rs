use std::ffi::{
    c_int,
    c_char
};

#[link(name = "zmq")]
extern "C" {
    fn zmq_curve_keypair(z85_public_key: *mut c_char, z85_secret_key: *mut c_char) -> c_int;
}

const KEY_Z85_LEN: usize = 40;
const KEY_Z85_CSTR_LEN: usize = KEY_Z85_LEN + 1;

fn zmqe_curve_keypair() -> (String, String, i32) {
    let mut publickey_bufn = vec![0u8; KEY_Z85_CSTR_LEN];
    let mut secretkey_bufn = vec![0u8; KEY_Z85_CSTR_LEN];
    let r = unsafe {
        zmq_curve_keypair(
            (&mut publickey_bufn).as_mut_ptr() as *mut c_char,
            (&mut secretkey_bufn).as_mut_ptr() as *mut c_char
        )
    } as i32;
    (String::from_utf8(publickey_bufn[..KEY_Z85_LEN].to_vec()).unwrap(), String::from_utf8(secretkey_bufn[..KEY_Z85_LEN].to_vec()).unwrap(), r)
}

fn main() {
    let (publickey, secretkey, _) = zmqe_curve_keypair();
    println!("Public key: {}", &publickey);
    // Make sure no one is behind your back...
    println!("Secret key: {}", &secretkey);
}