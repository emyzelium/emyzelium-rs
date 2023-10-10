use std::ffi::{
    c_int,
    c_char
};

#[link(name = "zmq")]
extern "C" {
    fn zmq_curve_keypair(z85_public_key: *mut c_char, z85_secret_key: *mut c_char) -> c_int;
}

const KEY_Z85_LEN: usize = 40;

fn main() {
    let mut publickey_bufn = vec![0u8; KEY_Z85_LEN + 1];
    let mut secretkey_bufn = vec![0u8; KEY_Z85_LEN + 1];
    unsafe {
        zmq_curve_keypair(
            (&mut publickey_bufn).as_mut_ptr() as *mut c_char,
            (&mut secretkey_bufn).as_mut_ptr() as *mut c_char
        );
    }
    let publickey = String::from_utf8(publickey_bufn[..KEY_Z85_LEN].to_vec()).unwrap();
    println!("Public key: {}", &publickey);
    let secretkey = String::from_utf8(secretkey_bufn[..KEY_Z85_LEN].to_vec()).unwrap();
    // Make sure no one is behind your back...
    println!("Secret key: {}", &secretkey);
}