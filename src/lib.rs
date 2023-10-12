/*
 * Emyzelium (Rust)
 *
 * is another wrapper around ZeroMQ's Publish-Subscribe messaging pattern
 * with mandatory Curve security and optional ZAP authentication filter,
 * over Tor, through Tor SOCKS proxy,
 * for distributed artificial elife, decision making etc. systems where
 * each peer, identified by its public key, onion address, and port,
 * publishes and updates vectors of vectors of bytes of data
 * under unique topics that other peers can subscribe to
 * and receive the respective data.
 * 
 * https://github.com/emyzelium/emyzelium-rs
 * 
 * emyzelium@protonmail.com
 * 
 * Copyright (c) 2023 Emyzelium caretakers
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

 /*
 * Source
 */

extern crate rand;

use rand::prelude::*;

#[allow(unused_imports)]
use std::{
    collections::{
        HashMap,
        HashSet
    },
    ffi::{
        c_char,
        c_int,
        c_long,
        c_longlong,
        c_short,
        c_uchar,
        c_void,
        CString,
    },
    fs,
    ptr,
    time::{
        SystemTime,
        UNIX_EPOCH
    }
};

// Copied from zmq.h
// Socket types
const ZMQ_PUB: c_int = 1;
const ZMQ_REP: c_int = 4;
const ZMQ_SUB: c_int = 2;

// Socket options
const ZMQ_CURVE_PUBLICKEY: c_int = 48;
const ZMQ_CURVE_SECRETKEY: c_int = 49;
const ZMQ_CURVE_SERVER: c_int = 47;
const ZMQ_CURVE_SERVERKEY: c_int = 50;
const ZMQ_IPV6: c_int = 42;
const ZMQ_LINGER: c_int = 17;
const ZMQ_ROUTING_ID: c_int = 5;
const ZMQ_SOCKS_PROXY: c_int = 68;
const ZMQ_SUBSCRIBE: c_int = 6;
const ZMQ_UNSUBSCRIBE: c_int = 7;
const ZMQ_ZAP_DOMAIN: c_int = 55;

// Message options
const ZMQ_MORE: c_int = 1;

// Send/recv options
const ZMQ_SNDMORE: c_int = 2;

const ZMQ_POLLIN: c_short = 1;

#[link(name = "zmq")]
extern "C" {
    fn zmq_bind(socket: *mut c_void, endpoint: *const c_char) -> c_int;
    fn zmq_close(socket: *mut c_void) -> c_int;
    fn zmq_connect(socket: *mut c_void, endpoint: *const c_char) -> c_int;
    fn zmq_ctx_new() -> *mut c_void;
    fn zmq_ctx_set(context: *mut c_void, option_name: c_int, option_value: c_int) -> c_int;
    fn zmq_ctx_shutdown(context: *mut c_void) -> c_int;
    fn zmq_ctx_term(context: *mut c_void) -> c_int;
    fn zmq_curve_public(z85_public_key: *mut c_uchar, z85_secret_key: *mut c_uchar);
    fn zmq_msg_close(msg: *mut zmq_msg_t) -> c_int;
    fn zmq_msg_data(msg: *mut zmq_msg_t) -> *mut c_void;
    fn zmq_msg_get(message: *mut zmq_msg_t, property: c_int) -> c_int;
    fn zmq_msg_init(msg: *mut zmq_msg_t) -> c_int;
    fn zmq_msg_init_data(msg: *mut zmq_msg_t, data: *mut c_void, size: usize, ffn: extern "C" fn(*mut c_void, *mut c_void), hint: *mut c_void);
    fn zmq_msg_recv(msg: *mut zmq_msg_t, socket: *mut c_void, flags: c_int) -> c_int;
    fn zmq_msg_send(msg: *mut zmq_msg_t, socket: *mut c_void, flags: c_int) -> c_int;
    fn zmq_msg_size(msg: *mut zmq_msg_t) -> usize;
    fn zmq_poll(items: *mut zmq_pollitem_t, nitems: c_int, timeout: c_long) -> c_int;
    fn zmq_setsockopt(socket: *mut c_void, option_name: c_int, option_value: *const c_void, option_len: usize) -> c_int;
    fn zmq_socket(context: *mut c_void, stype: c_int) -> *mut c_void;
    fn zmq_z85_encode(dest: *mut c_uchar, data: *const u8, size: usize) -> *mut c_char;
}

extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(p: *mut c_void);
}

pub const LIB_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const LIB_DATE: &str = "2023.10.12";

pub const DEF_PUBSUB_PORT: u16 = 0xEDAF; // 60847

pub const DEF_TOR_PROXY_PORT: u16 = 9050; // default from /etc/tor/torrc
pub const DEF_TOR_PROXY_HOST: &str = "127.0.0.1"; // default from /etc/tor/torrc

const KEY_Z85_LEN: usize = 40;
const KEY_Z85_CSTR_LEN: usize = 41;
const KEY_BIN_LEN: usize = 32;

const DEF_IPV6_STATUS: c_int = 1;
const DEF_LINGER: c_int = 1;

const CURVE_MECHANISM_ID: &str = "CURVE"; // See https://rfc.zeromq.org/spec/27/
const ZAP_DOMAIN: &str = "emyz";

const ZAP_SESSION_ID_LEN: usize = 32;

const ERR_ALREADY_PRESENT: &str = "already present";
const ERR_ALREADY_ABSENT: &str = "already absent";
const ERR_ALREADY_PAUSED: &str = "already paused";
const ERR_ALREADY_RESUMED: &str = "already resumed";
const ERR_ABSENT: &str = "absent";

#[repr(C)]
#[allow(non_camel_case_types)]
struct zmq_msg_t { // from zmq.h
    _d: [c_uchar; 64]
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct zmq_pollitem_t { // from zmq.h
    socket: *mut c_void,

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fd: c_longlong,

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    fd: c_int,

    events: c_short,
    revents: c_short
}

pub struct Etale {
    paused: bool,
    parts: Vec<Vec<u8>>,
    t_out: i64,
    t_in: i64
}

pub struct Ehypha {
    subsock: *mut c_void,
    subpollitem: zmq_pollitem_t,
    etales: HashMap<String, Etale>
}

pub struct Efunguz {
    secretkey: String,
    publickey: String,
    whitelist_publickeys: HashSet<String>,
    torproxy_port: u16,
    torproxy_host: String,
    ehyphae: HashMap<String, Ehypha>,
    context: *mut c_void,
    zapsock: *mut c_void,
    zappollitem: zmq_pollitem_t,
    zap_session_id: Vec<u8>,
    pubsock: *mut c_void
}

extern "C" fn zmq_free_fn(data: *mut c_void, _hint: *mut c_void) {
    unsafe {
        free(data);
    }
}

fn time_musec() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_micros() as i64,
        Err(_) => 0
    } 
}

fn cut_pad_key_str(s: &str) -> String {
    let mut s = String::from(s);
    if s.len() < KEY_Z85_LEN {
        s.extend(vec![' '; KEY_Z85_LEN - s.len()]);
    } else {
        s.truncate(KEY_Z85_LEN);
    }
    s
}

fn zmqe_setsockopt_int(socket: *mut c_void, option_name: c_int, option_value: c_int) -> c_int {
    unsafe {
        zmq_setsockopt(socket, option_name, (&option_value) as *const c_int as *const c_void, std::mem::size_of::<c_int>())
    }
}

fn zmqe_setsockopt_str(socket: *mut c_void, option_name: c_int, option_value: &str) -> c_int {
    let cstr = CString::new(option_value).unwrap_or_default();
    unsafe {
        zmq_setsockopt(socket, option_name, cstr.as_ptr() as *const c_char as *const c_void, option_value.len() + 1)
    }
}

fn zmqe_setsockopt_vec(socket: *mut c_void, option_name: c_int, option_value: &Vec<u8>) -> c_int {
    unsafe {
        zmq_setsockopt(socket, option_name, option_value.as_ptr() as *const c_void, option_value.len())
    }
}

fn zmqe_bind(socket: *mut c_void, endpoint: &str) -> c_int {
    let cstr = CString::new(endpoint).unwrap_or_default();
    unsafe {
        zmq_bind(socket, cstr.as_ptr())
    }
}

fn zmqe_connect(socket: *mut c_void, endpoint: &str) -> c_int {
    let cstr = CString::new(endpoint).unwrap_or_default();
    unsafe {
        zmq_connect(socket, cstr.as_ptr())
    }
}

fn zmqe_curve_public(z85_secret_key: &str) -> String {
    let mut sec_bufn = [0u8; KEY_Z85_CSTR_LEN];
    unsafe { // "safe" if z85_secret_key is not shorter than KEY_Z85_LEN... see cut_pad_key_str()
        (z85_secret_key.as_ptr() as *const u8).copy_to(sec_bufn.as_mut_ptr(), KEY_Z85_LEN);
    }
    let mut pub_bufn = [0u8; KEY_Z85_CSTR_LEN];
    unsafe {
        zmq_curve_public(pub_bufn.as_mut_ptr(), sec_bufn.as_mut_ptr());
    }
    String::from_utf8(pub_bufn[..KEY_Z85_LEN].to_vec()).unwrap_or_default()
}

impl zmq_msg_t {
    fn new_default() -> Self {
        Self {
            _d: [0 as c_uchar; 64]
        }
    }
}

impl zmq_pollitem_t {
    fn new_pollin(socket: *mut c_void) -> Self {
        Self {
            socket,
            fd: 0,
            events: ZMQ_POLLIN,
            revents: 0
        }
    }
}

fn zmqe_send(socket: *mut c_void, parts: & Vec<Vec<u8>>) {
    let mut msg = zmq_msg_t::new_default();
    for i in 0..parts.len() {
        unsafe {
            let size = parts[i].len();
            let data = malloc(size);
            (parts[i].as_ptr() as *const c_void).copy_to(data, size);
            zmq_msg_init_data((&mut msg) as *mut zmq_msg_t, data, size, zmq_free_fn, ptr::null_mut());
            if zmq_msg_send((&mut msg) as *mut zmq_msg_t, socket, if (i + 1) < parts.len() {ZMQ_SNDMORE} else {0}) < 0 {
                zmq_msg_close((&mut msg) as *mut zmq_msg_t);
            }
        }        
    }
}

fn zmqe_recv(socket: *mut c_void) -> Vec<Vec<u8>> {
    let mut parts = Vec::new();
    let mut msg = zmq_msg_t::new_default();
    let mut more: c_int;
    loop {
        unsafe {
            zmq_msg_init((&mut msg) as *mut zmq_msg_t);
            zmq_msg_recv((&mut msg) as *mut zmq_msg_t, socket, 0);
            let size = zmq_msg_size((&mut msg) as *mut zmq_msg_t);
            let mut part = vec![0u8; size];
            let data = zmq_msg_data((&mut msg) as *mut zmq_msg_t);
            (data as *const u8).copy_to(part.as_mut_ptr(), size);
            parts.push(part);
            more = zmq_msg_get((&mut msg) as *mut zmq_msg_t, ZMQ_MORE);
            zmq_msg_close((&mut msg) as *mut zmq_msg_t);
        }
        if more == 0 {
            break;
        }
    }
    parts
}

fn zmqe_poll_in_now(zpi: &mut zmq_pollitem_t) -> c_int {
    unsafe {
        zmq_poll(zpi as *mut zmq_pollitem_t, 1, 0)
    }
}

impl Etale {

    fn new_default() -> Self {
        Self {
            paused: false,
            parts: Vec::new(),
            t_out: -1,
            t_in: -1
        }
    }

    pub fn parts(&self) -> & Vec<Vec<u8>> {
        & self.parts
    }

    pub fn t_out(&self) -> i64 {
        self.t_out
    }

    pub fn t_in(&self) -> i64 {
        self.t_in
    }

}

impl Ehypha {

    fn new(context: *mut c_void, secretkey: &str, publickey: &str, serverkey: &str, onion: &str, port: u16, torproxy_port: u16, torproxy_host: &str) -> Self {
        let subsock = unsafe {
            zmq_socket(context, ZMQ_SUB)
        };
        zmqe_setsockopt_int(subsock, ZMQ_LINGER, DEF_LINGER);
        zmqe_setsockopt_str(subsock, ZMQ_CURVE_SECRETKEY, secretkey);
        zmqe_setsockopt_str(subsock, ZMQ_CURVE_PUBLICKEY, publickey);
        zmqe_setsockopt_str(subsock, ZMQ_CURVE_SERVERKEY, serverkey);
        zmqe_setsockopt_str(subsock, ZMQ_SOCKS_PROXY, & format!("{}:{}", torproxy_host, torproxy_port));
        zmqe_connect(subsock, & format!("tcp://{}.onion:{}", onion, port));
        let subpollitem = zmq_pollitem_t::new_pollin(subsock);
        Self {
            subsock,
            subpollitem,
            etales: HashMap::new()
        }
    }

    pub fn add_etale(&mut self, title: &str) -> Result<(), String> {
        match self.etales.insert(String::from(title), Etale::new_default()) {
            None => {
                zmqe_setsockopt_str(self.subsock, ZMQ_SUBSCRIBE, title);
                Ok(())
            },
            Some(_) => Err(String::from(ERR_ALREADY_PRESENT))
        }
    }

    pub fn get_etale(&self, title: &str) -> Option<&Etale> {
        self.etales.get(title)
    }

    pub fn del_etale(&mut self, title: &str) -> Result<(), String> {
        match self.etales.remove(title) {
            Some(_) => {
                zmqe_setsockopt_str(self.subsock, ZMQ_UNSUBSCRIBE, title);
                Ok(())
            },
            None => Err(String::from(ERR_ALREADY_ABSENT))
        }
    }

    pub fn pause_etale(&mut self, title: &str) -> Result<(), String> {
        match self.etales.get_mut(title) {
            Some(etale) => {
                if ! etale.paused {
                    zmqe_setsockopt_str(self.subsock, ZMQ_UNSUBSCRIBE, title);
                    etale.paused = true;
                    Ok(())
                } else {
                    Err(String::from(ERR_ALREADY_PAUSED))
                }
            },
            None => {
                Err(String::from(ERR_ABSENT))
            }
        }
    }

    pub fn resume_etale(&mut self, title: &str) -> Result<(), String> {
        match self.etales.get_mut(title) {
            Some(etale) => {
                if etale.paused {
                    zmqe_setsockopt_str(self.subsock, ZMQ_SUBSCRIBE, title);
                    etale.paused = false;
                    Ok(())
                } else {
                    Err(String::from(ERR_ALREADY_RESUMED))
                }
            },
            None => {
                Err(String::from(ERR_ABSENT))
            }
        }
    }

    pub fn pause_etales(&mut self) {
        for (title, etale) in &mut self.etales {
            if ! etale.paused {
                zmqe_setsockopt_str(self.subsock, ZMQ_UNSUBSCRIBE, title);
                etale.paused = true;
            }
        }
    }

    pub fn resume_etales(&mut self) {
        for (title, etale) in &mut self.etales {
            if etale.paused {
                zmqe_setsockopt_str(self.subsock, ZMQ_SUBSCRIBE, title);
                etale.paused = false;
            }
        }
    }

    fn update(&mut self) {
        let t = time_musec();
        while zmqe_poll_in_now(&mut self.subpollitem) > 0 {
            let msg_parts = zmqe_recv(self.subsock);
            // Sanity checks...
            if msg_parts.len() >= 2 {
                // 0th is topic, 1st is remote time, rest (optional) is data
                let topic = & msg_parts[0];
                let l = topic.len();
                if (l > 0) && (topic[l - 1] == 0) {
                    let title = String::from_utf8(topic[..(l - 1)].to_vec()).unwrap_or_default();
                    if let Some(etale) = self.etales.get_mut(&title) {
                        if ! etale.paused {
                            if msg_parts[1].len() == 8 {
                                etale.parts.clear();
                                etale.parts.extend_from_slice(& msg_parts[2..]);
                                let mut buf = [0u8; 8];
                                buf.copy_from_slice(& msg_parts[1]);
                                etale.t_out = i64::from_le_bytes(buf);
                                etale.t_in = t;
                            }
                        }
                    }
                }
            }
        }
    }

}

impl Drop for Ehypha {
    fn drop(&mut self) {
        unsafe {
            zmq_close(self.subsock);
        }
    }
}

impl Efunguz {

    pub fn new(secretkey: &str, whitelist_publickeys: & HashSet<String>, pub_port: u16, torproxy_port: u16, torproxy_host: &str) -> Self {
        let secretkey = cut_pad_key_str(secretkey);
        let publickey = zmqe_curve_public(&secretkey);

        let mut cp_whitelist_publickeys = HashSet::new();
        for k in whitelist_publickeys {
            cp_whitelist_publickeys.insert(cut_pad_key_str(k));
        }

        let torproxy_host = String::from(torproxy_host);

        let ehyphae = HashMap::new();

        let context = unsafe {
            zmq_ctx_new()
        };

        unsafe {
            zmq_ctx_set(context, ZMQ_IPV6, DEF_IPV6_STATUS);
        }

        // At first, REP socket for ZAP auth...
        let zapsock = unsafe {
            zmq_socket(context, ZMQ_REP)
        };

        zmqe_setsockopt_int(zapsock, ZMQ_LINGER, DEF_LINGER);
        zmqe_bind(zapsock, "inproc://zeromq.zap.01");

        let zappollitem = zmq_pollitem_t::new_pollin(zapsock);

        let mut zap_session_id = vec![0u8; ZAP_SESSION_ID_LEN];
        thread_rng().fill_bytes(&mut zap_session_id); // must be cryptographically random... is it?

        // ..and only then, PUB socket
        let pubsock = unsafe {
            zmq_socket(context, ZMQ_PUB)
        };

        zmqe_setsockopt_int(pubsock, ZMQ_LINGER, DEF_LINGER);
        zmqe_setsockopt_int(pubsock, ZMQ_CURVE_SERVER, 1);
        zmqe_setsockopt_str(pubsock, ZMQ_CURVE_SECRETKEY, &secretkey);
        zmqe_setsockopt_vec(pubsock, ZMQ_ZAP_DOMAIN, & ZAP_DOMAIN.as_bytes().to_vec()); // to enable auth, must be non-empty due to ZMQ RFC 27
        zmqe_setsockopt_vec(pubsock, ZMQ_ROUTING_ID, & zap_session_id); // to make sure only this pubsock can pass auth through zapsock; see update()
        zmqe_bind(pubsock, & format!("tcp://*:{}", pub_port));

        Self {
            secretkey,
            publickey,
            whitelist_publickeys: cp_whitelist_publickeys,
            torproxy_port,
            torproxy_host,
            ehyphae,
            context,
            zapsock,
            zappollitem,
            zap_session_id,
            pubsock
        }
    }

    pub fn add_whitelist_publickeys(&mut self, publickeys: & HashSet<String>) {
        for k in publickeys {
            self.whitelist_publickeys.insert(cut_pad_key_str(k));
        }
    }

    pub fn del_whitelist_publickeys(&mut self, publickeys: & HashSet<String>) {
        for k in publickeys {
            self.whitelist_publickeys.remove(& cut_pad_key_str(k));
        }
    }

    pub fn clear_whitelist_publickeys(&mut self) {
        self.whitelist_publickeys.clear();
    }

    pub fn read_whitelist_publickeys(&mut self, filepath: &str) {
        for line in fs::read_to_string(filepath).unwrap_or_default().lines() {
            if line.len() >= KEY_Z85_LEN {
                let mut cp_line = String::from(line);
                cp_line.truncate(KEY_Z85_LEN);
                self.whitelist_publickeys.insert(cp_line);
            }
        }
    }

    pub fn add_ehypha(&mut self, publickey: &str, onion: &str, port: u16) -> Result<&mut Ehypha, String> {
        let cp_publickey = cut_pad_key_str(publickey);
        match self.ehyphae.insert(
            cp_publickey.clone(),
            Ehypha::new(self.context, & self.secretkey, & self.publickey, &cp_publickey, onion, port, self.torproxy_port, & self.torproxy_host)
        ) {
            None => match self.ehyphae.get_mut(&cp_publickey) {
                Some(eh) => Ok(eh),
                None => Err(String::from(ERR_ABSENT))
            },
            Some(_) => Err(String::from(ERR_ALREADY_PRESENT))
        }
    }

    pub fn get_ehypha(&mut self, publickey: &str) -> Option<&Ehypha> {
        let cp_publickey = cut_pad_key_str(publickey);
        self.ehyphae.get(&cp_publickey)
    }

    pub fn get_mut_ehypha(&mut self, publickey: &str) -> Option<&mut Ehypha> {
        let cp_publickey = cut_pad_key_str(publickey);
        self.ehyphae.get_mut(&cp_publickey)
    }

    pub fn del_ehypha(&mut self, publickey: &str) -> Result<(), String> {
        let cp_publickey = cut_pad_key_str(publickey);
        match self.ehyphae.remove(&cp_publickey) {
            Some(_) => Ok(()),
            None => Err(String::from(ERR_ALREADY_ABSENT))
        }
    }

    pub fn emit_etale(&mut self, title: &str, parts: & Vec<Vec<u8>>) {
        let mut msg_parts: Vec<Vec<u8>> = Vec::new();

        let mut topic = String::from(title).as_bytes().to_vec();
        topic.push(0);
        msg_parts.push(topic);

        let t_out = time_musec();
        msg_parts.push(t_out.to_le_bytes().to_vec());

        msg_parts.extend_from_slice(parts);

        zmqe_send(self.pubsock, &msg_parts);
    }

    pub fn update(&mut self) {
        while zmqe_poll_in_now(&mut self.zappollitem) > 0 {
            let request = zmqe_recv(self.zapsock);
            let mut reply: Vec<Vec<u8>> = Vec::new();

            let version = request[0].clone();
            let sequence = request[1].clone();
            // let domain = request[2].clone();
            // let address = request[3].clone();
            let identity = request[4].clone();
            let mechanism = request[5].clone();
            let mut key_u8 = request[6].clone();

            key_u8.truncate(KEY_BIN_LEN);
            let mut key_bufn = [0u8; KEY_Z85_CSTR_LEN];
            unsafe {
                zmq_z85_encode(key_bufn.as_mut_ptr(), key_u8.as_ptr(), KEY_BIN_LEN);
            }
            let key = String::from_utf8(key_bufn[..KEY_Z85_LEN].to_vec()).unwrap_or_default();

            reply.push(version);
            reply.push(sequence);

            if (identity == self.zap_session_id) && (mechanism == CURVE_MECHANISM_ID.as_bytes().to_vec()) && (self.whitelist_publickeys.is_empty() || self.whitelist_publickeys.contains(&key)) {
                // Auth passed; though needless (yet), set user-id to client's publickey
                reply.push("200".as_bytes().to_vec());
                reply.push("OK".as_bytes().to_vec());
                reply.push(key.as_bytes().to_vec());
                reply.push("".as_bytes().to_vec());
            } else {
                // Auth failed
                reply.push("400".as_bytes().to_vec());
                reply.push("FAILED".as_bytes().to_vec());
                reply.push("".as_bytes().to_vec());
                reply.push("".as_bytes().to_vec());
            }

            zmqe_send(self.zapsock, &reply);
        }

        for (_, eh) in &mut self.ehyphae {
            eh.update();
        }
    }

}

impl Drop for Efunguz {
    fn drop(&mut self) {
        self.ehyphae.clear(); // to close subsock of each ehypha in its destructor before terminating context, to which those sockets belong

        unsafe {
            zmq_close(self.pubsock);
            zmq_close(self.zapsock);

            zmq_ctx_shutdown(self.context);
            zmq_ctx_term(self.context);
        }
    }
}