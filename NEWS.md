Version 0.9.8 (2024.01.08)
--------------------------

* Added, via socket monitor, the counter of current accepted incoming connections = the number of authorised subscribers = "popularity", and corresponding `in_connections_num()` getter to Efunguz


Version 0.9.6 (2023.11.30)
--------------------------

* Removed useless `mut` in `get_ehypha(&mut self, …)`, it is needed only in `get_mut_ehypha(…)`

* Replaced `zmq_poll(socket, …)` by `zmq_getsockopt(socket, ZMQ_EVENTS, …)`


Version 0.9.4 (2023.10.31)
--------------------------

* Switched to `getrandom` in library (demo uses `rand` as before)

* Replaced `zmq_msg_init_data()` with `zmq_msg_init_size()`

* `ZMQ_BLOCKY` is set to 0 at once for entire context, instead of `ZMQ_LINGER` for each socket

* Tiny changes and fixes

* Added links to Go version


Version 0.9.3 (2023.10.12)
--------------------------

* Very important update... fixed links to images in README.md to make them work at [crates.io](https://crates.io/crates/emyzelium) as well as at [GitHub](https://github.com/emyzelium/emyzelium-rs)


Version 0.9.2 (2023.10.11)
--------------------------

* Initial release of Rust version