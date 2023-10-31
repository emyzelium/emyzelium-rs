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