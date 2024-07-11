use std::{
    thread::sleep,
    time::Duration,
};

use mdns_lite::prelude::*;

fn main() {
    // Create broadcaster and example service:
    let mut broadcaster = MdnsBroadcaster::default();
    broadcaster.register_service(
        "example_service",
        "_http._tcp",
        80,
    ).unwrap();

    // Start broadcaster:
    broadcaster.start();

    // Sleep for 5 minutes:
    sleep(Duration::from_secs(300));
}