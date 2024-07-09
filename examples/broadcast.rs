use std::{thread::sleep, time::Duration};

use mdns_lite::MdnsBroadcaster;

fn main() {
    // Create broadcaster and example service:
    let mut broadcaster = MdnsBroadcaster::new();
    broadcaster.register_service(
        "example_service",
        "_tcp",
        80,
    );

    // Start broadcaster:
    broadcaster.start();

    // Sleep for 5 minutes:
    sleep(Duration::from_secs(300));
}