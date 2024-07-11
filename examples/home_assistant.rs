use std::{
    thread::sleep,
    time::Duration,
};

use mdns_lite::prelude::*;

fn main() {
    let mut txt_records = TxtRecords::new();
    txt_records.add("type", "sensor").unwrap();
    txt_records.add("device_class", "temperature").unwrap();
    txt_records.add("friendly_name", "Test Temperature Sensor").unwrap();
    txt_records.add("unit", "C").unwrap();
    let service = MdnsService::new(
        "           MyThermometer",
        "_home-assistant._tcp",
        "local",
        80,
        txt_records,
    ).unwrap();
    let mut broadcaster = MdnsBroadcaster::new(
        vec![service],
        60 * 1000   
    );
    broadcaster.start(None, None);  

    // Sleep for 5 minutes:
    sleep(Duration::from_secs(300));
}