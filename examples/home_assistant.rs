use std::{
    thread::sleep,
    time::Duration,
};

use mdns_lite::prelude::*;

fn main() {
    let mut txt_records = TxtRecords::new();
    txt_records.add("type", "temperature").unwrap();
    txt_records.add("model", "MyTemperatureSensor").unwrap();
    txt_records.add("manufacturer", "MyManufacturer").unwrap();
    txt_records.add("location", "LivingRoom").unwrap();
    txt_records.add("temp_unit", "C").unwrap();
    let service = MdnsService::new(
        "my_thermometer",
        "_temperature._tcp",
        "local",
        80,
        txt_records,
    ).unwrap();
    let mut broadcaster = MdnsBroadcaster::new(
        vec![service],
        60 * 1000
    );
    broadcaster.start();

    // Sleep for 5 minutes:
    sleep(Duration::from_secs(300));
}