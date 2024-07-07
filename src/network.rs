//! # ESP mDNS - Network
//! This module manages the underlying network operations, such as socket
//! management and network interface configuration. It provides the raw data to
//! the protocol module for processing and sends out the processed mDNS packets.
// TODO: Correct the documentation above

use std::{
    net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
        UdpSocket,
    },
    sync::{
        atomic::{
            AtomicBool,
            Ordering,
        },
        Arc,
        Mutex,
    },
    thread::{
        self,
        JoinHandle,
    },
    time::Duration,
};

use crate::{
    DnsClass,
    DnsType,
    MdnsPacket,
    MdnsService,
    Query,
    TxtRecords,
};

// TODO:
// This struct should register services. These services are then broadcast. The
// broadcaster will also respond to queries about the service.
pub struct MdnsBroadcaster {
    services: Arc<Mutex<Vec<MdnsService>>>,
    /// Interval between broadcasts in milliseconds.
    broadcast_interval: u64,
    /// Contains the [`JoinHandle`] for the [`MdnsBroadcaster`] thread.
    handle: Option<JoinHandle<()>>,
    /// A flag that tells the thread to stop.
    stop_flag: Arc<AtomicBool>,
}

impl Default for MdnsBroadcaster {
    #[inline]
    #[must_use]
    fn default() -> Self {
        Self::new()
    }
}

impl MdnsBroadcaster {
    /// Creates a new empty [`MdnsBroadcaster`].
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            services: Arc::new(Mutex::new(Vec::new())),
            broadcast_interval: 1000,
            handle: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Registers a new mDNS service with the
    /// [default domain](MdnsService::DEFAULT_DOMAIN).
    pub fn register_service(
        &mut self,
        instance_name: &str,
        service_type: &str,
        service_port: u16,
    ) {
        self.register_service_with_domain(
            instance_name,
            service_type,
            service_port,
            MdnsService::DEFAULT_DOMAIN,
        );
    }

    /// Registers a new mDNS service with a custom domain.
    pub fn register_service_with_domain(
        &mut self,
        instance_name: &str,
        service_type: &str,
        service_port: u16,
        service_domain: &str,
    ) {
        let service = MdnsService::new(
            instance_name,
            service_type,
            service_domain,
            service_port,
            TxtRecords::new(),
        );
        self.register_service_instance(service);
    }

    /// Registers a new mDNS service instance.
    pub fn register_service_instance(
        &mut self,
        service: MdnsService,
    ) {
        let mut services = self.services.lock().unwrap();
        services.push(service);
    }

    /// Starts the [`MdnsBroadcaster`].
    /// 
    /// If the broadcaster has already been started, this will do nothing.
    pub fn start(&mut self) {
        if self.handle.is_some() {
            return;
        }
        self.stop_flag.store(false, Ordering::Relaxed);
        let stop_flag = self.stop_flag.clone();
        let services = self.services.clone();
        let interval = Duration::from_millis(self.broadcast_interval);
        let handle = thread::spawn(move || {
            // TODO: This also needs to listen for mDNS questions.
            let multicast_address = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
                5353,
            );
            let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
            socket.set_broadcast(true).unwrap();
            loop {
                {
                    let services = services.lock().unwrap();
                    let total_services = services.len() as u16;
                    if total_services > 0 {
                        let mut questions = Vec::new();
                        for service in services.iter() {
                            let query = Query::new(
                                format!(
                                    "{}.{}.{}.",
                                    service.instance_name(),
                                    service.service_type(),
                                    service.service_domain(),
                                ),
                                DnsType::PTR,
                                DnsClass::IN,
                            );
                            questions.push(query);
                        }
                        let packet = MdnsPacket::new_query(
                            0,
                            questions,
                        );
                        let packet = packet.to_bytes();
                        socket.send_to(&packet, multicast_address).unwrap();
                    }
                }
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(interval);
            }
        });
        self.handle = Some(handle);
    }

    /// Stops the [`MdnsBroadcaster`].
    pub fn stop(&mut self) {
        if self.handle.is_some() {
            self.stop_flag.store(true, Ordering::Relaxed);
        }
    }
}