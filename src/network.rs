//! # ESP mDNS - Network
//! This module manages the underlying network operations, such as socket
//! management and network interface configuration. It provides the raw data to
//! the protocol module for processing and sends out the processed mDNS packets.
// TODO: Correct the documentation above

use std::{
    net::{
        IpAddr,
        Ipv4Addr,
        Ipv6Addr,
        SocketAddr,
        SocketAddrV4,
        SocketAddrV6,
    }, ops::Sub, sync::{
        atomic::{
            AtomicBool,
            Ordering,
        },
        Arc,
        Mutex,
    }, thread::{
        self,
        JoinHandle,
    }, time::{Duration, Instant}
};

use mio::{
    event::Event, net::UdpSocket, Events, Interest, Poll, Token
};

use crate::{
    DnsClass, DnsName, DnsType, MdnsPacket, MdnsService, MdnsServiceError, Query, Response, TxtRecords
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
        Self::new(
            Vec::new(),
            Self::DEFAULT_BROADCAST_INTERVAL
        )
    }
}

impl MdnsBroadcaster {
    /// Default value for [`Self::broadcast_interval`].
    pub const DEFAULT_BROADCAST_INTERVAL: u64 = 60 * 1000;

    /// Port used for mDNS multicast.
    pub const MULTICAST_PORT: u16 = 5353;

    /// IPv4 multicast address.
    pub const IPV4_MULTICAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

    /// IPv4 multicast address and port.
    pub const IPV4_MULTICAST_SOCKET_ADDRESS: SocketAddr = SocketAddr::new(
        IpAddr::V4(Self::IPV4_MULTICAST_ADDRESS),
        Self::MULTICAST_PORT,
    );

    /// IPv6 multicast address.
    pub const IPV6_MULTICAST_ADDRESS: Ipv6Addr = Ipv6Addr::new(0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00fb);

    /// IPv6 multicast address and port.
    pub const IPV6_MULTICAST_SOCKET_ADDRESS: SocketAddr = SocketAddr::new(
        IpAddr::V6(Self::IPV6_MULTICAST_ADDRESS),
        Self::MULTICAST_PORT,
    );

    /// Creates a new empty [`MdnsBroadcaster`].
    #[inline]
    #[must_use]
    pub fn new(
        services: Vec<MdnsService>,
        broadcast_interval: u64,
    ) -> Self {
        Self {
            services: Arc::new(Mutex::new(services)),
            broadcast_interval: broadcast_interval.max(1000),
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
    ) -> Result<(), MdnsServiceError> {
        self.register_service_with_domain(
            instance_name,
            service_type,
            service_port,
            MdnsService::DEFAULT_DOMAIN,
        )
    }

    /// Registers a new mDNS service with a custom domain.
    pub fn register_service_with_domain(
        &mut self,
        instance_name: &str,
        service_type: &str,
        service_port: u16,
        service_domain: &str,
    ) -> Result<(), MdnsServiceError> {
        let service = MdnsService::new(
            instance_name,
            service_type,
            service_domain,
            service_port,
            TxtRecords::new(),
        )?;
        self.register_service_instance(service);
        Ok(())
    }

    /// Registers a new mDNS service instance.
    pub fn register_service_instance(
        &mut self,
        service: MdnsService,
    ) {
        let mut services = self.services.lock().unwrap();
        services.push(service);
    }

    /// Returns the first local IPv4 and IPv6 address found when iterating
    /// through the available interfaces.
    fn get_local_ip_addresses() -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        match get_if_addrs::get_if_addrs() {
            Ok(interfaces) => {
                let mut ipv4 = None;
                let mut ipv6 = None;
                for interface in interfaces {
                    if interface.is_loopback() {
                        continue;
                    }
                    match interface.addr.ip() {
                        IpAddr::V4(ip) if ipv4.is_none() => ipv4 = Some(ip.octets().to_vec()),
                        IpAddr::V6(ip) if ipv6.is_none() => ipv6 = Some(ip.octets().to_vec()),
                        _ => continue,
                    }
                }
                (ipv4, ipv6)
            }
            Err(error) => {
                log::error!("Failed to get local IPv4 and IPv6 addresses: {error}");
                (None, None)
            }
        }
    }

    /// Creates a pair of IPv4 and IPv6 [`UdpSocket`]s.
    fn create_sockets() -> Result<(UdpSocket, UdpSocket), std::io::Error> {
        // Create IPv4 socket:
        let ipv4_socket = UdpSocket::bind(
            SocketAddr::V4(
                SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    0,
                )
            )
        )?;
        ipv4_socket.set_broadcast(true)?;
        ipv4_socket.set_multicast_loop_v4(true)?;
        ipv4_socket.join_multicast_v4(
            &Self::IPV4_MULTICAST_ADDRESS,
            &Ipv4Addr::UNSPECIFIED,
        )?;

        // Create IPv6 socket:
        let ipv6_socket = UdpSocket::bind(
            SocketAddr::V6(
                SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    0,
                    0,
                    0,
                )
            )
        )?;
        ipv6_socket.set_broadcast(true)?;
        ipv6_socket.set_multicast_loop_v6(true)?;
        ipv6_socket.join_multicast_v6(
            &Self::IPV6_MULTICAST_ADDRESS,
            0,
        )?;

        // Return sockets:
        Ok((ipv4_socket, ipv6_socket))
    }

    fn broadcast_services(
        services: Arc<Mutex<Vec<MdnsService>>>,
        ttl: u32,
        ipv4_socket: &UdpSocket,
        ipv6_socket: &UdpSocket,
    ) {
        // Lock the services:
        let services = services.lock().unwrap();

        // Check if there are services to broadcast:
        if !services.is_empty() {
            // There are services to broadcast. We should continue gathering
            // information before broadcasting the services:
            let (ipv4_local, ipv6_local) = Self::get_local_ip_addresses();

            // We now have all of the information we need to broadcast an mDNS
            // packet for each of the services:
            for service in services.iter() {
                // Get the DNS name of the service:
                let dns_name = DnsName::new(service.labels().to_vec());

                // Construct the authoritative nameservers:
                let mut authoritative_nameservers = Vec::new();
                if let Some(ipv4_local) = &ipv4_local {
                    authoritative_nameservers.push(
                        Response::new(
                            dns_name.clone(),
                            DnsType::A,
                            DnsClass::IN,
                            ttl,
                            ipv4_local.clone(),
                        )
                    );
                }
                if let Some(ipv6_local) = &ipv6_local {
                    authoritative_nameservers.push(
                        Response::new(
                            dns_name.clone(),
                            DnsType::AAAA,
                            DnsClass::IN,
                            ttl,
                            ipv6_local.clone(),
                        )
                    );
                }

                // Construct the mDNS packet:
                let packet = MdnsPacket::new_with_records(
                    0,
                    vec![Query::new(
                        dns_name,
                        DnsType::ANY,
                        DnsClass::IN,
                    )],
                    Vec::new(),
                    authoritative_nameservers,
                    Vec::new(),
                );

                // Send the packet to the mDNS IPv4 and IPv6 addresses:
                let packet = packet.to_bytes();
                if let Err(error) = ipv4_socket.send_to(&packet, Self::IPV4_MULTICAST_SOCKET_ADDRESS) {
                    log::error!("Failed to broadcast mDNS packet to IPv4 multicast host: {error}");
                }
                if let Err(error) = ipv6_socket.send_to(&packet, Self::IPV6_MULTICAST_SOCKET_ADDRESS) {
                    log::error!("Failed to broadcast mDNS packet to IPv6 multicast host: {error}");
                }
            }
        }
    }

    /// Responds to an mDNS packet.
    fn respond_to_mdns(
        services: Arc<Mutex<Vec<MdnsService>>>,
        ttl: u32,
        event: &Event,
        is_ipv6: bool,
    ) {
        log::info!("Received mDNS packet: {event:?}")
        // TODO
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
        let broadcast_interval = Duration::from_millis(self.broadcast_interval);
        let ttl = broadcast_interval.as_secs() as u32;
        let handle = thread::spawn(move || {
            // Create the IPv4 and IPv6 sockets to send multicast packets on:
            let (mut ipv4_socket, mut ipv6_socket) = Self::create_sockets().unwrap();

            // Create poll instance:
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(128);
            poll.registry().register(
                &mut ipv4_socket,
                Token(0),
                Interest::READABLE | Interest::WRITABLE
            ).unwrap();
            poll.registry().register(
                &mut ipv6_socket,
                Token(1),
                Interest::READABLE | Interest::WRITABLE
            ).unwrap();

            let mut last_broadcast = Instant::now().sub(broadcast_interval);

            // Enter main loop:
            loop {
                // Broadcast services:
                if last_broadcast.elapsed() > broadcast_interval {
                    Self::broadcast_services(
                        services.clone(),
                        ttl,
                        &ipv4_socket,
                        &ipv6_socket,
                    );
                    last_broadcast = Instant::now();
                }

                // Poll mDNS events:
                poll.poll(&mut events, Some(Duration::from_millis(500))).unwrap();
                for event in events.iter() {
                    match event.token() {
                        Token(0) => Self::respond_to_mdns(services.clone(), ttl, event, false),
                        Token(1) => Self::respond_to_mdns(services.clone(), ttl, event, true),
                        _ => unreachable!(),
                    }
                }

                // Check if the loop should exit:
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
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