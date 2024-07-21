//! # ESP mDNS - Network
//! This module manages the underlying network operations, such as socket
//! management and network interface configuration.

use std::{
    collections::HashMap, net::{
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
    }, time::{
        Duration,
        Instant,
    }
};

use mio::{
    event::Event,
    net::UdpSocket,
    Events,
    Interest,
    Poll,
    Token,
};
use thiserror::Error;

use crate::{
    DnsName, DnsType, MdnsPacket, MdnsService, MdnsServiceError, Query, Response, TxtRecords
};

/// Convenience type for a thread-safe set of [`MdnsService`]s.
pub type MdnsServices = Arc<Mutex<HashMap<DnsName, MdnsService>>>;
/// Listens for mDNS packets.
pub struct MdnsListener {
    poll: Poll,
    events: Events,
    buffer: Vec<u8>,
}

impl MdnsListener {
    /// [`Token`] that identifies that an event was received from the IPv4
    /// socket.
    pub const IPV4_POLL_TOKEN: Token = Token(0);

    /// [`Token`] that identifies that an event was received from the IPv6
    /// socket.
    pub const IPV6_POLL_TOKEN: Token = Token(1);

    /// Capacity of [`Self::events`].
    const POLL_EVENT_CAPACITY: usize = 128;

    /// Number of bytes in the [`Self::buffer`].
    const RECEIVE_BUFFER_SIZE: usize = 512;

    /// Timeout used when polling [`Self::poll`].
    const POLL_TIMEOUT: Option<Duration> = Some(Duration::from_millis(500));

    /// Creates a new [`MdnsListener`].
    pub fn new(socket_ipv4: &mut UdpSocket, socket_ipv6: &mut UdpSocket) -> Result<Self, std::io::Error> {
        let poll = Poll::new()?;
        let events = Events::with_capacity(Self::POLL_EVENT_CAPACITY);
        poll.registry().register(
            socket_ipv4,
            Self::IPV4_POLL_TOKEN,
            Interest::READABLE | Interest::WRITABLE,
        )?;
        poll.registry().register(
            socket_ipv6,
            Self::IPV6_POLL_TOKEN,
            Interest::READABLE | Interest::WRITABLE,
        )?;
        let buffer = Vec::with_capacity(Self::RECEIVE_BUFFER_SIZE);
        Ok(Self { poll, events, buffer })
    }

    /// Ticks the [`MdnsListener`].
    /// 
    /// This function parses mDNS packets received and returns them along with
    /// the address they were received from.
    /// 
    /// This function requires a receive function. This function should return
    /// the number of bytes read, and the address they were read from; otherwise
    /// it should return an [`std::io::Error`].
    pub fn tick<R>(&mut self, receive: R) -> Result<Vec<(SocketAddr, MdnsPacket)>, std::io::Error>
    where
        R: Fn(&Event, &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error>,
    {
        // Poll for events:
        self.poll.poll(&mut self.events, Self::POLL_TIMEOUT)?;
        
        // Create a vector for containing each of the response packets:
        let mut packets: Vec<(SocketAddr, MdnsPacket)> = Vec::new();

        // Iterate each of the events and try parse the mDNS packets:
        for event in self.events.iter() {
            // Receive the raw packet bytes:
            let (received_bytes, src) = receive(event, &mut self.buffer)?;
            let packet: &[u8] = &self.buffer[..received_bytes];

            // Try to parse the packet into an mDNS packet:
            match MdnsPacket::from_bytes(packet, &mut 0) {
                Ok(packet) => packets.push((src, packet)),
                Err(error) => log::error!("Received bad mDNS packet: {error}"),
            }
        }
        // Return the responses:
        Ok(packets)
    }
}

/// Describes errors that can occur while answering an mDNS query.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Error, Debug)]
pub enum MdnsAnswerError {
    #[error("Unknown mDNS query type: `{0}`.")]
    UnknownQueryType(u16),
}

/// Internal mDNS broadcaster.
/// 
/// This type contains all of the data for [`MdnsBroadcaster`]. The intention is
/// to allow this data to be accessed across multiple threads safely.
/// 
/// This is created by [`MdnsBroadcaster`] and is run on its own thread.
struct MdnsBroadcasterInternal {
    /// Contains each of the [`MdnsService`]s registered for the parent
    /// [`MdnsBroadcaster`].
    services: MdnsServices,
    /// Optional IPv4 address of the device that the [`MdnsBroadcaster`] is
    /// running on.
    device_ipv4: Option<Vec<u8>>,
    /// Optional IPv6 address of the device that the [`MdnsBroadcaster`] is
    /// running on.
    device_ipv6: Option<Vec<u8>>,
    /// IPv4 mDNS [`UdpSocket`].
    socket_ipv4: UdpSocket,
    /// IPv6 mDNS [`UdpSocket`].
    socket_ipv6: UdpSocket,
    /// Time-to-live for mDNS packets.
    ttl: u32,
    /// [`MdnsListener`] responsible for listening for [`MdnsPacket`]s over the
    /// network. These packets are then responded to by the
    /// [`MdnsBroadcasterInternal`].
    listener: MdnsListener,
    /// Time of the last mDNS broadcast.
    last_broadcast: Instant,
    /// Interval between mDNS broadcasts.
    broadcast_interval: Duration,
}

impl MdnsBroadcasterInternal {
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
    
    /// Creates a new [`MdnsBroadcasterInternal`] instance.
    pub fn new(
        services: MdnsServices,
        device_ipv4: Option<Vec<u8>>,
        device_ipv6: Option<Vec<u8>>,
        ttl: u32,
    ) -> Result<Self, std::io::Error> {
        // Create IPv4 socket:
        let mut socket_ipv4 = UdpSocket::bind(
            SocketAddr::V4(
                SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    0,
                )
            )
        )?;
        socket_ipv4.set_broadcast(true)?;
        socket_ipv4.set_multicast_loop_v4(true)?;
        socket_ipv4.join_multicast_v4(
            &Self::IPV4_MULTICAST_ADDRESS,
            &Ipv4Addr::UNSPECIFIED,
        )?;

        // Create IPv6 socket:
        let mut socket_ipv6 = UdpSocket::bind(
            SocketAddr::V6(
                SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    0,
                    0,
                    0,
                )
            )
        )?;
        socket_ipv6.set_broadcast(true)?;
        socket_ipv6.set_multicast_loop_v6(true)?;
        socket_ipv6.join_multicast_v6(
            &Self::IPV6_MULTICAST_ADDRESS,
            0,
        )?;

        // Create poll:
        let listener = MdnsListener::new(
            &mut socket_ipv4,
            &mut socket_ipv6,
        )?;

        // Construct and return the broadcaster:
        Ok(Self {
            services,
            device_ipv4,
            device_ipv6,
            socket_ipv4,
            socket_ipv6,
            ttl,
            listener,
            last_broadcast: Instant::now().sub(Duration::from_millis(ttl as u64)),
            broadcast_interval: Duration::from_millis(ttl as u64),
        })
    }

    /// Broadcasts an [`MdnsPacket`].
    /// 
    /// This function will broadcast the `packet` to both IPv4 and IPv6 mDNS.
    pub fn broadcast(&self, packet: MdnsPacket) -> Result<(), std::io::Error> {
        let packet = packet.to_bytes();
        self.socket_ipv4.send_to(
            &packet,
            Self::IPV4_MULTICAST_SOCKET_ADDRESS,
        )?;
        self.socket_ipv6.send_to(
            &packet,
            Self::IPV6_MULTICAST_SOCKET_ADDRESS,
        )?;
        Ok(())
    }

    /// Ticks the [`MdnsBroadcasterInternal`].
    /// 
    /// This should be called as often as possible.
    /// 
    /// This function ticks the mDNS packet listener and mDNS service
    /// announcement functionality of the [`MdnsBroadcasterInternal`].
    pub fn tick(&mut self) -> Result<(), std::io::Error> {
        self.listen()?;
        self.broadcast_services()?;
        Ok(())
    }

    /// Listens and responds to mDNS packets with questions about services
    /// registered within this [`MdnsBroadcasterInternal`].
    fn listen(&mut self) -> Result<(), std::io::Error> {
        // Tick the mDNS listener for mDNS packets:
        let packets = self.listener.tick(
            |event, buffer| {
                match event.token() {
                    MdnsListener::IPV4_POLL_TOKEN => self.socket_ipv4.recv_from(buffer),
                    MdnsListener::IPV6_POLL_TOKEN => self.socket_ipv6.recv_from(buffer),
                    _ => unreachable!(),
                }
            }
        )?;

        // Lock the mDNS services:
        let services = self.services.lock().unwrap();

        // Iterate each mDNS packet:
        for (src, packet) in packets {
            // Check if the packet contains any questions:
            if !packet.has_questions() {
                continue;
            }

            // Respond to each question in the packet:
            let questions = packet.questions();
            let mut answers: Vec<Response> = Vec::with_capacity(questions.len());
            for question in questions {
                // TODO: This needs redoing:
                // Questions may be asked about services; however, they may also
                // be asked about:
                // - The Host (this device). The question will contain the
                //   hostname (hostname.local).
                // - Service Types. For example, a PTR question could be asked
                //   about `_http._tcp.local`. In this case, we should respond
                //   with every service with that type.
                //
                // Currently this code only responds to questions about
                // services, which is only part of responding to mDNS questions.
                if let Some(service) = services.get(question.name()) {
                    match question.query_type() {
                        DnsType::A => {
                            if let Some(ipv4_address) = &self.device_ipv4 {
                                answers.push(
                                    Response::new_a(
                                        question.name().clone(),
                                        self.ttl,
                                        ipv4_address.clone(),
                                    )
                                );
                            }
                        },
                        DnsType::AAAA => {
                            if let Some(ipv6_address) = &self.device_ipv6 {
                                answers.push(
                                    Response::new_aaaa(
                                        question.name().clone(),
                                        self.ttl,
                                        ipv6_address.clone(),
                                    )
                                );
                            }
                        },
                        DnsType::TXT => {
                            match Response::new_txt(
                                question.name().clone(),
                                self.ttl,
                                service.records(),
                            ) {
                                Ok(response) => answers.push(response),
                                Err(error) => log::error!(
                                    "Failed to generate TXT response for service `{}`: {}",
                                    question.name(),
                                    error,
                                ),
                            }
                        },
                        DnsType::SRV => {
                            // TODO: Respond with a hostname and port for the
                            // service instance.
                        },
                        DnsType::ANY => {
                            // TODO: Respond with all available information
                            // about the service.
                        },
                        _ => continue,
                    }
                }
            }

            // Construct and broadcast the response packet:
            let response = MdnsPacket::new_response(
                packet.transaction_id(),
                answers,
                Vec::new(),
                Vec::new(),
            );
            if let Err(error) = self.broadcast(response) {
                log::error!("Failed to broadcast mDNS response: {error}");
            }
        }
        Ok(())
    }

    /// Attempts to broadcast the mDNS services.
    /// 
    /// This will only broadcast the services if the broadcast interval has expired.
    fn broadcast_services(&mut self) -> Result<(), std::io::Error> {
        if self.last_broadcast.elapsed() > self.broadcast_interval {
            let services = self.services.lock().unwrap();
            self.last_broadcast = Instant::now();
            for service in services.values() {
                self.broadcast_service(service)?;
            }
        }
        Ok(())
    }

    /// Broadcasts an [`MdnsService`].
    fn broadcast_service(&self, service: &MdnsService) -> Result<(), std::io::Error> {
        match service.to_service_announcement_packet(
            self.ttl,
            self.device_ipv4.as_ref(),
            self.device_ipv6.as_ref(),
        ) {
            Ok(packet) => self.broadcast(packet)?,
            Err(error) => log::error!(
                "Failed to create service announcement packet for service `{}`: {}",
                service.service_name(),
                error,
            ),
        }
        Ok(())
    }
}

pub struct MdnsBroadcaster {
    services: MdnsServices,
    /// Interval between broadcasts in milliseconds.
    broadcast_interval: u32,
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
            Self::DEFAULT_BROADCAST_INTERVAL,
        )
    }
}

impl MdnsBroadcaster {
    /// Default value for [`Self::broadcast_interval`].
    pub const DEFAULT_BROADCAST_INTERVAL: u32 = 60 * 1000;

    /// Creates a new empty [`MdnsBroadcaster`].
    #[inline]
    #[must_use]
    pub fn new(
        services: Vec<MdnsService>,
        broadcast_interval: u32,
    ) -> Self {
        Self {
            services: Arc::new(
                Mutex::new(
                    services
                        .into_iter()
                        .map(|service| (service.service_name(), service))
                        .collect()
                )
            ),
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
        services.insert(service.service_name(), service);
    }

    /// Starts the [`MdnsBroadcaster`].
    /// 
    /// If the broadcaster has already been started, this will do nothing.
    pub fn start(
        &mut self,
        device_ipv4: Option<Ipv4Addr>,
        device_ipv6: Option<Ipv6Addr>,
    ) {
        // Check if the broadcaster is currently running, if it is, stop here:
        if self.handle.is_some() {
            return;
        }

        // Reset the stop flag:
        self.stop_flag.store(false, Ordering::Relaxed);
        let stop_flag = self.stop_flag.clone();

        // Create the internal broadcaster:
        let mut broadcaster = MdnsBroadcasterInternal::new(
            self.services.clone(),
            device_ipv4.map(|ipv4| ipv4.octets().to_vec()),
            device_ipv6.map(|ipv6| ipv6.octets().to_vec()),
            self.broadcast_interval,
        ).unwrap();

        // Start the broadcaster thread:
        let handle = thread::spawn(move || {
            loop {
                if let Err(error) = broadcaster.tick() {
                    log::error!("mDNS tick error: {error}");
                }
                // Check if the loop should exit:
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
            }
        });

        // Assign the handle:
        self.handle = Some(handle);
    }

    /// Stops the [`MdnsBroadcaster`].
    pub fn stop(&mut self) {
        if self.handle.is_some() {
            self.stop_flag.store(true, Ordering::Relaxed);
        }
    }
}