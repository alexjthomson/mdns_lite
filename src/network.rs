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
    },
    ops::Sub,
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
    time::{
        Duration,
        Instant,
    },
};

use mio::{
    event::Event, net::UdpSocket, Events, Interest, Poll, Token
};

use crate::{
    DnsType, MdnsPacket, MdnsService, MdnsServiceError, Response, TxtRecords
};

/// Convenience type for a thread-safe [`Vec<MdnsService>`].
pub type MdnsServices = Arc<Mutex<Vec<MdnsService>>>;

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
    /// This function parses mDNS packets received over the network and executes
    /// the specified function.
    /// network.
    pub fn tick<R, P>(&mut self, receive: R, mut process: P) -> Result<(), std::io::Error>
    where
        R: Fn(&Event, &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error>,
        P: FnMut(MdnsPacket, SocketAddr) -> Result<(), std::io::Error>,
    {
        self.poll.poll(&mut self.events, None)?;
        for event in self.events.iter() {
            let (received_bytes, src) = receive(event, &mut self.buffer)?;
            let packet = &self.buffer[..received_bytes];
            let packet = MdnsPacket::from_bytes(packet);
            process(packet, src)?;
        }
        Ok(())
    }
}

/// Internal mDNS broadcaster.
/// 
/// This is created by [`MdnsBroadcaster`] and is run on its own thread.
struct MdnsBroadcasterInternal {
    services: MdnsServices,
    device_ipv4: Option<Vec<u8>>,
    device_ipv6: Option<Vec<u8>>,
    socket_ipv4: UdpSocket,
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
    pub fn tick(&mut self) -> Result<(), std::io::Error> {
        self.listen()?;
        self.broadcast_services()?;
        Ok(())
    }

    fn listen(&mut self) -> Result<(), std::io::Error> {
        let mut responses = Vec::new();
        self.listener.tick(
            |event, buffer| {
                match event.token() {
                    MdnsListener::IPV4_POLL_TOKEN => self.socket_ipv4.recv_from(buffer),
                    MdnsListener::IPV6_POLL_TOKEN => self.socket_ipv6.recv_from(buffer),
                    _ => unreachable!(),
                }
            },
            |packet, _src| {
                let mut answers = Vec::new();

                // TODO: Populate answers here
                
                if !answers.is_empty() {
                    responses.push(MdnsPacket::new_response(
                        packet.transaction_id(),
                        answers,
                        Vec::new(),
                        Vec::new(),
                    ));
                }
                Ok(())
            },
        )?;
        for response in responses {
            self.broadcast(response)?;
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
            for service in services.iter() {
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