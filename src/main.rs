use std::{
    collections::HashSet,
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use cfg_if::cfg_if;
use clap::Parser;
use futures::StreamExt;
use hex::FromHex;
use libp2p::{
    PeerId, Swarm, SwarmBuilder, autonat,
    core::{Multiaddr, multiaddr::Protocol},
    identify,
    identity::Keypair,
    noise, ping, relay, rendezvous,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use rand::rngs::OsRng;
use tokio::{signal, task::JoinHandle};

#[derive(Parser)]
struct Opt {
    /// Secret key for the server (64 hex characters for 32 bytes).
    #[clap(long = "secret-key", help = "Secret key as 64 hex characters")]
    secret_key: String,
    /// Port to listen on.
    #[clap(long = "listen-port", help = "Port to listen on", default_value = "34404")]
    listen_port: u16,
    /// Use IPv6 for listening.
    #[arg(long = "use-ipv6", help = "Listen on IPv6 interfaces")]
    use_ipv6: bool,
    /// Maximum time a circuit relay connection can exist.
    #[arg(long = "max-circuit-duration", help = "Maximum circuit duration in seconds", default_value = "7200")]
    max_circuit_duration: u64,
    /// Maximum data that can be transferred through a circuit.
    #[arg(long = "max-circuit-bytes", help = "Maximum circuit data transfer in bytes", default_value = "10485760")]
    max_circuit_bytes: u64,
    /// Enable logging of detailed protocol information.
    #[arg(long = "verbose", help = "Enable verbose protocol logging")]
    verbose: bool,
}

#[derive(NetworkBehaviour)]
struct ServerBehaviour {
    autonat: autonat::v2::server::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    rendezvous: rendezvous::server::Behaviour,
    relay: relay::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    cfg_if! {
        if #[cfg(feature = "jaeger")] {
            use tracing_subscriber::layer::SubscriberExt;
            use opentelemetry_sdk::runtime::Tokio;
            let tracer = opentelemetry_jaeger::new_agent_pipeline()
                .with_endpoint("jaeger:34401")
                .with_service_name("autonatv2")
                .install_batch(Tokio)?;
            let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
            let subscriber = tracing_subscriber::Registry::default()
                .with(telemetry);
        } else {
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .finish();
        }
    }

    tracing::subscriber::set_global_default(subscriber).expect("Setting default subscriber failed");

    let opt: Opt = Opt::parse();
    let secret_key_bytes: [u8; 32] = <[u8; 32]>::from_hex(&opt.secret_key).expect("Secret key must be 32 bytes (64 hex characters)");
    let keypair: Keypair = Keypair::ed25519_from_bytes(secret_key_bytes).unwrap();
    let identify_config: identify::Config = identify::Config::new("rendezvous/1.0.0".to_string(), keypair.clone().public());
    let relay_config: relay::Config = relay::Config {
        max_circuit_duration: Duration::from_secs(opt.max_circuit_duration),
        max_circuit_bytes: opt.max_circuit_bytes,
        ..Default::default()
    };
    let mut swarm: Swarm<ServerBehaviour> = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_behaviour(|key| ServerBehaviour {
            autonat: autonat::v2::server::Behaviour::new(OsRng),
            identify: identify::Behaviour::new(identify_config.with_agent_version("rust-libp2p/0.55.0".to_string())),
            ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_millis(3_000))),
            rendezvous: rendezvous::server::Behaviour::new(rendezvous::server::Config::default()),
            relay: relay::Behaviour::new(key.public().to_peer_id(), relay_config),
        })?
        .build();
    // Listen on all interfaces.
    let tcp_multiaddr: Multiaddr = Multiaddr::empty()
        .with(if opt.use_ipv6 {
            Protocol::from(Ipv6Addr::UNSPECIFIED)
        } else {
            Protocol::from(Ipv4Addr::UNSPECIFIED)
        })
        .with(Protocol::Tcp(opt.listen_port));
    let udp_multiaddr: Multiaddr = Multiaddr::empty()
        .with(if opt.use_ipv6 {
            Protocol::from(Ipv6Addr::UNSPECIFIED)
        } else {
            Protocol::from(Ipv4Addr::UNSPECIFIED)
        })
        .with(Protocol::Udp(opt.listen_port))
        .with(Protocol::QuicV1);

    swarm.listen_on(tcp_multiaddr).unwrap();
    swarm.listen_on(udp_multiaddr).unwrap();

    // Tracking information.
    let mut active_circuits: u32 = 0u32;
    let mut active_peers: HashSet<PeerId> = HashSet::new();

    let swarm_handle: JoinHandle<()> = tokio::spawn(async move {
        while let Some(event) = swarm.next().await {
            match event {
                SwarmEvent::NewListenAddr { address, .. } => tracing::info!(address=%address),
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    active_peers.insert(peer_id);
                    tracing::info!("Connection established with {} via {:?} (total peers: {})", peer_id, endpoint, active_peers.len());
                }
                SwarmEvent::IncomingConnectionError {
                    local_addr,
                    send_back_addr,
                    error,
                    ..
                } => {
                    tracing::warn!("Incoming connection error from {} to {}: {}", send_back_addr, local_addr, error);
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Autonat(autonat::v2::server::Event {
                    tested_addr,
                    data_amount,
                    result,
                    ..
                })) => tracing::info!("Autonat-v2 dial request result for {} with {} status {:?}", tested_addr, data_amount, result.unwrap()),
                SwarmEvent::Behaviour(ServerBehaviourEvent::Rendezvous(rendezvous::server::Event::PeerRegistered { peer, registration })) => {
                    tracing::info!(
                        "{} registered for namespace '{}' for the next {} seconds",
                        peer,
                        registration.namespace,
                        registration.ttl
                    );
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Rendezvous(rendezvous::server::Event::DiscoverServed { enquirer, registrations })) => {
                    tracing::info!("Served peer {} with {} registrations", enquirer, registrations.len());
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Relay(relay::Event::ReservationReqAccepted { src_peer_id, .. })) => {
                    tracing::info!("Relay reservation accepted for {}", src_peer_id);
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Relay(relay::Event::ReservationReqDenied { src_peer_id, .. })) => {
                    tracing::warn!("Relay reservation denied for {}", src_peer_id);
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Relay(relay::Event::CircuitReqDenied { src_peer_id, dst_peer_id, .. })) => {
                    tracing::warn!("Circuit request denied from {} to {}", src_peer_id, dst_peer_id);
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Relay(relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. })) => {
                    active_circuits = active_circuits.saturating_add(1);
                    tracing::info!("Circuit established from {} to {} (active circuits: {})", src_peer_id, dst_peer_id, active_circuits);
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Relay(relay::Event::CircuitClosed { src_peer_id, dst_peer_id, .. })) => {
                    if active_circuits > 0 {
                        active_circuits = active_circuits.saturating_sub(1);
                    }
                    tracing::info!("Circuit closed between {} and {} (active circuits: {})", src_peer_id, dst_peer_id, active_circuits);
                }
                SwarmEvent::Behaviour(event) => {
                    if let ServerBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) = &event {
                        tracing::debug!("Identified peer {} as {} with address: {}", peer_id, info.agent_version, info.observed_addr);
                        swarm.add_external_address(info.observed_addr.clone());
                    }
                    if opt.verbose {
                        tracing::debug!("Behaviour event: {:?}", event);
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    if let Some(peer) = peer_id {
                        tracing::warn!("Failed to connect to {}: {}", peer, error);
                    } else {
                        tracing::warn!("Failed outgoing connection: {}", error);
                    }
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    active_peers.remove(&peer_id);
                    tracing::info!("Connection closed with {} (total peers: {})", peer_id, active_peers.len());
                }
                other => {
                    if opt.verbose {
                        tracing::debug!("Other event: {:?}", other);
                    }
                }
            }
        }
    });

    // Start listening for Ctrl+C signal in a separate task.
    let shutdown_handle = async {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        tracing::info!("Shutdown initiated, shutting down...");
    };

    tokio::select! {
        _ = swarm_handle => {}
        _ = shutdown_handle  => {
            tracing::info!(".");
        },
    }

    return Ok(());
}
