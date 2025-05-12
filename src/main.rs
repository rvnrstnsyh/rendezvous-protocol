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
    gossipsub::{self, Message, MessageId},
    identify,
    identity::Keypair,
    mdns, noise, ping, relay, rendezvous,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use rand::rngs::OsRng;
use tokio::{io, signal, task::JoinHandle};

#[derive(Parser)]
struct Opt {
    /// Secret key for the server (64 hex characters for 32 bytes).
    #[clap(long = "secret-key", help = "Secret key as 64 hex characters", default_value = "")]
    secret_key: String,
    /// Gossipsub topic.
    #[clap(long = "gossipsub-topic", help = "Gossipsub topic", default_value = "nvll-rendezvous-protocol")]
    gossipsub_topic: String,
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
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
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
    let mut keypair: Keypair = Keypair::generate_ed25519();

    if !opt.secret_key.is_empty() {
        keypair = Keypair::ed25519_from_bytes(<[u8; 32]>::from_hex(&opt.secret_key).expect("Secret key must be 32 bytes (64 hex characters)"))?;
    }

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
            gossipsub: gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(10))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(|message: &Message| {
                        // peer_id + sequence_number + message -> message_id.
                        MessageId::from(
                            blake3::hash(
                                format!(
                                    "{}{}{}",
                                    message
                                        .source
                                        .as_ref()
                                        .map(|peer_id| peer_id.to_base58())
                                        .unwrap_or_else(|| PeerId::from_bytes(&[0, 1, 0]).unwrap().to_base58()),
                                    message.sequence_number.unwrap_or_default(),
                                    blake3::hash(&message.data).to_hex()
                                )
                                .as_bytes(),
                            )
                            .as_bytes()
                            .to_vec(),
                        )
                    })
                    .build()
                    .map_err(io::Error::other)
                    .expect("Failed to create gossipsub config"),
            )
            .expect("Failed to create gossipsub behaviour"),
            mdns: mdns::Behaviour::new(mdns::Config::default(), key.public().to_peer_id()).expect("Failed to create mdns behaviour"),
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

    // Subscribe to static gossipsub topic.
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&gossipsub::IdentTopic::new(opt.gossipsub_topic))
        .expect("Failed to subscribe to gossipsub topic");
    swarm.listen_on(tcp_multiaddr).unwrap();
    swarm.listen_on(udp_multiaddr).unwrap();

    // Tracking information.
    let mut active_circuits: u32 = 0u32;
    let mut active_peers: HashSet<PeerId> = HashSet::new();

    let swarm_handle: JoinHandle<()> = tokio::spawn(async move {
        while let Some(event) = swarm.next().await {
            match event {
                SwarmEvent::NewListenAddr { address, .. } => tracing::info!(address=%address),
                SwarmEvent::Behaviour(ServerBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    ..
                })) => tracing::info!("propagating gossip with id {id} from peer {peer_id}"),
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    active_peers.insert(peer_id);
                    tracing::info!("connection established with {} via {:?} (total peers: {})", peer_id, endpoint, active_peers.len());
                }
                SwarmEvent::IncomingConnectionError {
                    local_addr,
                    send_back_addr,
                    error,
                    ..
                } => {
                    tracing::warn!("incoming connection error from {} to {}: {}", send_back_addr, local_addr, error);
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Autonat(autonat::v2::server::Event {
                    tested_addr,
                    data_amount,
                    result,
                    ..
                })) => tracing::info!("autonat-v2 dial request result for {} with {} status {:?}", tested_addr, data_amount, result.unwrap()),
                SwarmEvent::Behaviour(ServerBehaviourEvent::Rendezvous(rendezvous::server::Event::PeerRegistered { peer, registration })) => {
                    tracing::info!(
                        "{} registered for namespace '{}' for the next {} seconds",
                        peer,
                        registration.namespace,
                        registration.ttl
                    );
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Rendezvous(rendezvous::server::Event::DiscoverServed { enquirer, registrations })) => {
                    tracing::info!("served peer {} with {} registrations", enquirer, registrations.len());
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Relay(relay::Event::ReservationReqAccepted { src_peer_id, .. })) => {
                    tracing::info!("relay reservation accepted for {}", src_peer_id);
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Relay(relay::Event::ReservationReqDenied { src_peer_id, .. })) => {
                    tracing::warn!("relay reservation denied for {}", src_peer_id);
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Relay(relay::Event::CircuitReqDenied { src_peer_id, dst_peer_id, .. })) => {
                    tracing::warn!("circuit request denied from {} to {}", src_peer_id, dst_peer_id);
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Relay(relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. })) => {
                    active_circuits = active_circuits.saturating_add(1);
                    tracing::info!("circuit established from {} to {} (active circuits: {})", src_peer_id, dst_peer_id, active_circuits);
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Relay(relay::Event::CircuitClosed { src_peer_id, dst_peer_id, .. })) => {
                    if active_circuits > 0 {
                        active_circuits = active_circuits.saturating_sub(1);
                    }
                    tracing::info!("circuit closed between {} and {} (active circuits: {})", src_peer_id, dst_peer_id, active_circuits);
                }
                SwarmEvent::Behaviour(ServerBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                }
                SwarmEvent::Behaviour(event) => {
                    if let ServerBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) = &event {
                        tracing::debug!("identified peer {} as {} with address: {}", peer_id, info.agent_version, info.observed_addr);
                        swarm.add_external_address(info.observed_addr.clone());
                    }
                    if opt.verbose {
                        tracing::debug!("behaviour event: {:?}", event);
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    if let Some(peer) = peer_id {
                        tracing::warn!("failed to connect to {}: {}", peer, error);
                    } else {
                        tracing::warn!("failed outgoing connection: {}", error);
                    }
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    active_peers.remove(&peer_id);
                    tracing::info!("connection closed with {} (total peers: {})", peer_id, active_peers.len());
                }
                other => {
                    if opt.verbose {
                        tracing::debug!("other event: {:?}", other);
                    }
                }
            }
        }
    });

    // Start listening for Ctrl+C signal in a separate task.
    let shutdown_handle = async {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        tracing::info!("shutdown initiated, shutting down...");
    };

    tokio::select! {
        _ = swarm_handle => {}
        _ = shutdown_handle  => {
            tracing::info!(".");
        },
    }

    return Ok(());
}
