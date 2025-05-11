use std::{error::Error, time::Duration};

use clap::Parser;
use futures::StreamExt;
use hex::FromHex;
use libp2p::{
    Swarm, SwarmBuilder, identify,
    identity::Keypair,
    noise, ping,
    rendezvous::server,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Opt {
    #[clap(long = "secret-key")]
    secret_key: String,
}

#[derive(NetworkBehaviour)]
struct RendezvousBehaviour {
    identify: identify::Behaviour,
    rendezvous: server::Behaviour,
    ping: ping::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    let opt: Opt = Opt::parse();
    let secret_key_bytes: [u8; 32] = <[u8; 32]>::from_hex(&opt.secret_key).expect("Secret key must be 32 bytes (64 hex characters)");
    let keypair: Keypair = Keypair::ed25519_from_bytes(secret_key_bytes).unwrap();
    let identify_config: identify::Config = identify::Config::new("rendezvous/1.0.0".to_string(), keypair.clone().public());
    let mut swarm: Swarm<RendezvousBehaviour> = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_behaviour(|_key| RendezvousBehaviour {
            identify: identify::Behaviour::new(identify_config.with_agent_version("rust-libp2p/0.55.0".to_string())),
            ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_millis(3_000))),
            rendezvous: server::Behaviour::new(server::Config::default()),
        })?
        .build();
    // Listen on all interfaces and whatever port the OS assigns.
    let _ = swarm.listen_on("/ip4/0.0.0.0/tcp/34404".parse().unwrap());
    let _ = swarm.listen_on("/ip4/0.0.0.0/udp/34404/quic-v1".parse().unwrap());

    while let Some(event) = swarm.next().await {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                tracing::info!("Dialed by {}", peer_id);
            }
            SwarmEvent::Behaviour(RendezvousBehaviourEvent::Rendezvous(server::Event::PeerRegistered { peer, registration })) => {
                tracing::info!("{} registered for namespace '{}' for the next {}", peer, registration.namespace, registration.ttl);
            }
            SwarmEvent::Behaviour(RendezvousBehaviourEvent::Rendezvous(server::Event::DiscoverServed { enquirer, registrations })) => {
                tracing::info!("Served peer {} with {} registrations", enquirer, registrations.len());
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                tracing::info!("Disconnected from {}", peer_id);
            }
            other => {
                tracing::debug!("Unhandled {:?}", other);
            }
        }
    }
    return Ok(());
}
