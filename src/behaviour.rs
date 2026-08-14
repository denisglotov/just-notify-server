use libp2p::swarm::NetworkBehaviour;
use libp2p::{autonat, identify, kad, ping};
use libp2p_connection_limits as connection_limits;

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    /// Connection limits MUST be defined first. The `#[derive(NetworkBehaviour)]` macro executes
    /// connection hooks (`handle_established_*_connection`) top-to-bottom with short-circuiting (`?`).
    /// Placing limits first ensures rejected connections (`ConnectionDenied`) fail immediately before
    /// downstream stateful behaviours (like AutoNAT / Request-Response) register unestablished connections
    /// in their internal tracking tables.
    pub connection_limits: connection_limits::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub autonat: autonat::Behaviour,
}
