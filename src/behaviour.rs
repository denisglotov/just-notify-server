use libp2p::swarm::NetworkBehaviour;
use libp2p::{autonat, identify, kad, ping};
use libp2p_connection_limits as connection_limits;

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub autonat: autonat::Behaviour,
    pub connection_limits: connection_limits::Behaviour,
}
