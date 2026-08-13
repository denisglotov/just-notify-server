use libp2p::swarm::NetworkBehaviour;
use libp2p::{autonat, identify, kad, ping};

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub autonat: autonat::Behaviour,
}
