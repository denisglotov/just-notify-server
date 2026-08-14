use cid::Cid;
use multihash::Multihash;
use sha2::{Digest, Sha256};
use std::str::FromStr;

/// Derives a deterministic Multihash and CID from a service name or CID string.
/// If the input string is already a valid CID, it returns the parsed CID and its multihash.
/// Otherwise, it computes SHA-256 of the input string and constructs a Raw multihash/CID.
pub fn derive_service_multihash(input: &str) -> (Cid, Multihash<64>) {
    if let Ok(cid) = Cid::from_str(input) {
        let hash = *cid.hash();
        // Convert to Multihash<64> if possible
        if let Ok(mhash) = Multihash::<64>::from_bytes(&hash.to_bytes()) {
            return (cid, mhash);
        }
    }

    // Otherwise compute SHA-256 digest of string
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();

    // Multihash code for SHA2-256 is 0x12
    let mhash =
        Multihash::<64>::wrap(0x12, &digest).expect("SHA256 multihash digest fits in 64 bytes");

    // CIDv1 with Raw codec (0x55)
    let cid = Cid::new_v1(0x55, mhash);

    (cid, mhash)
}

/// Extracts a PeerId from a multiaddress if it contains a /p2p/<peer_id> component.
pub fn extract_peer_id(addr: &libp2p::Multiaddr) -> Option<libp2p::PeerId> {
    for protocol in addr.iter() {
        if let libp2p::multiaddr::Protocol::P2p(peer_id) = protocol {
            return Some(peer_id);
        }
    }
    None
}

/// Extracts distinct IP addresses or hostnames from a collection of multiaddresses.
pub fn extract_ip_addresses(addrs: &[libp2p::Multiaddr]) -> Vec<String> {
    let mut ips = std::collections::HashSet::new();
    for addr in addrs {
        for protocol in addr.iter() {
            match protocol {
                libp2p::multiaddr::Protocol::Ip4(ip) => {
                    ips.insert(ip.to_string());
                }
                libp2p::multiaddr::Protocol::Ip6(ip) => {
                    ips.insert(ip.to_string());
                }
                libp2p::multiaddr::Protocol::Dns(dns)
                | libp2p::multiaddr::Protocol::Dns4(dns)
                | libp2p::multiaddr::Protocol::Dns6(dns)
                | libp2p::multiaddr::Protocol::Dnsaddr(dns) => {
                    ips.insert(dns.to_string());
                }
                _ => {}
            }
        }
    }
    let mut ip_list: Vec<String> = ips.into_iter().collect();
    ip_list.sort();
    ip_list
}

use anyhow::Context;

/// Normalizes an observed multiaddress from an Identify protocol message.
/// Ephemeral outgoing ports are replaced with the node's configured listening ports.
pub fn normalize_observed_address(
    observed: &libp2p::Multiaddr,
    tcp_port: u16,
    quic_port: u16,
) -> Option<libp2p::Multiaddr> {
    let mut ip_part = None;
    let mut is_quic = false;
    let mut is_tcp = false;

    for proto in observed.iter() {
        match proto {
            libp2p::multiaddr::Protocol::Ip4(ip) => {
                if !ip.is_unspecified() && !ip.is_broadcast() {
                    ip_part = Some(format!("/ip4/{}", ip));
                }
            }
            libp2p::multiaddr::Protocol::Ip6(ip) => {
                if !ip.is_unspecified() {
                    ip_part = Some(format!("/ip6/{}", ip));
                }
            }
            libp2p::multiaddr::Protocol::Dns(dns)
            | libp2p::multiaddr::Protocol::Dns4(dns)
            | libp2p::multiaddr::Protocol::Dns6(dns)
            | libp2p::multiaddr::Protocol::Dnsaddr(dns) => {
                ip_part = Some(format!("/dns4/{}", dns));
            }
            libp2p::multiaddr::Protocol::QuicV1 => {
                is_quic = true;
            }
            libp2p::multiaddr::Protocol::Tcp(_) => {
                is_tcp = true;
            }
            _ => {}
        }
    }

    let base = ip_part?;
    if is_quic {
        format!("{}/udp/{}/quic-v1", base, quic_port).parse().ok()
    } else if is_tcp {
        format!("{}/tcp/{}", base, tcp_port).parse().ok()
    } else {
        None
    }
}

/// Loads a keypair from a file if it exists, or generates a new ed25519 keypair and saves it.
/// If no path is provided, a new in-memory ed25519 keypair is generated.
pub fn load_or_generate_keypair(
    key_path: Option<&std::path::Path>,
) -> anyhow::Result<libp2p::identity::Keypair> {
    if let Some(path) = key_path {
        if path.exists() {
            let bytes = std::fs::read(path)
                .with_context(|| format!("Failed to read keypair file at '{}'", path.display()))?;
            let keypair =
                libp2p::identity::Keypair::from_protobuf_encoding(&bytes).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to decode keypair from '{}': {:?}",
                        path.display(),
                        e
                    )
                })?;
            return Ok(keypair);
        }

        let keypair = libp2p::identity::Keypair::generate_ed25519();
        if let Ok(bytes) = keypair.to_protobuf_encoding() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(path, &bytes)
                .with_context(|| format!("Failed to save keypair file to '{}'", path.display()))?;
        }
        Ok(keypair)
    } else {
        Ok(libp2p::identity::Keypair::generate_ed25519())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_derive_service_multihash() {
        let (cid1, mh1) = derive_service_multihash("org.dymka.just-notify-server");
        let (cid2, mh2) = derive_service_multihash("org.dymka.just-notify-server");

        assert_eq!(cid1, cid2);
        assert_eq!(
            cid1.to_string(),
            "bafkreic62cvyvkn5knp2gujymlpzd3y4brmdqlw42n52lt522an2xapsne"
        );
        assert_eq!(mh1, mh2);
        assert_eq!(mh1.code(), 0x12);
    }

    #[test]
    fn test_valid_cid_passthrough() {
        let cid_str = "bafybeicg253nyacwgahb3h4q6tx5v23e6qyr2m4eecw6srm6f3r7w3m2py";
        let (cid, _mh) = derive_service_multihash(cid_str);
        assert_eq!(cid.to_string(), cid_str);
    }

    #[test]
    fn test_extract_peer_id() {
        let addr_str =
            "/ip4/147.75.109.213/tcp/4001/p2p/QmNnooDu7bfjPFoTmdxMNeaVQEBTbkV4Ddbdb415D9x5D4";
        let addr = libp2p::Multiaddr::from_str(addr_str).unwrap();
        let peer_id = extract_peer_id(&addr).unwrap();
        assert_eq!(
            peer_id.to_string(),
            "QmNnooDu7bfjPFoTmdxMNeaVQEBTbkV4Ddbdb415D9x5D4"
        );
    }

    #[test]
    fn test_extract_ip_addresses() {
        let addr1: libp2p::Multiaddr = "/ip4/192.168.1.100/tcp/4001".parse().unwrap();
        let addr2: libp2p::Multiaddr = "/ip4/192.168.1.100/udp/4001/quic-v1".parse().unwrap();
        let addr3: libp2p::Multiaddr = "/ip4/10.0.0.1/tcp/4001".parse().unwrap();
        let addr4: libp2p::Multiaddr = "/dns4/ny5.bootstrap.libp2p.io/tcp/4001".parse().unwrap();

        let ips = extract_ip_addresses(&[addr1, addr2, addr3, addr4]);
        assert_eq!(
            ips,
            vec![
                "10.0.0.1".to_string(),
                "192.168.1.100".to_string(),
                "ny5.bootstrap.libp2p.io".to_string()
            ]
        );
    }

    #[test]
    fn test_normalize_observed_address_tcp() {
        let observed: libp2p::Multiaddr = "/ip4/136.169.50.80/tcp/54358".parse().unwrap();
        let normalized = normalize_observed_address(&observed, 4001, 4001).unwrap();
        assert_eq!(normalized.to_string(), "/ip4/136.169.50.80/tcp/4001");
    }

    #[test]
    fn test_normalize_observed_address_quic() {
        let observed: libp2p::Multiaddr = "/ip4/136.169.50.80/udp/1027/quic-v1".parse().unwrap();
        let normalized = normalize_observed_address(&observed, 4001, 4002).unwrap();
        assert_eq!(
            normalized.to_string(),
            "/ip4/136.169.50.80/udp/4002/quic-v1"
        );
    }

    #[test]
    fn test_keypair_persistence() {
        let temp_dir = std::env::temp_dir();
        let key_file = temp_dir.join(format!(
            "test_key_{}.key",
            std::time::SystemTime::now().elapsed().unwrap().as_nanos()
        ));

        let kp1 = load_or_generate_keypair(Some(&key_file)).unwrap();
        let peer_id1 = libp2p::PeerId::from(kp1.public());

        let kp2 = load_or_generate_keypair(Some(&key_file)).unwrap();
        let peer_id2 = libp2p::PeerId::from(kp2.public());

        assert_eq!(peer_id1, peer_id2);

        let _ = std::fs::remove_file(&key_file);
    }
}
