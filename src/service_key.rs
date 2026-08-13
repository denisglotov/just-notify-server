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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_derive_service_multihash() {
        let (cid1, mh1) = derive_service_multihash("dymka-just-notify");
        let (cid2, mh2) = derive_service_multihash("dymka-just-notify");

        assert_eq!(cid1, cid2);
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
}
