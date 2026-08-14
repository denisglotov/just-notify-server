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
    addr.iter().find_map(|protocol| match protocol {
        libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    })
}

/// Extracts distinct IP addresses or hostnames from a collection of multiaddresses.
pub fn extract_ip_addresses(addrs: &[libp2p::Multiaddr]) -> Vec<String> {
    addrs
        .iter()
        .flat_map(|addr| addr.iter())
        .filter_map(|protocol| match protocol {
            libp2p::multiaddr::Protocol::Ip4(ip) => Some(ip.to_string()),
            libp2p::multiaddr::Protocol::Ip6(ip) => Some(ip.to_string()),
            libp2p::multiaddr::Protocol::Dns(dns)
            | libp2p::multiaddr::Protocol::Dns4(dns)
            | libp2p::multiaddr::Protocol::Dns6(dns)
            | libp2p::multiaddr::Protocol::Dnsaddr(dns) => Some(dns.to_string()),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Checks if an IPv4 address is globally routable on the public internet.
/// Filters out private (RFC 1918), loopback (127.0.0.0/8), link-local (169.254.0.0/16),
/// CGNAT / Shared address space (100.64.0.0/10), documentation, benchmarking, multicast, and broadcast/unspecified.
pub fn is_public_routable_ipv4(ip: &std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    // Unspecified (0.0.0.0) or Broadcast (255.255.255.255)
    if ip.is_unspecified() || ip.is_broadcast() {
        return false;
    }
    // Loopback 127.0.0.0/8
    if ip.is_loopback() {
        return false;
    }
    // Private RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if ip.is_private() {
        return false;
    }
    // Link-local 169.254.0.0/16
    if ip.is_link_local() {
        return false;
    }
    // Shared / CGNAT (RFC 6598): 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
    if octets[0] == 100 && (octets[1] & 0xc0) == 64 {
        return false;
    }
    // IETF Protocol Assignments: 192.0.0.0/24
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return false;
    }
    // Documentation (RFC 5737): 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if ip.is_documentation() {
        return false;
    }
    // Benchmarking (RFC 2544): 198.18.0.0/15 (198.18.0.0 - 198.19.255.255)
    if octets[0] == 198 && (octets[1] & 0xfe) == 18 {
        return false;
    }
    // Direct Multicast 224.0.0.0/4 and Reserved (RFC 1112) 240.0.0.0/4
    if ip.is_multicast() || octets[0] >= 240 {
        return false;
    }
    true
}

/// Checks if an IPv6 address is globally routable on the public internet.
/// Filters out unspecified (::), loopback (::1), unique local (fc00::/7),
/// link-local (fe80::/10), documentation (2001:db8::/32), and multicast (ff00::/8).
pub fn is_public_routable_ipv6(ip: &std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    // Unspecified (::)
    if ip.is_unspecified() {
        return false;
    }
    // Loopback (::1)
    if ip.is_loopback() {
        return false;
    }
    // Multicast ff00::/8
    if ip.is_multicast() {
        return false;
    }
    // Unique Local Address (ULA) fc00::/7
    if (octets[0] & 0xfe) == 0xfc {
        return false;
    }
    // Unicast Link-Local fe80::/10
    if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
        return false;
    }
    // Documentation 2001:db8::/32
    if octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8 {
        return false;
    }
    true
}

use anyhow::Context;

/// Normalizes an observed multiaddress from an Identify protocol message.
/// Ephemeral outgoing ports are replaced with the node's configured listening ports.
/// Only globally routable public IP addresses are accepted.
pub fn normalize_observed_address(
    observed: &libp2p::Multiaddr,
    tcp_port: u16,
    quic_port: u16,
) -> Option<libp2p::Multiaddr> {
    use libp2p::multiaddr::Protocol;

    let mut host_protocol = None;
    let mut is_quic = false;
    let mut is_tcp = false;

    for proto in observed.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                if is_public_routable_ipv4(&ip) {
                    host_protocol = Some(Protocol::Ip4(ip));
                }
            }
            Protocol::Ip6(ip) => {
                if is_public_routable_ipv6(&ip) {
                    host_protocol = Some(Protocol::Ip6(ip));
                }
            }
            Protocol::Dns(dns) if dns != "localhost" && dns.contains('.') => {
                host_protocol = Some(Protocol::Dns(dns));
            }
            Protocol::Dns4(dns) if dns != "localhost" && dns.contains('.') => {
                host_protocol = Some(Protocol::Dns4(dns));
            }
            Protocol::Dns6(dns) if dns != "localhost" && dns.contains('.') => {
                host_protocol = Some(Protocol::Dns6(dns));
            }
            Protocol::Dnsaddr(dns) if dns != "localhost" && dns.contains('.') => {
                host_protocol = Some(Protocol::Dnsaddr(dns));
            }
            Protocol::QuicV1 => {
                is_quic = true;
            }
            Protocol::Tcp(_) => {
                is_tcp = true;
            }
            _ => {}
        }
    }

    let host = host_protocol?;
    let mut normalized = libp2p::Multiaddr::empty();
    normalized.push(host);

    if is_quic {
        normalized.push(Protocol::Udp(quic_port));
        normalized.push(Protocol::QuicV1);
        Some(normalized)
    } else if is_tcp {
        normalized.push(Protocol::Tcp(tcp_port));
        Some(normalized)
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
    fn test_normalize_observed_address_ipv6() {
        let observed: libp2p::Multiaddr = "/ip6/2600:1900::1/tcp/54358".parse().unwrap();
        let normalized = normalize_observed_address(&observed, 4001, 4001).unwrap();
        assert_eq!(normalized.to_string(), "/ip6/2600:1900::1/tcp/4001");
    }

    #[test]
    fn test_normalize_observed_address_dns_protocols() {
        let obs_dns4: libp2p::Multiaddr = "/dns4/bootstrap.libp2p.io/tcp/54358".parse().unwrap();
        assert_eq!(
            normalize_observed_address(&obs_dns4, 4001, 4001)
                .unwrap()
                .to_string(),
            "/dns4/bootstrap.libp2p.io/tcp/4001"
        );

        let obs_dns6: libp2p::Multiaddr = "/dns6/bootstrap.libp2p.io/udp/1234/quic-v1"
            .parse()
            .unwrap();
        assert_eq!(
            normalize_observed_address(&obs_dns6, 4001, 4002)
                .unwrap()
                .to_string(),
            "/dns6/bootstrap.libp2p.io/udp/4002/quic-v1"
        );

        let obs_dnsaddr: libp2p::Multiaddr =
            "/dnsaddr/bootstrap.libp2p.io/tcp/9999".parse().unwrap();
        assert_eq!(
            normalize_observed_address(&obs_dnsaddr, 4001, 4001)
                .unwrap()
                .to_string(),
            "/dnsaddr/bootstrap.libp2p.io/tcp/4001"
        );
    }

    #[test]
    fn test_is_public_routable_ipv4() {
        use std::net::Ipv4Addr;

        // Valid public IPs
        assert!(is_public_routable_ipv4(&Ipv4Addr::new(136, 169, 50, 80)));
        assert!(is_public_routable_ipv4(&Ipv4Addr::new(172, 238, 169, 224)));
        assert!(is_public_routable_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_public_routable_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));

        // Private RFC 1918
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(10, 60, 7, 102)));
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(192, 168, 50, 156)));

        // Loopback / Link-local / Unspecified / Broadcast
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(255, 255, 255, 255)));

        // CGNAT (100.64.0.0/10)
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(100, 127, 255, 254)));
        // 100.128.0.1 is outside CGNAT range
        assert!(is_public_routable_ipv4(&Ipv4Addr::new(100, 128, 0, 1)));

        // Documentation / Multicast
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(224, 0, 0, 1)));
        assert!(!is_public_routable_ipv4(&Ipv4Addr::new(240, 0, 0, 1)));
    }

    #[test]
    fn test_normalize_observed_address_rejects_private() {
        // Private 10.x IP (like the observed 10.60.7.102)
        let observed_10: libp2p::Multiaddr = "/ip4/10.60.7.102/tcp/54321".parse().unwrap();
        assert!(normalize_observed_address(&observed_10, 4001, 4001).is_none());

        // Private 192.168.x IP
        let observed_192: libp2p::Multiaddr = "/ip4/192.168.50.156/tcp/4001".parse().unwrap();
        assert!(normalize_observed_address(&observed_192, 4001, 4001).is_none());

        // Loopback
        let observed_loopback: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        assert!(normalize_observed_address(&observed_loopback, 4001, 4001).is_none());

        // CGNAT
        let observed_cgnat: libp2p::Multiaddr = "/ip4/100.64.1.2/tcp/4001".parse().unwrap();
        assert!(normalize_observed_address(&observed_cgnat, 4001, 4001).is_none());
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
