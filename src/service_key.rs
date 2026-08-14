use anyhow::Context;
use cid::Cid;
use multihash::Multihash;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::str::FromStr;

pub const SHA2_256_CODE: u64 = 0x12;
pub const RAW_CODEC: u64 = 0x55;

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
    let digest = Sha256::digest(input.as_bytes());

    let mhash = Multihash::<64>::wrap(SHA2_256_CODE, &digest)
        .expect("SHA256 multihash digest fits in 64 bytes");

    let cid = Cid::new_v1(RAW_CODEC, mhash);

    (cid, mhash)
}

/// Extracts a PeerId from a multiaddress if it contains a /p2p/<peer_id> component.
pub fn extract_peer_id(addr: &libp2p::Multiaddr) -> Option<libp2p::PeerId> {
    addr.iter().find_map(|protocol| match protocol {
        libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    })
}

#[inline]
fn is_valid_public_dns(dns: &str) -> bool {
    dns != "localhost" && dns.contains('.')
}

/// Checks if an IPv4 address is globally routable on the public internet.
/// Filters out private (RFC 1918), loopback (127.0.0.0/8), link-local (169.254.0.0/16),
/// CGNAT / Shared address space (100.64.0.0/10), documentation, benchmarking, multicast, and broadcast/unspecified.
pub fn is_public_routable_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let [o0, o1, o2, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_documentation()
        || ip.is_multicast()
        || (o0 == 100 && (o1 & 0xc0) == 64)       // Shared / CGNAT (RFC 6598): 100.64.0.0/10
        || (o0 == 192 && o1 == 0 && o2 == 0)      // IETF Protocol Assignments: 192.0.0.0/24
        || (o0 == 198 && (o1 & 0xfe) == 18)      // Benchmarking (RFC 2544): 198.18.0.0/15
        || o0 >= 240) // Reserved (RFC 1112) 240.0.0.0/4
}

/// Checks if an IPv6 address is globally routable on the public internet.
/// Filters out unspecified (::), loopback (::1), unique local (fc00::/7),
/// link-local (fe80::/10), documentation (2001:db8::/32), and multicast (ff00::/8).
pub fn is_public_routable_ipv6(ip: &std::net::Ipv6Addr) -> bool {
    let [s0, s1, s2, s3, ..] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s0 & 0xfe) == 0xfc                     // Unique Local Address (ULA) fc00::/7
        || (s0 == 0xfe && (s1 & 0xc0) == 0x80)    // Unicast Link-Local fe80::/10
        || (s0 == 0x20 && s1 == 0x01 && s2 == 0x0d && s3 == 0xb8)) // Documentation 2001:db8::/32
}

fn is_public_host(proto: &libp2p::multiaddr::Protocol) -> bool {
    use libp2p::multiaddr::Protocol;
    match proto {
        Protocol::Ip4(ip) => is_public_routable_ipv4(*ip),
        Protocol::Ip6(ip) => is_public_routable_ipv6(ip),
        Protocol::Dns(dns) | Protocol::Dns4(dns) | Protocol::Dns6(dns) | Protocol::Dnsaddr(dns) => {
            is_valid_public_dns(dns)
        }
        _ => false,
    }
}

/// Normalizes an observed multiaddress from an Identify protocol message.
/// Ephemeral outgoing ports are replaced with the node's configured listening ports.
/// Only globally routable public IP addresses are accepted.
pub fn normalize_observed_address(
    observed: &libp2p::Multiaddr,
    tcp_port: u16,
    quic_port: u16,
) -> Option<libp2p::Multiaddr> {
    use libp2p::multiaddr::Protocol;

    let host = observed.iter().find(is_public_host)?;
    let is_quic = observed.iter().any(|p| matches!(p, Protocol::QuicV1));
    let is_tcp = observed.iter().any(|p| matches!(p, Protocol::Tcp(_)));

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
pub fn load_or_generate_keypair(
    key_path: &std::path::Path,
) -> anyhow::Result<libp2p::identity::Keypair> {
    if key_path.exists() {
        let bytes = std::fs::read(key_path)
            .with_context(|| format!("Failed to read keypair file at '{}'", key_path.display()))?;
        let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&bytes).map_err(|e| {
            anyhow::anyhow!(
                "Failed to decode keypair from '{}': {:?}",
                key_path.display(),
                e
            )
        })?;
        return Ok(keypair);
    }

    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let bytes = keypair
        .to_protobuf_encoding()
        .map_err(|e| anyhow::anyhow!("Failed to encode generated keypair: {:?}", e))?;

    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create parent directory for '{}'",
                key_path.display()
            )
        })?;
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(key_path)
        .with_context(|| format!("Failed to create keypair file at '{}'", key_path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("Failed to write keypair file at '{}'", key_path.display()))?;

    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Validates deterministic SHA2-256 multihash and CIDv1 derivation from arbitrary service name strings.
    ///
    /// - Guarantees consistent IPFS content addressing across different daemon instances and CLI calls.
    /// - Ensures provider advertisements and query searches map to the exact same DHT record key (code 0x12, raw multihash).
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

    /// Verifies that valid existing CID strings are passed through without re-hashing.
    ///
    /// - Allows users to query or advertise directly by raw IPFS CID string in addition to service names.
    /// - Prevents accidental double-hashing of valid IPFS CIDs.
    #[test]
    fn test_valid_cid_passthrough() {
        let cid_str = "bafybeicg253nyacwgahb3h4q6tx5v23e6qyr2m4eecw6srm6f3r7w3m2py";
        let (cid, _mh) = derive_service_multihash(cid_str);
        assert_eq!(cid.to_string(), cid_str);
    }

    /// Validates extracting PeerId from libp2p multiaddresses containing `/p2p/<PeerId>`.
    ///
    /// - Essential for parsing bootstrap node lists and peer addresses with embedded peer identities.
    /// - Ensures correct extraction for establishing direct Kademlia dials.
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

    /// Verifies that observed TCP multiaddresses with ephemeral NAT ports are normalized to the daemon's listening TCP port.
    ///
    /// - In NAT environments, remote peers observe outgoing ephemeral source ports rather than listening ports.
    /// - Normalization ensures remote peers can dial back to our actual listening port.
    #[test]
    fn test_normalize_observed_address_tcp() {
        let observed: libp2p::Multiaddr = "/ip4/136.169.50.80/tcp/54358".parse().unwrap();
        let normalized = normalize_observed_address(&observed, 4001, 4001).unwrap();
        assert_eq!(normalized.to_string(), "/ip4/136.169.50.80/tcp/4001");
    }

    /// Verifies that observed QUIC multiaddresses (`/udp/<port>/quic-v1`) are normalized to the daemon's listening QUIC port.
    ///
    /// - Ensures QUIC transport addresses retain the correct UDP port and QUIC-v1 protocol identifier when discovered via AutoNAT/Identify.
    #[test]
    fn test_normalize_observed_address_quic() {
        let observed: libp2p::Multiaddr = "/ip4/136.169.50.80/udp/1027/quic-v1".parse().unwrap();
        let normalized = normalize_observed_address(&observed, 4001, 4002).unwrap();
        assert_eq!(
            normalized.to_string(),
            "/ip4/136.169.50.80/udp/4002/quic-v1"
        );
    }

    /// Verifies IPv6 address handling and port normalization.
    ///
    /// - Ensures dual-stack / IPv6 public addresses are properly identified and formatted with the correct port.
    #[test]
    fn test_normalize_observed_address_ipv6() {
        let observed: libp2p::Multiaddr = "/ip6/2600:1900::1/tcp/54358".parse().unwrap();
        let normalized = normalize_observed_address(&observed, 4001, 4001).unwrap();
        assert_eq!(normalized.to_string(), "/ip6/2600:1900::1/tcp/4001");
    }

    /// Verifies normalization across domain-based protocols (`/dns4/`, `/dns6/`, `/dnsaddr/`).
    ///
    /// - Ensures bootstrap nodes and domain-based addresses are properly normalized and validated against public DNS rules.
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

    /// Comprehensive verification of public routable IPv4 address classification.
    ///
    /// - Guards against advertising invalid or non-routable addresses to the public DHT.
    /// - Verifies filtering for RFC 1918 (10/8, 172.16/12, 192.168/16), CGNAT (100.64/10),
    ///   loopback (127/8), link-local (169.254/16), documentation, multicast, and broadcast ranges.
    #[test]
    fn test_is_public_routable_ipv4() {
        use std::net::Ipv4Addr;

        // Valid public IPs
        assert!(is_public_routable_ipv4(Ipv4Addr::new(136, 169, 50, 80)));
        assert!(is_public_routable_ipv4(Ipv4Addr::new(172, 238, 169, 224)));
        assert!(is_public_routable_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_public_routable_ipv4(Ipv4Addr::new(1, 1, 1, 1)));

        // Private RFC 1918
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(10, 60, 7, 102)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(192, 168, 50, 156)));

        // Loopback / Link-local / Unspecified / Broadcast
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(255, 255, 255, 255)));

        // CGNAT (100.64.0.0/10)
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(100, 127, 255, 254)));
        // 100.128.0.1 is outside CGNAT range
        assert!(is_public_routable_ipv4(Ipv4Addr::new(100, 128, 0, 1)));

        // Documentation / Multicast
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(!is_public_routable_ipv4(Ipv4Addr::new(240, 0, 0, 1)));
    }

    /// Verifies that private and loopback multiaddresses are rejected during address normalization.
    ///
    /// - Prevents local network addresses from being registered as candidate external addresses.
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

    /// Verifies persisting and reloading an Ed25519 keypair from disk.
    ///
    /// - Ensures node identity (PeerId) remains stable and deterministic across server restarts.
    /// - Verifies key serialization and file loading roundtrips properly.
    #[test]
    fn test_keypair_persistence() {
        let temp_dir = std::env::temp_dir();
        let key_file = temp_dir.join(format!(
            "test_key_{}.key",
            std::time::SystemTime::now().elapsed().unwrap().as_nanos()
        ));

        let kp1 = load_or_generate_keypair(&key_file).unwrap();
        let peer_id1 = libp2p::PeerId::from(kp1.public());

        let kp2 = load_or_generate_keypair(&key_file).unwrap();
        let peer_id2 = libp2p::PeerId::from(kp2.public());

        assert_eq!(peer_id1, peer_id2);

        let _ = std::fs::remove_file(&key_file);
    }
}
