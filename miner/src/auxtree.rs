//! The aux tree a block's `aux_hash` roots (docs/RELAYS.md): a binary tree
//! of SHA-256 hashes, an internal node's bytes `0x01 ‖ left ‖ right` and a
//! leaf's `0x00 ‖ its content`, each hash the SHA-256 of those bytes. The
//! root's left child is the leaf of the `consensus.txt` the block backs (the
//! relay list); its right child is the miner's own (zeros, here).
//!
//! A miner given `--consensus-file` backs that file: its blocks' `aux_hash`
//! is the root, and its network thread answers `GET_AUX` for the root's and
//! the leaf's bytes, so nodes can see what it voted for. The file's contents
//! are the nodes' to check (the Forth node's `src/consensus.fam`); here only
//! its first line is, to catch the wrong file early.

use std::collections::HashMap;

use crate::mnemonic::sha256;

/// A miner's aux tree: the root, and every node's and leaf's bytes by hash.
pub struct AuxTree {
    root: [u8; 32],
    leaf: [u8; 32],
    bytes: HashMap<[u8; 32], Vec<u8>>,
}

impl AuxTree {
    /// The tree backing `consensus` (its right side zeros).
    pub fn backing(consensus: &[u8]) -> AuxTree {
        let mut leaf_bytes = vec![0u8];
        leaf_bytes.extend_from_slice(consensus);
        let leaf = sha256(&leaf_bytes);
        let mut root_bytes = vec![1u8];
        root_bytes.extend_from_slice(&leaf);
        root_bytes.extend_from_slice(&[0u8; 32]);
        let root = sha256(&root_bytes);
        let bytes = HashMap::from([(leaf, leaf_bytes), (root, root_bytes)]);
        AuxTree { root, leaf, bytes }
    }

    /// What goes in the header's `aux_hash`.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The consensus file's leaf hash.
    pub fn leaf(&self) -> [u8; 32] {
        self.leaf
    }

    /// The bytes whose SHA-256 is `hash`, if they're in this tree.
    pub fn bytes(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.bytes.get(hash).map(Vec::as_slice)
    }
}

/// Whether `text` starts as a consensus file for `network` must: the line
/// `tabernacle-consensus 2 main` (or `dev`).
pub fn check_consensus(text: &[u8], network: crate::network::Network) -> Result<(), String> {
    let net = match network {
        crate::network::Network::Main => "main",
        crate::network::Network::Dev => "dev",
    };
    let head = format!("tabernacle-consensus 2 {net}\n");
    let Some(rest) = text.strip_prefix(head.as_bytes()) else {
        return Err(format!("its first line isn't `tabernacle-consensus 2 {net}`"));
    };
    let rest = std::str::from_utf8(rest).map_err(|_| "it isn't plain text".to_string())?;
    if !rest.is_empty() && !rest.ends_with('\n') {
        return Err("its last line has no newline".into());
    }
    // A decimal number below max, no leading zero (the nodes' cnpnum).
    fn num(s: &str, max: u32) -> Option<u32> {
        let ok = !s.is_empty() && s.len() <= 6 && s.bytes().all(|b| b.is_ascii_digit()) && !(s.len() > 1 && s.starts_with('0'));
        ok.then(|| s.parse::<u32>().ok()).flatten().filter(|&v| v < max)
    }
    let mut last: Option<&str> = None;
    let mut n = 0;
    for (i, line) in rest.lines().enumerate() {
        let at = || format!("line {}: `{line}`", i + 2);
        let fields = line.strip_prefix("relay ").and_then(|l| l.split_once(' ')).and_then(|(addr, id)| addr.split_once(':').map(|(ip, port)| (ip, port, id)));
        let Some((ip, port, id)) = fields else {
            return Err(format!("{}: not `relay A.B.C.D:PORT ID`", at()));
        };
        let octets: Vec<Option<u32>> = ip.split('.').map(|o| num(o, 256)).collect();
        if octets.len() != 4 || octets.iter().any(|o| o.is_none()) || octets.iter().all(|o| *o == Some(0)) {
            return Err(format!("{}: not an IP address (decimal, no leading zeros)", at()));
        }
        if num(port, 65536).filter(|&p| p > 0).is_none() {
            return Err(format!("{}: not a port (1-65535, no leading zeros)", at()));
        }
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(format!("{}: the relay id isn't 64 lower-case hex digits", at()));
        }
        if last.is_some_and(|l| l >= id) {
            return Err(format!("{}: out of order -- the relays must be sorted by id (tools/consensus writes it so)", at()));
        }
        last = Some(id);
        n += 1;
    }
    if n > 64 {
        return Err(format!("{n} relays: at most 64"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The same hashes the Forth node's `tests/consensus.fam` checks.
    #[test]
    fn leaves_and_nodes_hash_with_their_prefixes() {
        let tree = AuxTree::backing(b"abc");
        assert_eq!(hex(&tree.leaf()), "609f6e36d2405585188d5cfd761f407c7cc46a7d3f314c88270469dde315fcd1");
        let mut node = vec![1u8];
        node.extend_from_slice(&tree.leaf());
        node.extend_from_slice(&[0u8; 32]);
        assert_eq!(tree.root(), sha256(&node));
        assert_eq!(tree.bytes(&tree.root()), Some(node.as_slice()));
        assert_eq!(tree.bytes(&tree.leaf()), Some(&b"\0abc"[..]));
        assert_eq!(tree.bytes(&[7u8; 32]), None);
        assert_eq!(hex(&sha256(&[1u8; 1].iter().chain([0u8; 64].iter()).copied().collect::<Vec<u8>>())), "ae0798d0ecaed2b778eddebf18f071a561c53658c05e76cedecc27cafbdbc577");
    }

    #[test]
    fn the_first_line_names_the_network() {
        let dev = crate::network::Network::Dev;
        let (a, b) = ("1".repeat(64), "2".repeat(64));
        let file = |lines: &str| format!("tabernacle-consensus 2 dev\n{lines}").into_bytes();
        assert!(check_consensus(&file(""), dev).is_ok());
        assert!(check_consensus(&file(""), crate::network::Network::Main).is_err());
        assert!(check_consensus(&file(&format!("relay 62.210.163.171:3737 {a}\nrelay 10.0.0.1:1 {b}\n")), dev).is_ok());
        assert!(check_consensus(&file(&format!("relay 62.210.163.171:3737 {b}\nrelay 10.0.0.1:1 {a}\n")), dev).is_err());
        assert!(check_consensus(&file(&format!("relay 62.210.163.171:3737 {a}\nrelay 10.0.0.1:1 {a}\n")), dev).is_err());
        assert!(check_consensus(&file(&format!("relay 62.210.163.171:3737 {a}")), dev).is_err());
        assert!(check_consensus(&file(&format!("relay 62.210.163.171:3737 {}\n", a.to_uppercase().replace('1', "A"))), dev).is_err());
        for bad in ["256.0.0.1:3737", "62.0.010.1:3737", "0.0.0.0:3737", "62.0.0.1:0", "62.0.0.1:65536", "62.0.0.1"] {
            assert!(check_consensus(&file(&format!("relay {bad} {a}\n")), dev).is_err(), "{bad}");
        }
        assert!(check_consensus(&file(&format!("relay 255.0.10.1:65535 {a}\n")), dev).is_ok());
        assert!(check_consensus(b"relay 00\n", dev).is_err());
    }
}
