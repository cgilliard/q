//! A block's zero-knowledge proof: the one thing that attests a block
//! body's commitments are properly authorized and that everything
//! balances, without revealing any of the plaintext (pubkeys, amounts,
//! signatures) behind them. See `block`'s and `chain`'s module docs for
//! why that check belongs here, permanently, rather than anywhere in
//! plaintext.
//!
//! The statement proven is `block_air`'s: for the body's public input
//! and output commitment lists, there are transactions such that every
//! input carries its owner's valid WOTS signature over its transaction,
//! every commitment is correctly formed, and `sum(inputs) + REWARD ==
//! sum(outputs)` exactly. The proof is a two-phase, zero-knowledge
//! `stark` proof of that circuit, at `PARAMS`.
//!
//! Deliberately generic over raw commitment lists (`inputs`/`outputs` as
//! `&[[u8; 32]]`), not `block::BlockBody` -- same layering discipline
//! already used by `state_tree`/`utxo`: this module doesn't need to know
//! `BlockBody`'s specific shape, just the commitments it's attesting
//! about. It also avoids a dependency cycle: `BlockBody` holds a `Proof`
//! (see that module's docs), so `Proof` can't be defined in terms of
//! `BlockBody`.
//!
//! The miner proves every transaction in its block itself, from their
//! plaintext -- see `docs/BLOCK_TODO.md` #1.

#![allow(dead_code)]

use crate::recovery::NONCE_LEN;
use crate::aggregate::{self, ChunkTransition, Key, RootClaim, StateChange, TreeParams, VerifyingKey};
use crate::block_air::{self, ChunkShape};
use crate::poseidon2::{BabyBear, P, digest_from_bytes, hash_bytes_32};
use crate::stark::{self, Params};
use crate::transaction::Transaction;

/// The first era's block reward: 1,000,000,000 units. What a block may
/// claim at a height is `Schedule::reward`'s -- the proof enforces
/// `sum(inputs) + reward == sum(outputs)` exactly.
pub const REWARD: u64 = 1_000_000_000;

/// The block reward over the chain's life: `first` per block for the
/// first `first_blocks` blocks, then `then` per block; with an `end`, no
/// block at that height or after is valid, and the chain is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub first: u64,
    pub first_blocks: u64,
    pub then: u64,
    pub end: Option<u64>,
}

/// Blocks in a year of ten-minute blocks.
const YEAR: u64 = 144 * 365;

/// The main network's: 1,000,000,000 a block for seven years, then
/// 7,000,000 for a thousand -- each era issuing the same total,
/// 367,920,000,000,000 -- and then the chain ends.
pub const MAIN_SCHEDULE: Schedule = Schedule {
    first: REWARD,
    first_blocks: 7 * YEAR,
    then: 7_000_000,
    end: Some(1007 * YEAR),
};

/// The dev network's: `REWARD` at every height, without end.
pub const DEV_SCHEDULE: Schedule = Schedule {
    first: REWARD,
    first_blocks: 7 * YEAR,
    then: REWARD,
    end: None,
};

impl Schedule {
    /// The reward a block at `height` claims; `None` past the end.
    pub fn reward(&self, height: u64) -> Option<u64> {
        if self.end.is_some_and(|end| height >= end) {
            return None;
        }
        Some(if height < self.first_blocks { self.first } else { self.then })
    }
}

/// This network's schedule.
pub fn schedule() -> Schedule {
    match crate::network::current() {
        crate::network::Network::Main => MAIN_SCHEDULE,
        crate::network::Network::Dev => DEV_SCHEDULE,
    }
}

/// The proof system's parameters -- consensus constants, since a verifier
/// must check every block at the same ones. Chosen for small proofs and
/// fast verification over prover speed (blocks are minutes apart in
/// production): blowup 16 gives 4 bits per query, so 26 queries plus 24
/// bits of grinding come to 128 bits of (conjectured) soundness -- ~64
/// against Grover's search. Challenges themselves come from the ~124-bit
/// extension field.
pub const PARAMS: Params = Params {
    log_blowup: 4,
    num_queries: 26,
    grinding_bits: 24,
    hiding: true,
};

/// Every proof starts with its kind. (Kind 0, a direct proof of the
/// whole block in one trace, was retired: a chain step can only verify
/// one fixed proof shape -- `docs/CHAIN_RECURSION.md`.)
const KIND_TREE: u8 = 1;

/// An encoded block proof -- what's published and hashed into
/// `body_hash`, decoded only to verify. The block's transactions are
/// proven in chunks (`CHUNK_SHAPE`), each chunk's proof wrapped together
/// with the chunk's state transition, and the wraps aggregated
/// (`aggregate`) -- encoded as: the kind (`KIND_TREE`), the root's amount
/// totals `A`, `B` (`u64`s; `A - B` must be `REWARD`), whether the root
/// is an aggregation (`1`, more than one chunk) or a wrap (`0`), the
/// root's `data` (32 bytes), and the root `stark::Proof`. Nothing says
/// which chunk holds which commitment (see `aggregate`'s docs).
///
/// It attests that the body's commitments are authorized and balance,
/// **and** that applying them -- inputs spent, outputs appended in body
/// order -- takes the parent's state (`state_tree` root and output count)
/// to the block's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proof {
    bytes: Vec<u8>,
}

/// Whether `commitment` is eight canonical field elements (each 4-byte
/// group below P). Every commitment a proof can attest to is; anything
/// else is a second byte string for the same elements, which the proof
/// can't tell apart but the UTXO set would treat as a different output.
pub fn is_canonical(commitment: &[u8; 32]) -> bool {
    commitment
        .chunks_exact(4)
        .all(|c| u32::from_le_bytes(c.try_into().unwrap()) < P)
}

fn elements(list: &[[u8; 32]]) -> Vec<[BabyBear; 8]> {
    list.iter().map(digest_from_bytes).collect()
}

fn nonce_elements(nonces: &[[u8; NONCE_LEN]]) -> Vec<[BabyBear; 8]> {
    nonces.iter().map(crate::output::nonce_limbs).collect()
}

// ---- Tree proofs: consensus constants ----------------------------------------

/// Every chunk's shape: up to 8 inputs and 20 outputs, padded to 2^17
/// rows (4096 blocks). Also the most one transaction may have, since a
/// transaction is proven whole in one chunk. Sized so the wrap circuit --
/// which verifies the chunk proof *and* applies the chunk's 28 state
/// updates -- fits the tree's 2^18 rows.
/// Signatures a chunk proves, at most -- and so a transaction (each about
/// 278 of a chunk's 4096 blocks; `docs/CONTRACTS.md`).
pub const CHUNK_SIGNATURES: usize = 12;

pub const CHUNK_SHAPE: ChunkShape = ChunkShape {
    num_blocks: 4096,
    inputs: 8,
    outputs: 20,
};

/// Chunk proofs use the block parameters (zero knowledge: their witness
/// is the transactions).
pub const CHUNK_PARAMS: Params = PARAMS;

/// The dev network's parameters (`network`): blowup 4, 4 queries, no
/// grinding -- about 8 bits of soundness. **Not secure**; for testing
/// only, where they make proving several times faster (and keep the wrap
/// within dev's 2^17 rows: each query is ~5,400 rows of its verifier).
pub const DEV_PARAMS: Params = Params {
    log_blowup: 2,
    num_queries: 4,
    grinding_bits: 0,
    hiding: true,
};

/// The dev network's tree proofs: the same lightening, and half the rows
/// (fewer queries make the verifier circuits small enough).
pub const DEV_TREE: TreeParams = TreeParams {
    trace_len: 1 << 17,
    params: Params {
        log_blowup: 2,
        num_queries: 4,
        grinding_bits: 0,
        hiding: false,
    },
};

/// The chunk proofs' parameters on this node's network.
pub fn chunk_params() -> Params {
    match crate::network::current() {
        crate::network::Network::Main => CHUNK_PARAMS,
        crate::network::Network::Dev => DEV_PARAMS,
    }
}

/// The tree proofs' size and parameters on this node's network.
pub fn tree() -> TreeParams {
    match crate::network::current() {
        crate::network::Network::Main => TREE,
        crate::network::Network::Dev => DEV_TREE,
    }
}

/// `log2` of tree proofs' low-degree extension: the trace, times the
/// composition factor (4), times the blowup.
fn tree_log_lde() -> usize {
    let t = tree();
    t.trace_len.trailing_zeros() as usize + 2 + t.params.log_blowup
}

/// Every tree proof's size and parameters: the same soundness as `PARAMS`,
/// without zero-knowledge blinding -- a tree proof's witness is other
/// proofs, ultimately zero-knowledge chunk proofs (see `stark::Params::
/// hiding` and `docs/RECURSION.md`). 2^19 rows: a circuit verifying two
/// proofs at 26 queries (an aggregation, the chain step) needs ~330,000.
pub const TREE: TreeParams = TreeParams {
    trace_len: 1 << 19,
    params: Params {
        log_blowup: 4,
        num_queries: 26,
        grinding_bits: 24,
        hiding: false,
    },
};


/// The verifying keys: the wrap and aggregation circuits' preprocessed
/// caps, as hex. Derived from the circuits (see the `tree_keys` test,
/// which regenerates them); any change to those circuits changes these.
const WRAP_CAP: &str = "3d951563486d1d3ded7daf75ad686470262e6a1d665b890ee0c18476e7756b517de86c3dba88580dafe00a0a4391f92ebe0edb5c6aaf5f32a6dc800d6b96d2350b887e10612eef6030cd7c4021312238b2086d1d49112764f415a873cb446105ab1c0836e6aa1410b192270712b5d2594eb9520ee3d02d357705bc33c320022cd46d773ecd38350a971251273fd1e35969af046fd6f46f44c8bf67754997e076f00ed67050a12a2e02b4ec29d6768030967fd8360805202e0492295abbc70f24d269793acdd95f125a0d5216017a9950cd01bc4c80d88f4e0bd9d854fa3cdc4ad805b7541051a93a31363f5510f54313fdbe813a971d710b07085c693326167475413f62f410ce2292e5a3166d2df613efd117444ee45d5876fc3472ed70990d45e6095f517d9c597d9f7c073cb8c32bb6575d24813a5b3b24879b5e4a87fd53b7bbd962775e8227ffb4507678536b7340234a448f62573f758abd1908a70d71ae07e138c6902b52b84a6c580b9403350227146b3181e43174a4e36dd4bb04240a6ce11fca2d140c4ed5c5184beaf2767d9277491880b65eb6e79b32a7811f4300b5cd32da66ff400126573ab16a275570973863c6f56972117a1662dd7dba72d44c0d3bd72ae028059ce82582b44f12b888ff09c7f24e6d7434c14e754cb2027a0bbd11c113941009057a0125a66c22658e4e5666547275b7102d2dce3c95113438db3700329045a43511652f891f0b08c045221adbd02c90cdd4730292c334044c5c074b28a822aa9cec5a6008ad1c9de64f5fe579ad0d494510707d45fa00d46dda2c27486815f4cb3c13eeac5e665d5e146418d1ed33c6319629db64f01bfcf2613f016e526ff8134836f55b050d1c8c2c0d4b87b04893482c682555dd3a6c48983b3b32e54fefcc9f2158acfc6a2f42af37756a34545701aa04b306f964dea022594b3ac83e8e9640124c4b611069a44a0cdbc7df5798a5554db06ae6397fedbd75204b2101f8e913368ff2b04be43ce77625ee022e49a9413c457548353b123811cd8513642f250364860a0118fa08bf03ba795e680fb5725b951766025ea8dd1c30d8d2250b2fae435640685db55878483c28d637848af64fcc819b1c99d71b0bdaeaa4400ee10726cda4c837505bbd2deb4f22490e6f6b1fd876941423c9312aec423a5a944bed0fa0d2c905e416e141c904472e97e34947ebd2ef6f8a972f59bb015e4ab0924423ccfa375d09767e0e63c0a35aca0a0d0ef08c4312aeaf17729e508d6cfc0de46339f5464298550d1cb1aecf6366bce4309564ee67a8f8a9496b16b8103a956a6ed02a0c38f94db257fa0fcd6614207c17fd874c6bee12dc6c8771434484fcde12eb94d03c1dd6c511dbe5d052220d102eef5e4d6111095968a0ed9d3982da2539803c2e6180754b1d8869441a94d3e204536b3e29";
const AGGREGATE_CAP: &str = "1f71566e893bae219373c66dad1a734b910d621e01e6632a18dd1f5f019cab1cce1a254ad039424c2ebe0606569b263e4f20835b952d0f4be9b60e2aabf22c2d66f8555f415ec618bbef56745f22022521abaf4346fcd66ad586964851319b2c78e7bd72516b890932085b33d3e70c32a61c8318f8d540006ee1f404f40ab15c00a42039d25fec57603f644c7b636a4c9a9c0559f9c2647161f7a56c94b5d0693ecf8e5b8ea52c09bff33349967c8705f3460e6bd77ce10a487b5e6b2452976d6cc4576d2c262f28555a6d6201ea980cb0a1444b0e13d132cb39406246fa333e9fa82331fcbbc50ba98ce4059a6f70762b9c9219242b7f2292fa73196c7e9032e167ef01f2c3432ce2105b70371e4a0bfaa1585a8cc2410bd4971b6d575a5539a773100ec99f501020393073ab2a6915d4b1bc4c71547a68591bea757f254e570b89706331f6065f99612a77ae17365201e961303b396223a630603e838166593b3ee512dd7320704aadda6bc120e50656dc6614f249387299246c12feced00383e0a02d13bd7651eda6bc0c3d5244171acc7e04880b841945bdfb0a175c84487cec75016ea6cc55289c0b6e7b44fe0320ecf45d45cc305cf6e17802d8e6453fdba3353e510d9a67c7eb983c5d9a5615d44b0e6025f56502511a0372c5bd56174a1f8819ad66ca56b689d4027dfba222a6c94c5ff5e00e3251d9fb77d542715767eaca5321b11e5e8038741349187264e1e8bb5a34c14b18996a5f5064e777571dc8aa0d448e201e2e55ce6185fe1e73c568076530f271720d81df7486dcd74bd5d103095fd5ac67189e6e3ea7ae8e3280172b3168dabe365b71e2418f36081cb1afa82ba3b1dc172b09e670f6927053a95bba6eec22fd1a3bfbb3774216ca6066859d3af972755c2bc4414dd139b7480845d523271d4223d41f4b29a717a004561ccb2e76bf423eb267c51de8af033c3a37da3e0290a034f579f826c61a5a068856800ae650b162e1c0945ef3f2ca1e52e4f175da5020395dfb4d1ebb1f1c1d5a92ee38af4405138fbb556c2e57bd767b829834d8de720405377d06c0e76446d30d4e41b0df9f2efbf539034897e561a9a26d2c5ff2900f32fe5b2f610e5f3314d0914a2d02560858620029195e90491f3b690f846b2c29640ad0499398f25c2ee9045876ca0a48c979404653034a2423d7fc572c61a30f6e87ad6d5e3c974f0642d55303ce3f26fdc0650731a0f666e426b33a57e7a9249420791d3b63eb121adb1b68e2e16621dd1bf606592c1456751bee77c0cfd92d32c9081d25f172281d7f9c443196f07338ca420b7653651b50682b15a581be30b2cfab373cfe424ef0d8d84393c096493f277a4e8566751ded18bd6bd19b483260713c173694920410385049cb9eba7590b9044f6d92495924535724e7e29a33221fc135ed5ade32";

fn cap_from_hex(hex: &str) -> Vec<[u8; 32]> {
    let bytes: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect();
    bytes.chunks_exact(32).map(|c| c.try_into().unwrap()).collect()
}

fn cap_to_hex(cap: &[[u8; 32]]) -> String {
    cap.iter().flatten().map(|b| format!("{b:02x}")).collect()
}

/// The dev network's verifying keys (`tree_keys` with `NETWORK=dev`).
const DEV_WRAP_CAP: &str = "7f72572547a0f22d82eb50518b8882092ad0a3375b66702e5d462824a9c89a5eaf4a2f745c2a0a071c597a0e7696ad3c217788180cfb2369ac2ede34408e0100b7f433545d05cf1069850e195a256d45c1319b045c058127ab290a38f517f14123d2147173a97867c5827149a2850f5cb062cc759c030a532b5a5871eda75f19cae9522a64e721271c3abe20482df75c882d9e77b828a242d0096a720d5a9a02bfdf7f4a9c78bb3c389632616062a91c8ec0b5239bec47748bdcf910e5c401052ed3de46e47e4208f29d23696644ca2febd4d3707eb32576f0459240441f2753d894350f1d174e4fe58a3a6158b22114b7c9a47187cb3553f103ae39a46b0673da621c11728ea56a66cf643915eae20f42262843ebdbdd5e6f8e88264fd500108d7abe516b90ad205cdb5a2c3a9a8751be9ed82c5474cd5ce3df733a2e4fcf23eb1ded1e43940d0ce4b3f773ab7ded2f8bf7681e64989643fa7b0c5c04d34101d37ec4056e077b125888040174d993677a36d85c033bd73606eecd031451851e927bd95bd796d6367ccb1c3b9915cf6670aeb524e28bc800fbde8f5eb2fb5008c1c2be06362b42473f333d6f156aa2382962ca242660f21f9a691428adb98e68da512a2e3dbf1b5ab43ead30760e023234ada84da2431e70fb763525ff6dee24b544ab26d83b2d656ccb3a113ec1d44de129c03cb10df3627002db403567dd5d44f2de64dd66886a4fe2f30621a0fb6510c27a50f6cd9104ed2e0a0e3ad4366d29c5823e6369a8359a1c7a10e5cd9a5e07ee8c5afacebf50acb3a162f6358a3ed6d1ef5b87810a3643cbd156d36e56302e53c53dc937885276b8304acab92203d053b169cf6cf558de08de50f97e3106986bce7347287160edd2023ebcbe041e9c4c1662ec6db706be333222cdf49633d5d96541d7ca572e6f54c139c7580e749cb6d1447d2c95556d76a365218b0046bd6ff33ff1455d566f70b46beeeb2e2711a94676c1cebf506ac98d72f5a71b085e3897160beccb4d699bec104c09701a5a599c0a3357b7702d86cb1e2476bf0c356d262fc8647e048b931308e2c71e685a663a441fbca862da17a6240ad85b2a220f7c127aa82f5270fc321e41348f75180bb60ffba84371ce2ae945df1bf81da9424c5776447173b261d25b5a77502ccb9b1242e28d66622037a165c468013be0ba1b2824d08b59d062680e8d457677755cfb6f9387eb6fcb0346254ebe3c00ce557608c68a756f2e48c175cc2e3f2b25486b6b6c438d3cda4f847572edac5090da845f57219b3a61d6d90cb79abd35874da259ddb6350e3246dd0b740b3e604c0f9c0c408e801c3a69ae73f0733c1a7abe286b6254aa15e2bc3b4fa7a9a72db54e6a66235f1a10b875dc08db7772118827163c0aac44595916a81855ee216e2f7a996c186436565a5232275c2b8415";
const DEV_AGGREGATE_CAP: &str = "14a0bc5bfa2aa91319e5df58954c113809364a3a00c3260b2423ea510b4d581d77cb34772703a20ecfd3364e034f993231135e46c09bb22bf5b8166b578773473db31f1440914d3cc2b6076ec8705c2f744b810d7c10e9577ee90f76e997e729e2cbfd00cf6200654993865edd75814447d2326874f8bc36efdc9c38ca9f3075df72bc1cec964e0b7e454766bdb43a305caaff11d398c7614efd2858a60b3f599b8dc128be57de0004983b68e0aa4029156b780f3477a05bc443262749705a2e83763c2c047574777f0c1b49e2148876998dba28d669b54c5d5cdd6673f0033d7935fd0a69b1115c7b3be745229c7f3f2e20ed5cb2a59c7396a24865dc83e947840c603ae21c7630410e943fd9312d1b3f7cb63b6342e974ad0bac07d7efe82eec08533709ed46543b446f4c2714be6dd8c6c620259c9013f3b2c9313b26115ee66dc273bbce9d564b154104a4585339323fc33510541e042d209f044305e864989ed45c03eb2445c1c5b7074dc6c4345613f0762a7d3638da580708d80daa01054f1a3dce80f46228e5dd005584e471849418274f53575fa804440d47fbd24735777164682a5638e6e0853de0128d348aa01144646d8e6f5a600765ed35466aea74ab56b0aadb47d7683869460d133e43a423400e04160f4ae9c6277db3b262efa5d0536776eb657e45d94ba6ce9133600e2b02a1f5de2a59eb9f140a5df42214a7641b148dca403678aa6e4583b122009cfc2c0274a46a3d61671bfc04b26b2d471d4752e85843d1d2c03daf14460137d1294d36d27577af7ff55d15bac62974b8e0496ded794e375a114073d11608e1247f0c8718d5519895bc2be6fa7b44f7ba422f40eb7a712e6bc9078fd7dc24d65f955c80d7ff36089f601e7fea114d6dda004a540e2b2613e95b495765f11a5d589e742132eb0918a79e702359726bd216c26fd3c2661d68aed137ef64d472d7c020619160d05253dbec041b938c2568ae0f215a505b3e4ca5512d7801f63c52de3805b43e3a4a80449e3853777768e4843d6e7492e143120c5e190ad8ea435be7c02a9f65ea4e9a15806e6964c50a3fd088593db55c403096156b48bf1d32977d46185fda0f62b95c300409ea084ebfa9f724d3f4d85a84f890032d21e5763370ce610a767d190fe8f568e9f3485ce4c77f42d60cc21cea28ee61aa5f7c7737da7e1ad84be01b0977614de4ba9c5b49c2ca14544149457d02db62acd8b30b522e2b4af2248f5212a43e77672fb1528d32925c4cc83c0e4243d94ce635c032b70a1b380151532363c9e92bbce6ac268849550dbdc9b357bbc34872ffbb4f10e32be14ca0167200427a451a51f54b58e3dc6c76f0ab9c3d655cf13d325bb2670d7f315bc26bf76d566233450604e145a3782f247170f300ae7dfd36fa52910e983b6a48796d4f66be0b2549bad84070";

/// This network's verifying key for tree proofs.
pub fn tree_verifying_key() -> VerifyingKey {
    let (wrap, aggregate) = match crate::network::current() {
        crate::network::Network::Main => (WRAP_CAP, AGGREGATE_CAP),
        crate::network::Network::Dev => (DEV_WRAP_CAP, DEV_AGGREGATE_CAP),
    };
    VerifyingKey {
        wrap_cap: cap_from_hex(wrap),
        aggregate_cap: cap_from_hex(aggregate),
        log_lde: tree_log_lde(),
        tree: tree(),
    }
}

/// Little-endian reads off the front of a byte slice.
struct Bytes<'a>(&'a [u8]);

impl<'a> Bytes<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = (self.0.get(..n)?, &self.0[n..]);
        self.0 = tail;
        Some(head)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

impl Proof {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Proof { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Whether this is a tree proof (else garbage).
    pub fn is_tree(&self) -> bool {
        self.bytes.first() == Some(&KIND_TREE)
    }

    /// An empty stand-in proof, for tests about everything *but* proofs
    /// (forks, retargeting, sync), whose chains skip proof checks -- and
    /// for blocks mined with `--debug-disable-verification`.
    pub fn placeholder() -> Self {
        Proof::default()
    }

    /// What `BlockBody::body_hash` folds in to commit to the proof.
    pub fn commitment_hash(&self) -> [u8; 32] {
        hash_bytes_32(&self.bytes)
    }

    /// Whether this proves the block statement for exactly these public
    /// commitment lists and outputs' recovery nonces (`nonces[i]` is
    /// `outputs[i]`'s), claiming `reward`, with the state moving as
    /// `state` says for a block at `height`.
    pub fn verify(&self, inputs: &[[u8; 32]], outputs: &[[u8; 32]], nonces: &[[u8; NONCE_LEN]], state: &StateChange, height: u32, reward: u64) -> bool {
        if !inputs.iter().chain(outputs).all(is_canonical) || nonces.len() != outputs.len() {
            return false;
        }
        verify_tree(&self.bytes, inputs, outputs, nonces, state, height, reward)
    }
}

/// A tree proof's header -- amounts, whether its root aggregates, the
/// root's data -- and the root proof's bytes.
type Header<'a> = ((u64, u64), bool, [u8; 32], &'a [u8]);

fn parse_header_and_rest(bytes: &[u8]) -> Option<Header<'_>> {
    let mut r = Bytes(bytes);
    if r.take(1)? != [KIND_TREE] {
        return None;
    }
    let amounts = (r.u64()?, r.u64()?);
    let aggregated = match r.take(1)? {
        [0] => false,
        [1] => true,
        _ => return None,
    };
    let data: [u8; 32] = r.take(32)?.try_into().unwrap();
    is_canonical(&data).then_some((amounts, aggregated, data, r.0))
}

/// What a root proof is checked against, for this body, state change and
/// height; `None` if the proof's header doesn't parse.
fn claim(bytes: &[u8], inputs: &[[u8; 32]], outputs: &[[u8; 32]], nonces: &[[u8; NONCE_LEN]], state: &StateChange, height: u32) -> Option<(RootClaim, stark::Proof)> {
    let (amounts, aggregated, data, rest) = parse_header_and_rest(bytes)?;
    let claim = RootClaim {
        inputs: elements(inputs),
        outputs: elements(outputs).into_iter().zip(nonce_elements(nonces)).collect(),
        state: *state,
        height,
        aggregated,
        data: digest_from_bytes(&data),
        amounts,
    };
    Some((claim, stark::Proof::from_bytes(rest)?))
}

/// A block proof's tree root, as a chain step verifies it
/// (`chain_step`): for this body, state change and height. `None` if the
/// proof doesn't parse; whether it verifies is `Proof::verify`'s question.
pub fn block_root(proof: &Proof, inputs: &[[u8; 32]], outputs: &[[u8; 32]], nonces: &[[u8; NONCE_LEN]], state: &StateChange, height: u32) -> Option<aggregate::Node> {
    let (claim, root) = claim(&proof.bytes, inputs, outputs, nonces, state, height)?;
    Some(tree_verifying_key().root(&claim, root))
}

fn verify_tree(bytes: &[u8], inputs: &[[u8; 32]], outputs: &[[u8; 32]], nonces: &[[u8; NONCE_LEN]], state: &StateChange, height: u32, reward: u64) -> bool {
    if state.count_out.checked_sub(state.count_in) != Some(outputs.len() as u64) {
        return false;
    }
    match claim(bytes, inputs, outputs, nonces, state, height) {
        Some((claim, root)) => tree_verifying_key().verify_block(&claim, reward, &root),
        None => false,
    }
}

/// How a block's transactions are proven: grouped, in order, into chunks
/// (`plan_chunks`), and each chunk's state transition -- what
/// `chain::Chain::build_block` works out against the parent's state.
#[derive(Clone, Debug)]
pub struct BlockPlan {
    /// Each chunk's transactions, as indices into the block's list.
    pub chunks: Vec<Vec<usize>>,
    pub transitions: Vec<ChunkTransition>,
    /// The reward the block claims, at its height (`Schedule::reward`).
    pub reward: u64,
    /// The block's height and its inputs' creation heights.
    pub heights: block_air::Heights,
}

/// Group transactions, in order, into chunks that fit `CHUNK_SHAPE` and
/// `CHUNK_SIGNATURES`, as indices; `None` if one doesn't fit even alone
/// (consensus: no transaction may have more inputs, outputs or signatures
/// than a chunk holds).
pub fn plan_chunks(transactions: &[Transaction]) -> Option<Vec<Vec<usize>>> {
    let mut chunks: Vec<Vec<usize>> = Vec::new();
    let (mut ins, mut outs, mut sigs) = (usize::MAX, usize::MAX, usize::MAX);
    for (t, tx) in transactions.iter().enumerate() {
        let (i, o, s) = (tx.inputs.len(), tx.outputs.len(), tx.signature_count());
        if i > CHUNK_SHAPE.inputs || o > CHUNK_SHAPE.outputs || s > CHUNK_SIGNATURES {
            return None;
        }
        if chunks.is_empty() || ins + i > CHUNK_SHAPE.inputs || outs + o > CHUNK_SHAPE.outputs || sigs + s > CHUNK_SIGNATURES {
            chunks.push(Vec::new());
            (ins, outs, sigs) = (0, 0, 0);
        }
        chunks.last_mut().unwrap().push(t);
        (ins, outs, sigs) = (ins + i, outs + o, sigs + s);
    }
    Some(chunks)
}

/// The tree circuits' proving keys -- derived from the first block this
/// process proves (their fixed columns don't depend on which), then kept.
struct TreeKeys {
    wrap: Key,
    aggregate: Option<Key>,
}

static TREE_KEYS: std::sync::Mutex<Option<TreeKeys>> = std::sync::Mutex::new(None);

/// Prove the block whose body is `inputs`/`outputs`/`nonces`, from its
/// `transactions` (each fully signed) and `plan`: chunk proofs, wraps
/// (each applying its chunk to the state), aggregation. `seed` must be
/// fresh random bytes for every proof (it's what keeps chunk proofs
/// zero-knowledge). `None` if the transactions don't verify, don't
/// balance against the plan's reward, or don't match the body or the
/// plan.
pub fn prove_block(
    inputs: &[[u8; 32]],
    outputs: &[[u8; 32]],
    nonces: &[[u8; NONCE_LEN]],
    transactions: &[Transaction],
    plan: &BlockPlan,
    seed: [u8; 32],
) -> Option<Proof> {
    prove_block_with_root(inputs, outputs, nonces, transactions, plan, seed).map(|(proof, _)| proof)
}

/// `prove_block`, also returning the tree's root proof itself -- what a
/// chain step (`chain_step`) verifies.
pub fn prove_block_with_root(
    inputs: &[[u8; 32]],
    outputs: &[[u8; 32]],
    nonces: &[[u8; NONCE_LEN]],
    transactions: &[Transaction],
    plan: &BlockPlan,
    seed: [u8; 32],
) -> Option<(Proof, aggregate::Node)> {
    if plan.chunks.len() != plan.transitions.len() || plan.chunks.is_empty() {
        return None;
    }
    let derive = |k: u16| {
        let mut s = seed;
        s[31] ^= k as u8;
        s[30] ^= 0x5a ^ (k >> 8) as u8;
        s
    };
    // Each chunk's net: what its outputs take beyond its inputs (a), or
    // the reverse (b) -- its share of reward and fees. All laid out (and
    // checked against the body) before any proving.
    let mut witnesses = Vec::with_capacity(plan.chunks.len());
    let mut totals = (0u128, 0u128);
    for indices in &plan.chunks {
        let txs: Vec<Transaction> = indices.iter().map(|&i| transactions.get(i).cloned()).collect::<Option<_>>()?;
        let spent: u128 = txs.iter().flat_map(|t| &t.inputs).map(|i| i.amount as u128).sum();
        let created: u128 = txs.iter().flat_map(|t| &t.outputs).map(|o| o.amount as u128).sum();
        let net = if created >= spent {
            (u64::try_from(created - spent).ok()?, 0)
        } else {
            (0, u64::try_from(spent - created).ok()?)
        };
        totals = (totals.0 + net.0 as u128, totals.1 + net.1 as u128);
        witnesses.push(block_air::build_chunk(&txs, net, CHUNK_SHAPE, &plan.heights).ok()?);
    }
    // The block must claim exactly the reward (plus fees, which cancel).
    if totals.0.checked_sub(totals.1) != Some(plan.reward as u128) {
        return None;
    }

    // The chunks' commitments must be exactly the body's.
    let mut proven: Vec<[u8; 32]> = witnesses
        .iter()
        .flat_map(|w| w.air.public_inputs().iter().chain(w.air.public_outputs()))
        .map(|c| crate::poseidon2::digest_to_bytes(*c))
        .collect();
    let mut listed: Vec<[u8; 32]> = inputs.iter().chain(outputs).copied().collect();
    proven.sort_unstable();
    listed.sort_unstable();
    if proven != listed {
        return None;
    }

    // The binding (`aggregate`'s docs): each leaf's data under a fresh
    // salt, so the root's data -- and with it the challenge every wrap
    // takes -- is fixed before any wrap is proven.
    let salt = |k: usize| digest_from_bytes(&hash_bytes_32(&[&derive(0x4000 | k as u16)[..], b"salt"].concat()));
    let salts: Vec<crate::circuit::Octet> = (0..witnesses.len()).map(salt).collect();
    let leaves: Vec<_> = witnesses.iter().zip(&salts).map(|(w, &salt)| (aggregate::chunk_data(&w.air, salt), (0, 0))).collect();
    let (data, _) = aggregate::tree_data(&leaves)?;
    let body_outputs: Vec<_> = elements(outputs).into_iter().zip(nonce_elements(nonces)).collect();
    let challenge = aggregate::challenge(data, &elements(inputs), &body_outputs);

    let mut chunks = Vec::with_capacity(witnesses.len());
    for (k, w) in witnesses.into_iter().enumerate() {
        let proof = stark::prove(&w.air, &w.trace, &chunk_params(), derive(k as u16)).ok()?;
        chunks.push((w.air, proof));
    }

    let mut keys = TREE_KEYS.lock().unwrap();
    if keys.is_none() {
        let (air, proof) = &chunks[0];
        let wrap = aggregate::wrap_key(air, proof, &plan.transitions[0], &chunk_params(), &tree()).ok()?;
        *keys = Some(TreeKeys { wrap, aggregate: None });
    }
    let keys = keys.as_mut().unwrap();
    let mut wraps = Vec::with_capacity(chunks.len());
    for (k, ((air, proof), transition)) in chunks.iter().zip(&plan.transitions).enumerate() {
        let binding = aggregate::Binding { salt: salts[k], challenge };
        wraps.push(aggregate::wrap(&keys.wrap, air, proof, transition, &binding, &chunk_params(), &tree(), derive(0x8000 | k as u16)).ok()?);
    }
    let aggregated = wraps.len() > 1;
    let root = if aggregated {
        if keys.aggregate.is_none() {
            keys.aggregate = Some(aggregate::aggregate_key([&wraps[0], &wraps[1]], &keys.wrap, &tree()).ok()?);
        }
        aggregate::aggregate_all(keys.aggregate.as_ref().unwrap(), &keys.wrap, wraps, &tree(), derive(0xffff)).ok()?
    } else {
        wraps.pop().unwrap()
    };

    let mut bytes = vec![KIND_TREE];
    bytes.extend(root.amounts.0.to_le_bytes());
    bytes.extend(root.amounts.1.to_le_bytes());
    bytes.push(aggregated as u8);
    bytes.extend(crate::poseidon2::digest_to_bytes(root.data));
    bytes.extend(root.proof.to_bytes());
    // Check against the consensus key before anyone else has to: keys
    // derived here that don't match it (stale constants) would make every
    // proof this miner publishes invalid.
    let proof = Proof { bytes };
    let state = StateChange {
        root_in: plan.transitions[0].change.root_in,
        count_in: plan.transitions[0].change.count_in,
        root_out: plan.transitions.last().unwrap().change.root_out,
        count_out: plan.transitions.last().unwrap().change.count_out,
    };
    proof.verify(inputs, outputs, nonces, &state, plan.transitions[0].height, plan.reward).then_some((proof, root))
}

/// This network's tree circuits' verifying keys (`aggregate::vk_digest` of
/// each cap): `(wrap, aggregate)` -- what a chain step accepts a block's
/// root proof by.
pub fn tree_vks() -> (crate::circuit::Octet, crate::circuit::Octet) {
    let vk = tree_verifying_key();
    (aggregate::vk_digest(&vk.wrap_cap), aggregate::vk_digest(&vk.aggregate_cap))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Main's two eras issue the same total, and the chain ends after
    /// the second; dev pays `REWARD` forever.
    #[test]
    fn the_schedule_has_two_equal_eras_then_ends() {
        let (first, end) = (MAIN_SCHEDULE.first_blocks, MAIN_SCHEDULE.end.unwrap());
        assert_eq!((first, end), (7 * 144 * 365, 1007 * 144 * 365));
        assert_eq!(MAIN_SCHEDULE.first * first, MAIN_SCHEDULE.then * (end - first));
        assert_eq!(MAIN_SCHEDULE.first * first, 367_920_000_000_000);
        let rewards: Vec<Option<u64>> = [0, first - 1, first, end - 1, end].iter().map(|&h| MAIN_SCHEDULE.reward(h)).collect();
        assert_eq!(rewards, [Some(REWARD), Some(REWARD), Some(7_000_000), Some(7_000_000), None]);
        assert_eq!(DEV_SCHEDULE.reward(u64::MAX >> 1), Some(REWARD));
    }
    use crate::block::BlockBody;
    use crate::output::Output;
    use crate::poseidon2::digest_from_bytes;
    use crate::stark::Air;
    use crate::wots;

    /// A block: its body's lists, its transactions, and how to prove it
    /// against a state that holds its inputs (with zero nonces) -- what
    /// `chain::Chain::build_block` works out against the real state.
    struct TestBlock {
        inputs: Vec<[u8; 32]>,
        outputs: Vec<[u8; 32]>,
        nonces: Vec<[u8; NONCE_LEN]>,
        txs: Vec<Transaction>,
        plan: BlockPlan,
        state: StateChange,
        height: u32,
    }

    /// The test blocks' height, and their inputs' creation height.
    const HEIGHT: u32 = 5;
    const CREATED: u32 = 2;

    /// `HEIGHT`, every input of `txs` created at `CREATED`.
    fn heights_of(txs: &[Transaction]) -> block_air::Heights {
        let created = txs.iter().flat_map(|t| &t.inputs).map(|i| (i.commitment(), CREATED)).collect();
        block_air::Heights { block: HEIGHT, created }
    }

    fn block(txs: Vec<Transaction>) -> TestBlock {
        use crate::state_circuit::MemTree;
        use crate::state_tree::compress_leaf;
        let body = BlockBody::from_transactions(&txs).unwrap();
        let chunks = plan_chunks(&txs).unwrap();
        let zero = [0; NONCE_LEN];
        let leaf = |c: &[u8; 32], n: &[u8; NONCE_LEN], h: u32| compress_leaf(&digest_from_bytes(c), &crate::output::nonce_limbs(n), h);
        let mut tree = MemTree::default();
        for c in &body.inputs {
            tree.append(leaf(c, &zero, CREATED));
        }
        let (root_in, base) = (tree.root(), tree.count());
        let end = base + body.outputs.len() as u64;
        let mut transitions = Vec::new();
        let mut count = base;
        for indices in &chunks {
            let mut ins: Vec<[u8; 32]> = indices.iter().flat_map(|&t| &txs[t].inputs).map(|i| i.commitment()).collect();
            let mut outs: Vec<[u8; 32]> = indices.iter().flat_map(|&t| &txs[t].outputs).map(|o| o.commitment()).collect();
            ins.sort();
            outs.sort();
            let (root, count_in) = (tree.root(), count);
            let mut t_inputs = Vec::new();
            for slot in 0..CHUNK_SHAPE.inputs {
                match ins.get(slot) {
                    Some(c) => {
                        let p = tree.position_of(&leaf(c, &zero, CREATED)).unwrap();
                        t_inputs.push((p, zero, CREATED, tree.path(p)));
                        tree.spend(&leaf(c, &zero, CREATED));
                    }
                    None => t_inputs.push((end, zero, 0, tree.path(end))),
                }
            }
            let mut t_outputs = Vec::new();
            for slot in 0..CHUNK_SHAPE.outputs {
                match outs.get(slot) {
                    Some(c) => {
                        let o = body.outputs.binary_search(c).unwrap();
                        let p = base + o as u64;
                        t_outputs.push((p, tree.path(p)));
                        tree.place(p, leaf(c, &body.nonces[o], HEIGHT));
                        count += 1;
                    }
                    None => t_outputs.push((end, tree.path(end))),
                }
            }
            transitions.push(ChunkTransition {
                change: StateChange { root_in: root, count_in, root_out: tree.root(), count_out: count },
                window: (base, end),
                height: HEIGHT,
                inputs: t_inputs,
                outputs: t_outputs,
            });
        }
        let heights = heights_of(&txs);
        TestBlock {
            inputs: body.inputs.clone(),
            outputs: body.outputs,
            nonces: body.nonces,
            txs,
            plan: BlockPlan { chunks, transitions, reward: REWARD, heights },
            state: StateChange { root_in, count_in: base, root_out: tree.root(), count_out: end },
            height: HEIGHT,
        }
    }

    fn reward_tx(amount: u64) -> Transaction {
        let (_, pk) = wots::keygen(&[1; 32]);
        let mut tx = Transaction::new();
        tx.add_output(Output::new(&pk, amount)).unwrap();
        tx
    }

    /// `count` single-input spends (each paying a fee of 10) and the reward
    /// transaction claiming the reward plus all fees.
    fn spends(count: u8) -> Vec<Transaction> {
        let mut txs = Vec::new();
        for k in 0..count {
            let (sk, pk) = wots::keygen(&[100 + k; 32]);
            let (_, to) = wots::keygen(&[200 - k; 32]);
            let mut tx = Transaction::new();
            tx.add_input(&pk, 1000).unwrap();
            tx.add_output(Output::new(&to, 990)).unwrap();
            assert!(tx.sign_input(&pk, &sk));
            txs.push(tx);
        }
        let (_, miner) = wots::keygen(&[7; 32]);
        let mut reward = Transaction::new();
        reward.add_output(Output::new(&miner, REWARD + 10 * count as u64)).unwrap();
        txs.push(reward);
        txs
    }

    #[test]
    fn proving_refuses_lists_that_dont_match_the_transactions() {
        let mut b = block(vec![reward_tx(REWARD)]);
        b.outputs[0][0] ^= 1;
        assert!(prove_block(&b.inputs, &b.outputs, &b.nonces, &b.txs, &b.plan, [1; 32]).is_none());
    }

    #[test]
    fn proving_refuses_a_block_that_overclaims_the_reward() {
        let b = block(vec![reward_tx(REWARD + 1)]);
        assert!(prove_block(&b.inputs, &b.outputs, &b.nonces, &b.txs, &b.plan, [1; 32]).is_none());
    }

    #[test]
    fn garbage_and_placeholder_proofs_dont_verify() {
        let b = block(vec![reward_tx(REWARD)]);
        for proof in [Proof::placeholder(), Proof::from_bytes(vec![4, 0, 0, 0, 1, 2, 3]), Proof::from_bytes(vec![0, 0, 0, 0])] {
            assert!(!proof.verify(&b.inputs, &b.outputs, &b.nonces, &b.state, b.height, REWARD));
        }
    }

    #[test]
    fn tree_proof_headers_are_checked_before_anything_expensive() {
        let b = block(vec![reward_tx(REWARD)]);
        let mut header = vec![KIND_TREE];
        header.extend(REWARD.to_le_bytes());
        header.extend(0u64.to_le_bytes());
        // Truncated, an unknown root kind, non-canonical data.
        assert!(parse_header_and_rest(&header).is_none());
        let mut bad_kind = header.clone();
        bad_kind.push(2);
        bad_kind.extend([0; 32]);
        assert!(parse_header_and_rest(&bad_kind).is_none());
        let mut bad_data = header.clone();
        bad_data.push(0);
        bad_data.extend([0xff; 32]);
        assert!(parse_header_and_rest(&bad_data).is_none());
        let mut good = header;
        good.push(1);
        good.extend([0; 32]);
        assert!(parse_header_and_rest(&good).is_some());
        assert!(!Proof::from_bytes(good).verify(&b.inputs, &b.outputs, &b.nonces, &b.state, b.height, REWARD));
    }

    #[test]
    fn transactions_plan_into_chunks_in_order() {
        let txs = spends(12);
        let chunks = plan_chunks(&txs).unwrap();
        assert_eq!(chunks.iter().map(|c| c.len()).collect::<Vec<_>>(), vec![8, 5]);
        assert_eq!(chunks[0][0], 0);
        let mut big = Transaction::new();
        for k in 0..=CHUNK_SHAPE.inputs as u8 {
            big.add_input(&wots::keygen(&[k; 32]).1, 1).unwrap();
        }
        assert!(plan_chunks(&[big]).is_none(), "more inputs than a chunk holds");
    }

    /// Prove an 11-input block (two chunks) with the consensus parameters,
    /// and print the tree circuits' verifying keys -- run after changing
    /// any circuit, then update `WRAP_CAP` / `AGGREGATE_CAP`. Then checks
    /// the proof verifies, and tampering is refused. Slow (minutes):
    /// `cargo test --release -- --ignored --nocapture tree_keys`.
    #[test]
    #[ignore]
    fn tree_keys() {
        let b = block(spends(11));
        let start = std::time::Instant::now();
        let proof = prove_block(&b.inputs, &b.outputs, &b.nonces, &b.txs, &b.plan, [3; 32]);
        println!("proved in {:.2?}", start.elapsed());
        // (The lock is released at the end of this block: proving again
        // below takes it.)
        let (wrap, aggregate) = {
            let keys = TREE_KEYS.lock().unwrap();
            let keys = keys.as_ref().unwrap();
            assert_eq!(keys.wrap.preprocessed.log_lde, tree_log_lde());
            (
                cap_to_hex(&keys.wrap.preprocessed.cap),
                cap_to_hex(&keys.aggregate.as_ref().unwrap().preprocessed.cap),
            )
        };
        let dev = crate::network::current() == crate::network::Network::Dev;
        let (current_wrap, current_aggregate) = if dev { (DEV_WRAP_CAP, DEV_AGGREGATE_CAP) } else { (WRAP_CAP, AGGREGATE_CAP) };
        if wrap != current_wrap || aggregate != current_aggregate {
            let prefix = if dev { "DEV_" } else { "" };
            println!("const {prefix}WRAP_CAP: &str = \"{wrap}\";");
            println!("const {prefix}AGGREGATE_CAP: &str = \"{aggregate}\";");
            panic!("the verifying-key constants are stale: update them to the above");
        }
        let proof = proof.expect("a tree proof that verifies");
        println!("tree proof: {} KB", proof.len() / 1024);
        let start = std::time::Instant::now();
        assert!(proof.verify(&b.inputs, &b.outputs, &b.nonces, &b.state, b.height, REWARD));
        println!("verified in {:.2?}", start.elapsed());
        // Other lists, a different claimed split of the totals, or another
        // state change.
        let mut other = b.outputs.clone();
        other.swap(0, 1);
        assert!(!proof.verify(&b.inputs, &other, &b.nonces, &b.state, b.height, REWARD));
        let mut bytes = proof.as_bytes().to_vec();
        bytes[1] ^= 1; // A
        bytes[9] ^= 1; // B, keeping A - B
        assert!(!Proof::from_bytes(bytes).verify(&b.inputs, &b.outputs, &b.nonces, &b.state, b.height, REWARD));
        let mut state = b.state;
        state.count_out += 1;
        assert!(!proof.verify(&b.inputs, &b.outputs, &b.nonces, &state, b.height, REWARD));
        // Another height (its outputs' leaves would differ).
        assert!(!proof.verify(&b.inputs, &b.outputs, &b.nonces, &b.state, b.height + 1, REWARD));
        let mut nonces = b.nonces.clone();
        nonces[0][0] ^= 1;
        assert!(!proof.verify(&b.inputs, &b.outputs, &nonces, &b.state, b.height, REWARD));
        // A one-chunk block: its root is the wrap.
        let small = block(vec![reward_tx(REWARD)]);
        let proof = prove_block(&small.inputs, &small.outputs, &small.nonces, &small.txs, &small.plan, [5; 32]).unwrap();
        assert!(proof.verify(&small.inputs, &small.outputs, &small.nonces, &small.state, small.height, REWARD));
    }

    /// A block spending a policy output -- by the 2-of-3, hash-locked
    /// branch of a two-branch policy -- proves and verifies with this
    /// network's parameters, through chunk, wrap and aggregation. Slow:
    /// `[NETWORK=dev] cargo test --release -- --ignored --nocapture
    /// a_policy_spend_proves`.
    #[test]
    #[ignore]
    fn a_policy_spend_proves() {
        use crate::policy::{Branch, Policy};
        use crate::poseidon2::digest_to_bytes;
        let key = |k: u8| digest_to_bytes(wots::keygen(&[k; 32]).1.hash());
        let preimage = digest_to_bytes([BabyBear::new(7); 8]);
        let pay = Branch { threshold: 2, keys: vec![key(11), key(12), key(13)], after_height: 0, after_age: 0, hashlock: crate::policy::hashlock(&preimage), rebind: None };
        let refund = Branch { threshold: 1, keys: vec![key(14)], after_height: 1_000, after_age: 0, hashlock: None, rebind: None };
        let policy = Policy { branches: vec![refund, pay.clone()] };
        let mut spend = Transaction::new();
        let path = policy.path(1).iter().map(|h| digest_to_bytes(*h)).collect();
        spend.add_policy_input(pay, 1, path, Some(preimage), 300).unwrap();
        spend.add_output(Output::new(&wots::keygen(&[15; 32]).1, 300)).unwrap();
        let commitment = Output::locked(policy.lock(), 300).commitment();
        for k in [0u8, 2] {
            let (sk, pk) = wots::keygen(&[11 + k; 32]);
            assert!(spend.sign_policy_input(&commitment, k, &pk, crate::keytree::KeyProof::one_time(), &sk));
        }
        assert!(spend.verify());
        // Two chunks (the spend's three signatures don't fit beside the
        // spends), so an aggregation too.
        let mut txs = spends(10);
        txs.push(spend);
        let b = block(txs);
        assert!(b.plan.chunks.len() > 1);
        let start = std::time::Instant::now();
        let proof = prove_block(&b.inputs, &b.outputs, &b.nonces, &b.txs, &b.plan, [7; 32]).expect("a policy spend proves");
        println!("proved in {:.2?}", start.elapsed());
        assert!(proof.verify(&b.inputs, &b.outputs, &b.nonces, &b.state, b.height, REWARD));
    }

    /// The wrap circuit's size for a full chunk (verifying its proof and
    /// applying its 28 state updates) against the tree's trace length.
    /// `cargo test --release -- --ignored --nocapture wrap_rows`.
    #[test]
    #[ignore]
    fn wrap_rows() {
        let b = block(spends(3));
        let k = 0;
        let txs: Vec<Transaction> = b.plan.chunks[k].iter().map(|&i| b.txs[i].clone()).collect();
        let spent: u64 = txs.iter().flat_map(|t| &t.inputs).map(|i| i.amount).sum();
        let created: u64 = txs.iter().flat_map(|t| &t.outputs).map(|o| o.amount).sum();
        let chunk = block_air::build_chunk(&txs, (created - spent, 0), CHUNK_SHAPE, &heights_of(&txs)).unwrap();
        let start = std::time::Instant::now();
        let proof = stark::prove(&chunk.air, &chunk.trace, &chunk_params(), [1; 32]).unwrap();
        println!("chunk proof: {:.2?}", start.elapsed());
        crate::recursion::clear_profile();
        let rows = aggregate::wrap_rows(&chunk.air, &proof, &b.plan.transitions[k], &chunk_params()).unwrap();
        let t = tree();
        println!("wrap circuit: {rows} rows of {} ({:.0}%)", t.trace_len, 100.0 * rows as f64 / t.trace_len as f64);
        crate::recursion::print_profile(rows, 1, chunk_params().num_queries);
    }

    /// Not a correctness test: proving costs. `COST=chunk`: one chunk
    /// proof (fixed shape, so any chunk costs the same). `COST=block
    /// INPUTS=n`: a whole block of `n` one-input spends plus the reward.
    /// Run with `COST=... cargo test --release -- --ignored --nocapture
    /// proof_costs` (under `/usr/bin/time -v` for peak memory).
    #[test]
    #[ignore]
    fn proof_costs() {
        let case = std::env::var("COST").unwrap_or_default();
        let count: u8 = std::env::var("INPUTS").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
        let b = block(spends(count));
        let time = std::time::Instant::now;
        match case.as_str() {
            "chunk" => {
                let chunk = block_air::build_chunk(&b.txs, (REWARD, 0), CHUNK_SHAPE, &heights_of(&b.txs)).unwrap();
                let start = time();
                let proof = stark::prove(&chunk.air, &chunk.trace, &chunk_params(), [1; 32]).unwrap();
                println!(
                    "chunk: {} rows; prove {:.2?}; {:.1} KB",
                    chunk.air.trace_len(),
                    start.elapsed(),
                    proof.to_bytes().len() as f64 / 1024.0
                );
            }
            "block" => {
                let start = time();
                let proof = prove_block(&b.inputs, &b.outputs, &b.nonces, &b.txs, &b.plan, [1; 32]).unwrap();
                let proving = start.elapsed();
                let start = time();
                assert!(proof.verify(&b.inputs, &b.outputs, &b.nonces, &b.state, b.height, REWARD));
                println!(
                    "{count} inputs, {} chunk(s): prove {proving:.2?} (keys included); {:.1} KB; verify {:.2?}",
                    b.plan.chunks.len(),
                    proof.len() as f64 / 1024.0,
                    start.elapsed()
                );
            }
            _ => panic!("set COST to chunk or block"),
        }
    }

    #[test]
    fn non_canonical_commitments_are_refused() {
        assert!(is_canonical(&[0u8; 32]));
        let mut bad = [0u8; 32];
        bad[..4].copy_from_slice(&P.to_le_bytes());
        assert!(!is_canonical(&bad));
    }
}
