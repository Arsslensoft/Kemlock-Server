//! `sig1-edge.json`: the edge cases of the Ed25519 verification rule (docs/crypto.md). The inputs are
//! fixed bytes, computed once with an independent RFC 8032 reference implementation (the cases of
//! Chalkias et al., "Taming the many EdDSAs", 2020), so this file has no random source. The check
//! of the cases is in `check.rs`.

use serde_json::{Value, json};

use super::document;

/// One case: a bare Ed25519 verification and its two verdicts.
#[derive(Debug)]
struct Case {
    name: &'static str,
    description: &'static str,
    public_key: &'static str,
    message: &'static str,
    signature: &'static str,
    /// Whether the key passes the parse-time check of `sig1::PublicKey::from_bytes`.
    key_ok: bool,
    /// Whether verification passes.
    valid: bool,
}

const DESCRIPTION: &str = "Ed25519 edge cases for the one verification rule of docs/crypto.md (Ed25519 verification rule), the inputs of Chalkias et al., Taming the many EdDSAs (2020): small-order key, non-canonical key, non-canonical S, small-order R, non-canonical R, mixed-order key. Each case is a bare Ed25519 check (public_key, message, signature as hex): key_ok is whether the key passes the parse-time check of sig1 public keys (canonical, not of small order), valid is whether verification must pass. Every backend gives the same verdicts. The values were computed with an independent RFC 8032 reference implementation, not with the code under test; the small-order and non-canonical keys are the known encodings (the identity, the points of order 2 and 8, and y = p + 1).";

const CASES: &[Case] = &[
    Case {
        name: "valid",
        description: "An ordinary signature by an ordinary key: accepted.",
        public_key: "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
        message: "6b656d6c6f636b20736967312d6564676520766563746f72",
        signature: "f9600c963459ba120688b259a8a5d26359755be8de9d70c88aa2f614b6c455eb6dbe9d551156b4029254fdd46250e4fa9e8c8487b5fa1a619339a090821ea407",
        key_ok: true,
        valid: true,
    },
    Case {
        name: "small-order-key-identity",
        description: "The key is the identity point (order 1). R is the identity and S is zero, so the check without the rule passes for every message. Refused: a small-order key.",
        public_key: "0100000000000000000000000000000000000000000000000000000000000000",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7200",
        signature: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        key_ok: false,
        valid: false,
    },
    Case {
        name: "small-order-key-order-2",
        description: "The key is the point of order 2 (y = p - 1). R is the identity and S is zero; passes the bare equation for a message whose hash is even. Refused: a small-order key.",
        public_key: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7200",
        signature: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        key_ok: false,
        valid: false,
    },
    Case {
        name: "small-order-key-order-8",
        description: "The key is a point of order 8. R is the identity and S is zero; passes the bare equation for a message whose hash is a multiple of 8. Refused: a small-order key.",
        public_key: "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        message: "6b656d6c6f636b20736967312d6564676520766563746f720d",
        signature: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        key_ok: false,
        valid: false,
    },
    Case {
        name: "non-canonical-key-identity",
        description: "The key is the identity written as y = p + 1 (ee ff .. 7f), which a loose decoder reads as y = 1. R is the identity and S zero. Refused: a non-canonical key.",
        public_key: "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7200",
        signature: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        key_ok: false,
        valid: false,
    },
    Case {
        name: "non-canonical-key-point",
        description: "The key is a point that is not of small order, written non-canonically as y = 3 + p. The signature is another key's, so it fails anyway; the case pins that the key is refused by its encoding. Refused: a non-canonical key.",
        public_key: "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7201",
        signature: "3cebac4dcc8f4c47353010289a58c3a2cef783da457f0b5a33eda54771ab8b1face516d745f11fca96c54ce66ba429aaf04df0a493dc58a54acbc244fec7b10d",
        key_ok: false,
        valid: false,
    },
    Case {
        name: "canonical-twin-of-non-canonical-key",
        description: "The same point as the previous case, written canonically (y = 3). The key is acceptable; the signature is another key's, so verification fails.",
        public_key: "0300000000000000000000000000000000000000000000000000000000000000",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7201",
        signature: "3cebac4dcc8f4c47353010289a58c3a2cef783da457f0b5a33eda54771ab8b1face516d745f11fca96c54ce66ba429aaf04df0a493dc58a54acbc244fec7b10d",
        key_ok: true,
        valid: false,
    },
    Case {
        name: "non-canonical-s",
        description: "An honest signature with S replaced by S + L (below 2^253, so even a verifier that only checks the top three bits takes it). It satisfies the equation. Refused: S is not below L.",
        public_key: "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7200",
        signature: "58c44993b979a8b9a1cadbe596d92b1914d129d2a37c86e4e394b4a91d18e1351ed406bf7244c9e329c8daaa9c5190d5da34a1bd84c9f732475043c2f6b9311b",
        key_ok: true,
        valid: false,
    },
    Case {
        name: "canonical-s-of-the-same-signature",
        description: "The honest signature that the previous case was made from: accepted.",
        public_key: "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7200",
        signature: "58c44993b979a8b9a1cadbe596d92b1914d129d2a37c86e4e394b4a91d18e1353100116258e1b68b532be307be57b1c0da34a1bd84c9f732475043c2f6b9310b",
        key_ok: true,
        valid: true,
    },
    Case {
        name: "small-order-r",
        description: "The key is an ordinary key and R is the identity (order 1); S = k * a mod L, so the bare equation holds. Refused: a small-order R.",
        public_key: "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7202",
        signature: "010000000000000000000000000000000000000000000000000000000000000044742e9b1e58525876d7288762cc7c90d23e40c110d5c2ecd832422ab0a43f09",
        key_ok: true,
        valid: false,
    },
    Case {
        name: "non-canonical-r",
        description: "As the previous case, with R written as y = p + 1 (ee ff .. 7f). Refused: a non-canonical R.",
        public_key: "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7202",
        signature: "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f399d2f3f88b5865010456fa0dc2c03342ee3504bc5ac3e0247fe5cf5e641350a",
        key_ok: true,
        valid: false,
    },
    Case {
        name: "non-canonical-key-identity-sign-bit",
        description: "The key is the identity written with the sign bit set (01 00 .. 80), which is not the canonical form of any point. R is the identity and S zero. Refused: a non-canonical key.",
        public_key: "0100000000000000000000000000000000000000000000000000000000000080",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7200",
        signature: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        key_ok: false,
        valid: false,
    },
    Case {
        name: "mixed-order-key",
        description: "The key is a * B + T, where T has order 8: it is not of small order, and it is canonical. R carries the matching torsion part so that the (cofactorless) equation holds exactly. Accepted: the rule does not refuse mixed-order keys, and every verifier that checks the equation exactly agrees.",
        public_key: "c6e2cb790d0e8833a455b24cc304bf11cc0e2d0b6625c64663aa9ee64506188d",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7200",
        signature: "a83e5207873d7885b2a38dabe480bac8dcf84ca0da488ee63fa09d20481a18ba90a37fba0417393fb3019b76d2eb5a2367da9a817d93c7cd1d85a3ef4b95e60d",
        key_ok: true,
        valid: true,
    },
    Case {
        name: "key-not-on-the-curve",
        description: "The key is y = 2 (little endian), which no point has. It passes the encoding check and every verification fails. Refused: not a curve point.",
        public_key: "0200000000000000000000000000000000000000000000000000000000000000",
        message: "6b656d6c6f636b20736967312d6564676520766563746f7203",
        signature: "8976ca310916b1bee83bce79218834d2879a176cb62f85ac8fd6ddceeabfdf69bcc4909a7bcdc8e4c8b3d8b1986b5c66c4d8c82be3aadf3827701de26cff1405",
        key_ok: true,
        valid: false,
    },
    Case {
        name: "short-signature",
        description: "An honest signature one byte short. Refused: a signature is 64 bytes.",
        public_key: "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
        message: "6b656d6c6f636b20736967312d6564676520766563746f72",
        signature: "f9600c963459ba120688b259a8a5d26359755be8de9d70c88aa2f614b6c455eb6dbe9d551156b4029254fdd46250e4fa9e8c8487b5fa1a619339a090821ea4",
        key_ok: true,
        valid: false,
    },
];

pub(crate) fn generate() -> Value {
    let cases = CASES
        .iter()
        .map(|c| {
            json!({
                "name": c.name,
                "description": c.description,
                "public_key": c.public_key,
                "message": c.message,
                "signature": c.signature,
                "key_ok": c.key_ok,
                "valid": c.valid,
            })
        })
        .collect();
    document("sig1-edge", DESCRIPTION, cases)
}
