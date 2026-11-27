//! `space-chain.json`: the record layout and its one spelling, the labelled hash link, the signing
//! input, seal commitments with real sealed boxes, and the chains of the spec's test cases, each
//! with the verdict a verifier must give. The generator and the check both work from the
//! scenarios of `space_chain::scenarios`; the check replays every case from its bytes.

use serde_json::{Map, Value, json};

use super::{document, hx};
use crate::{
    Error,
    backend::{Backend, rustcrypto::RustCrypto},
    space_chain::{
        Body, KeyRef, Reason, Record, SignedRecord, b64, link,
        scenarios::{Case, Expect, cases},
        seals::box_context,
        testkit::{ADMIN, ANA, Account, Kit, OWNER, OWNER2, general, space_id, uid},
        uuid_text,
    },
};

type G = RustCrypto;

/// The file's name.
pub(crate) const NAME: &str = "space-chain";

fn wire(record: &SignedRecord) -> Value {
    let mut m = Map::new();
    m.insert("entry".into(), hx(&record.entry));
    m.insert("signature".into(), hx(&record.signature));
    if let Some(c) = &record.cosignature {
        m.insert("cosignature".into(), hx(c));
    }
    Value::Object(m)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("a record is ASCII")
}

/// The two examples of the spec, which pin the layout and the link.
fn link_cases() -> Vec<Value> {
    let fence = Record {
        space: uid(1),
        seq: 7,
        prev: [0x11; 32],
        epoch: 2,
        at: 1_700_000_700,
        by: uid(2),
        body: Body::Fence {
            home: uid(0xf2),
            promotion: crate::hash::sha256(b"example promotion record"),
        },
    }
    .to_bytes();
    let fence_link = link(&fence);
    let role = Record {
        space: uid(1),
        seq: 8,
        prev: fence_link,
        epoch: 2,
        at: 1_700_000_800,
        by: uid(2),
        body: Body::Role {
            custom: vec![
                crate::space_chain::CustomPerm::CreateCollections,
                crate::space_chain::CustomPerm::ManageUsers,
            ],
            member: uid(3),
            role: crate::space_chain::Role::Custom,
        },
    }
    .to_bytes();
    [("spec-fence-example", fence), ("spec-role-example", role)]
        .into_iter()
        .map(|(name, bytes)| {
            json!({
                "type": "link",
                "name": name,
                "record": text(&bytes),
                "record_hex": hx(&bytes),
                "link": hx(&link(&bytes)),
                "link_b64url": b64::encode(&link(&bytes)),
                "unlabelled_sha256": hx(&crate::hash::sha256(&bytes)),
            })
        })
        .collect()
}

/// Spellings a reader must refuse, made from valid records by changing their text.
fn encoding_cases() -> Vec<Value> {
    let base = |body: Body| Record {
        space: uid(1),
        seq: 5,
        prev: [2; 32],
        epoch: 1,
        at: 1_700_000_000,
        by: uid(3),
        body,
    };
    let invite = text(
        &base(Body::Invite {
            custom: vec![
                crate::space_chain::CustomPerm::CreateCollections,
                crate::space_chain::CustomPerm::ManageUsers,
            ],
            grants: vec![],
            member: uid(0x0b),
            role: crate::space_chain::Role::Custom,
        })
        .to_bytes(),
    );
    let mv = text(
        &base(Body::Move {
            collection: uid(0x0a),
            parent: Some(uid(0x0b)),
        })
        .to_bytes(),
    );
    let members = text(
        &base(Body::GroupMembers {
            add: vec![uid(0x0a), uid(0x0c)],
            group: uid(0x0d),
            remove: vec![],
            replace: vec![],
        })
        .to_bytes(),
    );
    let grant = text(
        &base(Body::Grant {
            collection: uid(0x0a),
            grantee: crate::space_chain::Grantee::User(uid(0x0b)),
            permission: crate::space_chain::CollectionPerm::View,
        })
        .to_bytes(),
    );
    let (id_a, id_b, id_c) = (
        uuid_text(&uid(0x0a)),
        uuid_text(&uid(0x0b)),
        uuid_text(&uid(0x0c)),
    );
    let swap = |t: &str, from: &str, to: &str| {
        assert!(t.contains(from), "{from} is in {t}");
        t.replacen(from, to, 1)
    };
    let custom = "[\"create-collections\",\"manage-users\"]";
    let cases: Vec<(&str, String)> = vec![
        (
            "null for parent",
            swap(&mv, &format!("\"parent\":\"{id_b}\""), "\"parent\":null"),
        ),
        (
            "null for custom",
            swap(&invite, &format!("\"custom\":{custom}"), "\"custom\":null"),
        ),
        ("1.0", swap(&invite, "\"seq\":5", "\"seq\":1.0")),
        ("-1", swap(&invite, "\"seq\":5", "\"seq\":-1")),
        ("-0", swap(&invite, "\"seq\":5", "\"seq\":-0")),
        ("1e0", swap(&invite, "\"seq\":5", "\"seq\":1e0")),
        (
            "2^53",
            swap(&invite, "\"seq\":5", "\"seq\":9007199254740992"),
        ),
        ("a leading zero", swap(&invite, "\"seq\":5", "\"seq\":05")),
        (
            "a one-character role",
            swap(&invite, "\"role\":\"custom\"", "\"role\":\"A\""),
        ),
        (
            "a lone surrogate",
            swap(&invite, "\"role\":\"custom\"", "\"role\":\"\\ud800\""),
        ),
        (
            "custom out of order",
            swap(&invite, custom, "[\"manage-users\",\"create-collections\"]"),
        ),
        (
            "an id twice in add",
            swap(
                &members,
                &format!("\"add\":[\"{id_a}\",\"{id_c}\"]"),
                &format!("\"add\":[\"{id_a}\",\"{id_a}\"]"),
            ),
        ),
        (
            "a member name twice",
            swap(
                &invite,
                "\"role\":\"custom\"}",
                "\"role\":\"custom\",\"role\":\"custom\"}",
            ),
        ),
        (
            "a space after a colon",
            swap(&invite, "\"role\":\"custom\"", "\"role\": \"custom\""),
        ),
        (
            "an unknown member",
            swap(
                &grant,
                "\"permission\":\"view\"",
                "\"permission\":\"view\",\"zzz\":1",
            ),
        ),
        (
            "a missing member",
            swap(&grant, &format!("\"grantee\":\"user:{id_b}\","), ""),
        ),
        ("trailing bytes", format!("{grant}\n")),
        ("a byte-order mark", format!("\u{feff}{grant}")),
    ];
    cases
        .into_iter()
        .map(|(name, record)| {
            json!({
                "type": "encoding",
                "name": name,
                "record": record,
                "reason": Reason::Malformed.as_str(),
            })
        })
        .collect()
}

/// The signing input of a record, and its signature.
fn signing_case(valid: &Case) -> Value {
    let first = &valid.chain[0];
    let owner = Account::new::<G>(OWNER, 1);
    let mut input = b"kemlock/v1/sig1".to_vec();
    input.extend_from_slice(&[0, 0, 0, 11]);
    input.extend_from_slice(b"space-chain");
    input.extend_from_slice(
        &u32::try_from(first.entry.len())
            .expect("short")
            .to_be_bytes(),
    );
    input.extend_from_slice(&first.entry);
    json!({
        "type": "signing",
        "name": "record-signature",
        "record": hx(&first.entry),
        "signing_input": hx(&input),
        "signing_input_prefix": hx(b"kemlock/v1/sig1\x00\x00\x00\x0bspace-chain"),
        "public_key": hx(owner.bundle.sig1_public.as_bytes()),
        "signature": hx(&first.signature),
        "wrong_contexts": ["bundle", "manifest", "confirm"],
    })
}

/// Seal commitments with real boxes: the digest, the key check and each recipient's box.
fn seals_cases() -> Vec<Value> {
    let owner = uid(OWNER);
    let mut kit = Kit::new(space_id());
    for n in [OWNER, OWNER2, ANA, ADMIN] {
        kit.add(Account::new::<G>(n, 1));
    }
    kit.create::<G>(&owner, general());
    let recipients = [uid(OWNER2), uid(ANA), uid(ADMIN), owner];
    let mut out = Vec::new();
    for (name, key, version) in [
        ("space-key", KeyRef::Space, 2u32),
        ("collection-key", KeyRef::Collection(general()), 3u32),
    ] {
        let commitment = kit.make::<G>(key, version, &recipients);
        let secret = kit.secrets[&(key, version)];
        let mut ids = recipients.to_vec();
        ids.sort_unstable();
        let members: Vec<Value> = ids
            .iter()
            .map(|id| {
                let account = kit.acc(id);
                let sealed = &kit.boxes[&(key, version, *id)];
                let (context, aad) = box_context(&key, &space_id(), version, id);
                json!({
                    "member": hx(id),
                    "bundle_version": account.bundle.key_version,
                    "kx1_private_key": hx(account.kx.as_bytes()),
                    "context": context,
                    "aad": hx(&aad),
                    "box": hx(sealed),
                    "seal_hash": hx(&crate::space_chain::seal_hash(sealed)),
                })
            })
            .collect();
        out.push(json!({
            "type": "seals",
            "name": name,
            "space": hx(&space_id()),
            "key": key.text(),
            "version": version,
            "secret": hx(&secret),
            "digest": hx(&commitment.digest),
            "check": hx(&commitment.check.expect("a made version has a check")),
            "recipients": members,
        }));
    }
    out
}

fn chain_case(case: &Case, valid: &Case) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), json!("chain"));
    m.insert("name".into(), json!(case.name));
    m.insert("description".into(), json!(case.description));
    m.insert("space".into(), json!(uuid_text(&space_id())));
    // Chains share their start with the valid chain, so the file keeps it once.
    let common = case
        .chain
        .iter()
        .zip(&valid.chain)
        .take_while(|(a, b)| a == b)
        .count();
    let prefix = if case.name == valid.name { 0 } else { common };
    if prefix > 0 {
        m.insert("base".into(), json!(valid.name));
        m.insert("prefix".into(), json!(prefix));
    }
    m.insert(
        "records".into(),
        Value::Array(case.chain[prefix..].iter().map(wire).collect()),
    );
    if let Some(anchor) = &case.anchor {
        let mut a = Map::new();
        a.insert("seq".into(), json!(anchor.seq));
        a.insert("epoch".into(), json!(anchor.epoch));
        a.insert(
            "links".into(),
            json!(anchor.links.iter().map(|l| hx(l)).collect::<Vec<_>>()),
        );
        // The confirmed Owners the device kept with its anchor, each with SHA-256 of their bundle,
        // when it kept them.
        if let Some(owners) = &anchor.owners {
            let mut kept = Map::new();
            for (id, bundle) in owners {
                kept.insert(uuid_text(id), hx(bundle));
            }
            a.insert("owners".into(), Value::Object(kept));
        }
        // The promotion records the device holds and verified.
        if !anchor.promotions.is_empty() {
            a.insert(
                "promotions".into(),
                json!(
                    anchor
                        .promotions
                        .iter()
                        .map(|(home, promotion)| json!({
                            "home": uuid_text(home),
                            "promotion": hx(promotion),
                        }))
                        .collect::<Vec<_>>()
                ),
            );
        }
        m.insert("anchor".into(), Value::Object(a));
    }
    let expect = match case.expect {
        Expect::Accepted {
            head_seq,
            divergence,
        } => {
            let head = case.chain.last().expect("a chain");
            let mut e = Map::new();
            e.insert("verdict".into(), json!("accepted"));
            e.insert("head_seq".into(), json!(head_seq));
            e.insert("head_link".into(), hx(&link(&head.entry)));
            if let Some(d) = divergence {
                e.insert("divergence".into(), json!(d));
            }
            Value::Object(e)
        }
        Expect::Refused { seq, reason } => {
            let mut e = Map::new();
            e.insert("verdict".into(), json!("refused"));
            e.insert("reason".into(), json!(reason.as_str()));
            if let Some(seq) = seq {
                e.insert("seq".into(), json!(seq));
            }
            Value::Object(e)
        }
    };
    m.insert("expect".into(), expect);
    Value::Object(m)
}

/// The end of a chain ("Limits", "The end of a chain"): which records a chain taken to a given
/// `seq` and byte total still takes, from whom. Each case names the `seq` the record would have,
/// the chain's record `bytes` with it, the signer's `role`, the record's `kind`, and for a `keys`
/// record whether every key it replaces is marked, and says whether the record is `taken`.
fn end_of_chain_cases() -> Vec<Value> {
    use crate::space_chain::Limits;
    let mut out = Vec::new();
    let mut case =
        |name: &str, seq: u64, bytes: u64, role: &str, kind: &str, marked: bool, taken: bool| {
            out.push(json!({
                "type": "end-of-chain",
                "name": name,
                "seq": seq,
                "bytes": bytes,
                "role": role,
                "kind": kind,
                "keys_marked": marked,
                "expect": if taken { "taken" } else { "refused" },
            }));
        };
    let (open, owner_only) = (Limits::OPEN_RECORDS, Limits::OWNER_ONLY_FROM);
    let (open_bytes, owner_bytes) = (Limits::OPEN_BYTES, Limits::OWNER_ONLY_BYTES);
    // By record count.
    case(
        "records-before-the-reserve",
        open - 1,
        1_000,
        "admin",
        "policies",
        false,
        true,
    );
    case(
        "records-in-the-reserve-a-policy",
        open,
        1_000,
        "admin",
        "policies",
        false,
        false,
    );
    case(
        "records-in-the-reserve-a-removal",
        open,
        1_000,
        "admin",
        "remove",
        false,
        true,
    );
    case(
        "records-in-the-reserve-marked-keys",
        open,
        1_000,
        "admin",
        "keys",
        true,
        true,
    );
    case(
        "records-in-the-reserve-unmarked-keys",
        open,
        1_000,
        "admin",
        "keys",
        false,
        false,
    );
    case(
        "records-in-the-reserve-unmarked-keys-of-a-manager",
        open,
        1_000,
        "custom",
        "keys",
        false,
        false,
    );
    case(
        "records-last-of-the-reserve-a-removal",
        owner_only - 1,
        1_000,
        "member",
        "remove",
        false,
        true,
    );
    case(
        "records-owner-only-a-removal",
        owner_only,
        1_000,
        "member",
        "remove",
        false,
        false,
    );
    case(
        "records-owner-only-marked-keys",
        owner_only,
        1_000,
        "admin",
        "keys",
        true,
        false,
    );
    case(
        "records-owner-only-an-owner",
        Limits::CHAIN_RECORDS - 1,
        1_000,
        "owner",
        "policies",
        false,
        true,
    );
    // By record bytes.
    case(
        "bytes-before-the-reserve",
        100,
        open_bytes,
        "admin",
        "policies",
        false,
        true,
    );
    case(
        "bytes-in-the-reserve-a-policy",
        100,
        open_bytes + 1,
        "admin",
        "policies",
        false,
        false,
    );
    case(
        "bytes-in-the-reserve-a-removal",
        100,
        open_bytes + 1,
        "admin",
        "remove",
        false,
        true,
    );
    case(
        "bytes-in-the-reserve-marked-keys",
        100,
        open_bytes + 1,
        "admin",
        "keys",
        true,
        true,
    );
    case(
        "bytes-in-the-reserve-unmarked-keys",
        100,
        open_bytes + 1,
        "admin",
        "keys",
        false,
        false,
    );
    case(
        "bytes-last-of-the-reserve-a-removal",
        100,
        owner_bytes,
        "admin",
        "remove",
        false,
        true,
    );
    case(
        "bytes-owner-only-a-removal",
        100,
        owner_bytes + 1,
        "admin",
        "remove",
        false,
        false,
    );
    case(
        "bytes-owner-only-an-owner",
        100,
        Limits::CHAIN_BYTES_U64,
        "owner",
        "remove",
        false,
        true,
    );
    out
}

/// The whole file.
pub(crate) fn generate() -> Result<Value, Error> {
    let seed = G::sha256(b"kemlock-vectors/space-chain");
    crate::with_seeded_random(seed, || {
        let all = cases::<G>();
        let valid = all[0].clone();
        let mut out = link_cases();
        out.extend(encoding_cases());
        out.push(signing_case(&valid));
        out.extend(seals_cases());
        out.extend(end_of_chain_cases());
        for case in &all {
            out.push(chain_case(case, &valid));
        }
        Ok(document(
            NAME,
            "The space chain (docs/crypto.md, \"Space chain\"). `link` cases pin the labelled hash \
             link: link = SHA-256(\"kemlock/v1/space-chain/link\" || record bytes), the spec's two \
             examples; `encoding` cases are records a reader must refuse as malformed; the \
             `signing` case pins the signing input, \"kemlock/v1/sig1\" || lp(\"space-chain\") || \
             lp(record), and a record signature; `seals` cases pin commitments: seal hash = \
             SHA-256(box), digest, key check, and each recipient's box with its context and aad; \
             `end-of-chain` cases give the `seq` and record `bytes` a record would take the chain \
             to, its signer's `role`, its `kind` and whether the keys of a `keys` record are \
             marked, and say whether the chain takes it (`taken`) or not (`refused`); \
             `chain` cases are chains of records (the first case is a valid chain with every kind; \
             a chain that has `base` and `prefix` starts with that many records of the base chain) \
             with the verdict a verifier must give: accepted with the head, or refused with the \
             reason and the seq. A chain with an `anchor` is verified against it. Bytes are \
             lower-case hex, except that `record` and `link_b64url` are text.",
            out,
        ))
    })
}

// ---- the check --------------------------------------------------------------------------------

#[cfg(test)]
pub(crate) use check::check;

#[cfg(test)]
mod check {
    use std::collections::BTreeMap;

    use serde_json::Value;

    use super::NAME;
    use crate::{
        backend::Backend,
        bundle::Bundle,
        kx1, sealed_box,
        sig1::{self, context::SPACE_CHAIN},
        space_chain::{
            Anchor, KeyRef, Kind, Reason, Record, Role, SignedRecord, b64, end_of_chain_allows,
            key_check, link, parse_uuid,
            seals::{key_check_in, seal_digest_in},
            verify::verify_chain_in,
            verify_record_signature,
        },
    };

    fn s<'a>(v: &'a Value, key: &str) -> &'a str {
        v[key]
            .as_str()
            .unwrap_or_else(|| panic!("`{key}` is missing or not a string in {v}"))
    }

    fn bytes(v: &Value, key: &str) -> Vec<u8> {
        hex::decode(s(v, key)).unwrap_or_else(|e| panic!("`{key}` is not hex: {e}"))
    }

    fn arr<const N: usize>(v: &Value, key: &str) -> [u8; N] {
        bytes(v, key)
            .try_into()
            .unwrap_or_else(|b: Vec<u8>| panic!("`{key}` is {} bytes, not {N}", b.len()))
    }

    fn int(v: &Value, key: &str) -> u64 {
        v[key]
            .as_u64()
            .unwrap_or_else(|| panic!("`{key}` is missing or not an integer in {v}"))
    }

    fn record(v: &Value) -> SignedRecord {
        SignedRecord {
            entry: bytes(v, "entry"),
            signature: bytes(v, "signature"),
            cosignature: v.get("cosignature").map(|_| bytes(v, "cosignature")),
        }
    }

    fn link_case(case: &Value) {
        let record_text = s(case, "record").as_bytes();
        assert_eq!(record_text, bytes(case, "record_hex"), "{case}");
        let expected = arr::<32>(case, "link");
        assert_eq!(link(record_text), expected);
        assert_eq!(b64::encode(&expected), s(case, "link_b64url"));
        assert_ne!(
            crate::hash::sha256(record_text).as_slice(),
            expected.as_slice()
        );
        assert_eq!(
            hex::encode(crate::hash::sha256(record_text)),
            s(case, "unlabelled_sha256")
        );
        let parsed = Record::parse(record_text).expect("the example is a record");
        assert_eq!(parsed.to_bytes(), record_text);
    }

    fn encoding_case(case: &Value) {
        assert_eq!(s(case, "reason"), Reason::Malformed.as_str());
        assert_eq!(
            Record::parse(s(case, "record").as_bytes()),
            Err(Reason::Malformed),
            "{}",
            s(case, "name")
        );
    }

    fn end_of_chain_case(case: &Value) {
        let name = s(case, "name");
        let role = Role::parse(s(case, "role")).expect("a role");
        let kind = Kind::parse(s(case, "kind")).expect("a kind");
        let taken = end_of_chain_allows(
            int(case, "seq"),
            int(case, "bytes"),
            role,
            kind,
            case["keys_marked"].as_bool().expect("a bool"),
        );
        match s(case, "expect") {
            "taken" => assert!(taken, "{name}"),
            "refused" => assert!(!taken, "{name}"),
            other => panic!("{name}: unknown expectation {other}"),
        }
    }

    fn signing_case<B: Backend>(case: &Value) {
        let record = bytes(case, "record");
        let mut input = bytes(case, "signing_input_prefix");
        input.extend_from_slice(&u32::try_from(record.len()).expect("short").to_be_bytes());
        input.extend_from_slice(&record);
        assert_eq!(input, bytes(case, "signing_input"));
        assert_eq!(&input[..15], b"kemlock/v1/sig1");
        let public = sig1::PublicKey::from_bytes(&bytes(case, "public_key")).expect("public key");
        let signature = bytes(case, "signature");
        sig1::verify_in::<B>(&public, SPACE_CHAIN, &record, &signature).expect("verifies");
        verify_record_signature(&public, &record, &signature).expect("verifies");
        for context in case["wrong_contexts"].as_array().expect("contexts") {
            let context = context.as_str().expect("a context");
            assert!(sig1::verify_in::<B>(&public, context, &record, &signature).is_err());
        }
        let mut changed = record.clone();
        changed[10] ^= 1;
        assert!(sig1::verify_in::<B>(&public, SPACE_CHAIN, &changed, &signature).is_err());
    }

    fn seals_case<B: Backend>(case: &Value) {
        let space: [u8; 16] = arr(case, "space");
        let key = KeyRef::parse(s(case, "key")).expect("a key ref");
        let version = u32::try_from(int(case, "version")).expect("u32");
        let secret: [u8; 32] = arr(case, "secret");
        assert_eq!(
            key_check_in::<B>(&space, &key, version, &secret).expect("check"),
            arr::<32>(case, "check"),
            "{}",
            B::NAME
        );
        assert_eq!(
            key_check(&space, &key, version, &secret).expect("check"),
            arr::<32>(case, "check")
        );
        let mut entries = Vec::new();
        let mut previous: Option<[u8; 16]> = None;
        for r in case["recipients"].as_array().expect("recipients") {
            let member: [u8; 16] = arr(r, "member");
            assert!(previous.is_none_or(|p| p < member), "ascending");
            previous = Some(member);
            let bundle_version = u32::try_from(int(r, "bundle_version")).expect("u32");
            let sealed = bytes(r, "box");
            assert_eq!(sealed.len(), 1661);
            assert_eq!(sealed[0], 1);
            let hash = B::sha256(&sealed);
            assert_eq!(hex::encode(hash), s(r, "seal_hash"));
            entries.push((member, bundle_version, hash));
            // The box opens, with the documented context and aad, to the key.
            let private = kx1::PrivateKey::from_bytes(&arr(r, "kx1_private_key"));
            let opened =
                sealed_box::open_in::<B>(&private, s(r, "context"), &bytes(r, "aad"), &sealed)
                    .expect("the box opens");
            assert_eq!(opened.as_slice(), secret.as_slice(), "{}", B::NAME);
            // Not under another aad.
            let mut other = bytes(r, "aad");
            other[0] ^= 1;
            assert!(sealed_box::open_in::<B>(&private, s(r, "context"), &other, &sealed).is_err());
        }
        assert_eq!(
            seal_digest_in::<B>(&space, &key, version, &entries),
            arr::<32>(case, "digest"),
            "{}",
            B::NAME
        );
        // The aad layout, rebuilt by hand.
        for r in case["recipients"].as_array().expect("recipients") {
            let member: [u8; 16] = arr(r, "member");
            let mut aad = space.to_vec();
            match key {
                KeyRef::Space => {
                    assert_eq!(s(r, "context"), "space-key");
                    aad.extend_from_slice(&version.to_be_bytes());
                }
                KeyRef::Collection(id) => {
                    assert_eq!(s(r, "context"), "collection-key");
                    aad.extend_from_slice(&id);
                    aad.extend_from_slice(&version.to_be_bytes());
                }
            }
            aad.extend_from_slice(&member);
            assert_eq!(aad, bytes(r, "aad"));
        }
    }

    fn chain_case<B: Backend>(
        case: &Value,
        known: &BTreeMap<String, Vec<SignedRecord>>,
    ) -> Vec<SignedRecord> {
        let name = s(case, "name");
        let space = parse_uuid(s(case, "space")).expect("a space id");
        let mut chain: Vec<SignedRecord> = Vec::new();
        if let Some(base) = case.get("base") {
            let base = known
                .get(base.as_str().expect("a name"))
                .expect("an earlier chain");
            let prefix = usize::try_from(int(case, "prefix")).expect("small");
            chain.extend(base[..prefix].iter().cloned());
        }
        chain.extend(
            case["records"]
                .as_array()
                .expect("records")
                .iter()
                .map(record),
        );
        let anchor = case.get("anchor").map(|a| Anchor {
            seq: int(a, "seq"),
            epoch: u32::try_from(int(a, "epoch")).expect("u32"),
            links: a["links"]
                .as_array()
                .expect("links")
                .iter()
                .map(|l| {
                    hex::decode(l.as_str().expect("hex"))
                        .expect("hex")
                        .try_into()
                        .expect("32 bytes")
                })
                .collect(),
            owners: a.get("owners").map(|owners| {
                owners
                    .as_object()
                    .expect("owners")
                    .iter()
                    .map(|(id, bundle)| {
                        (
                            parse_uuid(id).expect("a uuid"),
                            hex::decode(bundle.as_str().expect("hex"))
                                .expect("hex")
                                .try_into()
                                .expect("32 bytes"),
                        )
                    })
                    .collect()
            }),
            promotions: a
                .get("promotions")
                .map(|list| {
                    list.as_array()
                        .expect("promotions")
                        .iter()
                        .map(|p| {
                            (
                                parse_uuid(s(p, "home")).expect("a uuid"),
                                hex::decode(s(p, "promotion"))
                                    .expect("hex")
                                    .try_into()
                                    .expect("32 bytes"),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
        });
        let verdict = verify_chain_in::<B>(&space, &chain, anchor.as_ref());
        let expect = &case["expect"];
        match s(expect, "verdict") {
            "accepted" => {
                let verified = verdict.unwrap_or_else(|e| panic!("{name} on {}: {e}", B::NAME));
                assert_eq!(
                    verified.state.head.map(|h| h.seq),
                    Some(int(expect, "head_seq")),
                    "{name}"
                );
                assert_eq!(
                    verified.links.last().map(hex::encode),
                    Some(s(expect, "head_link").to_owned()),
                    "{name}"
                );
                assert_eq!(
                    verified.divergence,
                    expect.get("divergence").map(|_| int(expect, "divergence")),
                    "{name}"
                );
            }
            "refused" => {
                let err = verdict.expect_err(name);
                assert_eq!(
                    err.reason.as_str(),
                    s(expect, "reason"),
                    "{name} on {}",
                    B::NAME
                );
                assert_eq!(
                    err.seq,
                    expect.get("seq").map(|_| int(expect, "seq")),
                    "{name} on {}",
                    B::NAME
                );
            }
            other => panic!("{name}: unknown verdict {other}"),
        }
        chain
    }

    /// Checks the whole file on one backend.
    pub(crate) fn check<B: Backend>(doc: &Value) {
        assert_eq!(s(doc, "format"), NAME);
        let mut known: BTreeMap<String, Vec<SignedRecord>> = BTreeMap::new();
        let mut kinds = std::collections::BTreeSet::new();
        for case in doc["cases"].as_array().expect("cases") {
            kinds.insert(s(case, "type").to_owned());
            match s(case, "type") {
                "link" => link_case(case),
                "encoding" => encoding_case(case),
                "signing" => signing_case::<B>(case),
                "seals" => seals_case::<B>(case),
                "end-of-chain" => end_of_chain_case(case),
                "chain" => {
                    let chain = chain_case::<B>(case, &known);
                    known.insert(s(case, "name").to_owned(), chain);
                }
                other => panic!("unknown space-chain case type {other}"),
            }
        }
        for needed in [
            "link",
            "encoding",
            "signing",
            "seals",
            "end-of-chain",
            "chain",
        ] {
            assert!(kinds.contains(needed), "no {needed} case");
        }
        // The valid chain has every kind of record.
        let valid = known.get("valid-every-kind").expect("the valid chain");
        let used: std::collections::BTreeSet<_> = valid
            .iter()
            .map(|r| Record::parse(&r.entry).expect("a record").kind())
            .collect();
        assert_eq!(used.len(), crate::space_chain::Kind::ALL.len());
        // A public bundle in the chain carries what the chain says about its own key.
        let first = Record::parse(&valid[0].entry).expect("a record");
        if let crate::space_chain::Body::Create { bundle, .. } = first.body {
            assert_eq!(
                Bundle::from_bytes(&bundle).expect("a bundle").account_id,
                first.by
            );
        } else {
            panic!("the chain starts with a create");
        }
        let _ = link(&valid[0].entry);
    }
}
