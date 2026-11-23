//! Reading and writing a record's canonical bytes (docs/crypto.md, "Space chain", "Record" and
//! "Encoding"), and the wire form of a signed record.

use super::{
    Limits, b64,
    json::{self, Json},
    model::{
        Body, CollectionPerm, Commitment, CustomPerm, Grantee, Hash, Id, KeyRef, Kind, NameTarget,
        Policies, Reason, Record, Role, SignedRecord, TimeoutAction, parse_uuid, uuid_text,
    },
};
use crate::sig1;

/// A bundle's length, the signatures' and the statement's, as the shapes need them.
const BUNDLE_LEN: usize = crate::bundle::BUNDLE_LEN;
const SIGNATURE_LEN: usize = sig1::SIGNATURE_LEN;
const STATEMENT_LEN: usize = crate::confirm::STATEMENT_LEN;
const KX1_LEN: usize = crate::kx1::PUBLIC_KEY_LEN;

type R<T> = Result<T, Reason>;

/// What the shape checks found that isn't a shape error: a list past its limit.
#[derive(Default)]
struct Cx {
    too_large: bool,
}

// ---- writing ----------------------------------------------------------------------------------

fn id_json(id: &Id) -> Json {
    Json::Str(uuid_text(id))
}

fn bin_json(bytes: &[u8]) -> Json {
    Json::Str(b64::encode(bytes))
}

fn ids_json(ids: &[Id]) -> Json {
    Json::Arr(ids.iter().map(id_json).collect())
}

fn keys_json(keys: &[KeyRef]) -> Json {
    Json::Arr(keys.iter().map(|k| Json::Str(k.text())).collect())
}

fn custom_json(custom: &[CustomPerm]) -> Json {
    Json::Arr(custom.iter().map(|p| Json::str(p.as_str())).collect())
}

fn commitment_json(c: &Commitment) -> Json {
    let mut pairs = vec![
        ("count", Json::Int(u64::from(c.count))),
        ("digest", bin_json(&c.digest)),
        ("key", Json::Str(c.key.text())),
        ("version", Json::Int(u64::from(c.version))),
    ];
    if let Some(check) = &c.check {
        pairs.push(("check", bin_json(check)));
    }
    Json::obj(pairs)
}

fn commitments_json(list: &[Commitment]) -> Json {
    Json::Arr(list.iter().map(commitment_json).collect())
}

fn policies_json(p: &Policies) -> Json {
    let mp = &p.master_password;
    Json::obj(vec![
        ("accountRecovery", Json::Bool(p.account_recovery)),
        ("alwaysShowEmail", Json::Bool(p.always_show_email)),
        ("centralOwnership", Json::Bool(p.central_ownership)),
        ("disableExport", Json::Bool(p.disable_export)),
        ("disableSend", Json::Bool(p.disable_send)),
        ("duplicateMatching", Json::Bool(p.duplicate_matching)),
        (
            "masterPassword",
            Json::obj(vec![
                ("enforceOnLogin", Json::Bool(mp.enforce_on_login)),
                ("minComplexity", Json::Int(u64::from(mp.min_complexity))),
                ("minLength", Json::Int(u64::from(mp.min_length))),
                ("requireLower", Json::Bool(mp.require_lower)),
                ("requireNumbers", Json::Bool(mp.require_numbers)),
                ("requireSpecial", Json::Bool(mp.require_special)),
                ("requireUpper", Json::Bool(mp.require_upper)),
            ]),
        ),
        ("noCardItems", Json::Bool(p.no_card_items)),
        ("noPinUnlock", Json::Bool(p.no_pin_unlock)),
        ("requireSso", Json::Bool(p.require_sso)),
        (
            "sessionTimeout",
            Json::obj(vec![
                ("action", Json::str(p.session_timeout.action.as_str())),
                ("minutes", Json::Int(u64::from(p.session_timeout.minutes))),
            ]),
        ),
        ("singleSpace", Json::Bool(p.single_space)),
        ("twoStep", Json::Bool(p.two_step)),
    ])
}

fn body_json(body: &Body) -> Json {
    match body {
        Body::Create {
            bundle,
            bundle_signature,
            collection,
            collection_name,
            member,
            name_hash,
            seals,
        } => Json::obj(vec![
            ("bundle", bin_json(bundle)),
            ("bundleSignature", bin_json(bundle_signature)),
            (
                "collection",
                Json::obj(vec![
                    ("id", id_json(collection)),
                    ("nameHash", bin_json(collection_name)),
                ]),
            ),
            ("member", id_json(member)),
            ("nameHash", bin_json(name_hash)),
            ("seals", commitments_json(seals)),
        ]),
        Body::Invite {
            custom,
            grants,
            member,
            role,
        } => Json::obj(vec![
            ("custom", custom_json(custom)),
            (
                "grants",
                Json::Arr(
                    grants
                        .iter()
                        .map(|(c, p)| {
                            Json::obj(vec![
                                ("collection", id_json(c)),
                                ("permission", Json::str(p.as_str())),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("member", id_json(member)),
            ("role", Json::str(role.as_str())),
        ]),
        Body::Confirm {
            bundle,
            bundle_signature,
            member,
            statement,
            statement_signature,
        } => Json::obj(vec![
            ("bundle", bin_json(bundle)),
            ("bundleSignature", bin_json(bundle_signature)),
            ("member", id_json(member)),
            ("statement", bin_json(statement)),
            ("statementSignature", bin_json(statement_signature)),
        ]),
        Body::Rekey {
            bundle,
            bundle_signature,
        } => Json::obj(vec![
            ("bundle", bin_json(bundle)),
            ("bundleSignature", bin_json(bundle_signature)),
        ]),
        Body::Role {
            custom,
            member,
            role,
        } => Json::obj(vec![
            ("custom", custom_json(custom)),
            ("member", id_json(member)),
            ("role", Json::str(role.as_str())),
        ]),
        Body::Remove { member, replace } => Json::obj(vec![
            ("member", id_json(member)),
            ("replace", keys_json(replace)),
        ]),
        Body::Grant {
            collection,
            grantee,
            permission,
        } => Json::obj(vec![
            ("collection", id_json(collection)),
            ("grantee", Json::Str(grantee.text())),
            ("permission", Json::str(permission.as_str())),
        ]),
        Body::Ungrant {
            collection,
            grantee,
            replace,
        } => Json::obj(vec![
            ("collection", id_json(collection)),
            ("grantee", Json::Str(grantee.text())),
            ("replace", keys_json(replace)),
        ]),
        Body::Collection {
            collection,
            grants,
            name_hash,
            parent,
            seals,
        } => {
            let mut pairs = vec![
                ("collection", id_json(collection)),
                (
                    "grants",
                    Json::Arr(
                        grants
                            .iter()
                            .map(|(g, p)| {
                                Json::obj(vec![
                                    ("grantee", Json::Str(g.text())),
                                    ("permission", Json::str(p.as_str())),
                                ])
                            })
                            .collect(),
                    ),
                ),
                ("nameHash", bin_json(name_hash)),
                ("seals", commitments_json(seals)),
            ];
            if let Some(parent) = parent {
                pairs.push(("parent", id_json(parent)));
            }
            Json::obj(pairs)
        }
        Body::Move { collection, parent } => {
            let mut pairs = vec![("collection", id_json(collection))];
            if let Some(parent) = parent {
                pairs.push(("parent", id_json(parent)));
            }
            Json::obj(pairs)
        }
        Body::CollectionDelete { collection } => {
            Json::obj(vec![("collection", id_json(collection))])
        }
        Body::Group { group, name_hash } => Json::obj(vec![
            ("group", id_json(group)),
            ("nameHash", bin_json(name_hash)),
        ]),
        Body::GroupMembers {
            add,
            group,
            remove,
            replace,
        } => Json::obj(vec![
            ("add", ids_json(add)),
            ("group", id_json(group)),
            ("remove", ids_json(remove)),
            ("replace", keys_json(replace)),
        ]),
        Body::GroupDelete { group, replace } => Json::obj(vec![
            ("group", id_json(group)),
            ("replace", keys_json(replace)),
        ]),
        Body::Rename { name_hash, target } => Json::obj(vec![
            ("nameHash", bin_json(name_hash)),
            ("target", Json::Str(target.text())),
        ]),
        Body::Seal { seals } => Json::obj(vec![("seals", commitments_json(seals))]),
        Body::Keys { names, rotate } => {
            let mut pairs = vec![("rotate", commitments_json(rotate))];
            if let Some(names) = names {
                pairs.push(("names", bin_json(names)));
            }
            Json::obj(pairs)
        }
        Body::Policies { policies } => Json::obj(vec![("policies", policies_json(policies))]),
        Body::RecoveryKey { key } => Json::obj(vec![("key", bin_json(key))]),
        Body::RecoveryKeyClear => Json::obj(vec![]),
        Body::Fence { home, promotion } => Json::obj(vec![
            ("home", id_json(home)),
            ("promotion", bin_json(promotion)),
        ]),
    }
}

impl Record {
    /// The record's bytes: its RFC 8785 serialisation, which for this subset is the text the
    /// format describes. They are what is signed and hashed.
    pub fn to_bytes(&self) -> Vec<u8> {
        let value = Json::obj(vec![
            ("at", Json::Int(self.at)),
            ("body", body_json(&self.body)),
            ("by", id_json(&self.by)),
            ("epoch", Json::Int(u64::from(self.epoch))),
            ("kind", Json::str(self.kind().as_str())),
            ("prev", bin_json(&self.prev)),
            ("seq", Json::Int(self.seq)),
            ("space", id_json(&self.space)),
            ("v", Json::Int(1)),
        ]);
        let mut out = Vec::new();
        json::write(&value, &mut out);
        out
    }

    /// Reads a record from canonical bytes. Anything but the one spelling is refused as
    /// [`Reason::Malformed`], and a record or a list past a limit as [`Reason::TooLarge`]; the
    /// record's bytes are measured first, its lists after its shape.
    pub fn parse(bytes: &[u8]) -> Result<Record, Reason> {
        if bytes.len() > Limits::RECORD_BYTES {
            return Err(Reason::TooLarge);
        }
        let value = json::parse(bytes).map_err(|()| Reason::Malformed)?;
        let mut cx = Cx::default();
        let record = record_from(value, &mut cx)?;
        // The backstop: whatever the reading let through, the record must write back to exactly
        // these bytes.
        if record.to_bytes() != bytes {
            return Err(Reason::Malformed);
        }
        if cx.too_large {
            return Err(Reason::TooLarge);
        }
        Ok(record)
    }
}

// ---- reading ----------------------------------------------------------------------------------

struct Fields(Vec<(String, Json)>);

impl Fields {
    fn new(value: Json) -> R<Fields> {
        match value {
            Json::Obj(pairs) => Ok(Fields(pairs)),
            _ => Err(Reason::Malformed),
        }
    }

    fn take(&mut self, name: &str) -> Option<Json> {
        let i = self.0.iter().position(|(k, _)| k == name)?;
        Some(self.0.remove(i).1)
    }

    fn req(&mut self, name: &str) -> R<Json> {
        self.take(name).ok_or(Reason::Malformed)
    }

    /// Fails when a member nobody asked for is left.
    fn finish(self) -> R<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Reason::Malformed)
        }
    }
}

fn j_str(value: Json) -> R<String> {
    match value {
        Json::Str(s) => Ok(s),
        _ => Err(Reason::Malformed),
    }
}

fn j_int(value: Json) -> R<u64> {
    match value {
        Json::Int(n) => Ok(n),
        _ => Err(Reason::Malformed),
    }
}

fn j_bool(value: Json) -> R<bool> {
    match value {
        Json::Bool(b) => Ok(b),
        _ => Err(Reason::Malformed),
    }
}

fn j_arr(value: Json) -> R<Vec<Json>> {
    match value {
        Json::Arr(items) => Ok(items),
        _ => Err(Reason::Malformed),
    }
}

fn j_u32(value: Json, min: u32) -> R<u32> {
    let n = u32::try_from(j_int(value)?).map_err(|_| Reason::Malformed)?;
    if n < min {
        return Err(Reason::Malformed);
    }
    Ok(n)
}

fn j_id(value: Json) -> R<Id> {
    parse_uuid(&j_str(value)?).ok_or(Reason::Malformed)
}

fn j_bin(value: Json, len: Option<usize>) -> R<Vec<u8>> {
    let bytes = b64::decode(&j_str(value)?).ok_or(Reason::Malformed)?;
    match len {
        Some(len) if bytes.len() != len => Err(Reason::Malformed),
        _ => Ok(bytes),
    }
}

fn j_hash(value: Json) -> R<Hash> {
    j_bin(value, Some(32))?
        .try_into()
        .map_err(|_| Reason::Malformed)
}

/// An array of `min..=max` elements read with `f`; one past `max` is read all the same and noted as
/// too large once the whole record has been read.
fn list<T>(
    value: Json,
    min: usize,
    max: usize,
    cx: &mut Cx,
    mut f: impl FnMut(Json) -> R<T>,
) -> R<Vec<T>> {
    let items = j_arr(value)?;
    if items.len() < min {
        return Err(Reason::Malformed);
    }
    if items.len() > max {
        cx.too_large = true;
    }
    items.into_iter().map(&mut f).collect()
}

/// Fails unless `items` are strictly ascending by `key`: sets have one order and no repeats.
fn ascending<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> R<()> {
    if items.windows(2).all(|w| key(&w[0]) < key(&w[1])) {
        Ok(())
    } else {
        Err(Reason::Malformed)
    }
}

fn custom_list(value: Json, cx: &mut Cx) -> R<Vec<CustomPerm>> {
    let perms = list(value, 0, usize::MAX, cx, |j| {
        CustomPerm::parse(&j_str(j)?).ok_or(Reason::Malformed)
    })?;
    ascending(&perms, |p| *p)?;
    Ok(perms)
}

fn id_list(value: Json, cx: &mut Cx) -> R<Vec<Id>> {
    let ids = list(value, 0, usize::MAX, cx, j_id)?;
    ascending(&ids, |i| *i)?;
    Ok(ids)
}

fn key_list(value: Json, cx: &mut Cx) -> R<Vec<KeyRef>> {
    let keys = list(value, 0, usize::MAX, cx, |j| {
        KeyRef::parse(&j_str(j)?).ok_or(Reason::Malformed)
    })?;
    ascending(&keys, |k| *k)?;
    Ok(keys)
}

fn grantee(value: Json) -> R<Grantee> {
    Grantee::parse(&j_str(value)?).ok_or(Reason::Malformed)
}

fn permission(value: Json) -> R<CollectionPerm> {
    CollectionPerm::parse(&j_str(value)?).ok_or(Reason::Malformed)
}

fn commitment(value: Json, makes: bool) -> R<Commitment> {
    let mut f = Fields::new(value)?;
    let check = f.take("check");
    if check.is_some() != makes {
        return Err(Reason::Malformed);
    }
    let count = f.req("count")?;
    let digest = j_hash(f.req("digest")?)?;
    let key = KeyRef::parse(&j_str(f.req("key")?)?).ok_or(Reason::Malformed)?;
    let version = j_u32(f.req("version")?, 1)?;
    f.finish()?;
    let count = j_u32(count, 1)?;
    if count > Limits::SEAL_COUNT {
        return Err(Reason::Malformed);
    }
    Ok(Commitment {
        key,
        version,
        count,
        digest,
        check: check.map(j_hash).transpose()?,
    })
}

fn commitments(
    value: Json,
    makes: bool,
    min: usize,
    max: usize,
    cx: &mut Cx,
) -> R<Vec<Commitment>> {
    let seals = list(value, min, max, cx, |j| commitment(j, makes))?;
    ascending(&seals, |c| c.key)?;
    Ok(seals)
}

fn policies(value: Json) -> R<Policies> {
    let mut f = Fields::new(value)?;
    let account_recovery = j_bool(f.req("accountRecovery")?)?;
    let always_show_email = j_bool(f.req("alwaysShowEmail")?)?;
    let central_ownership = j_bool(f.req("centralOwnership")?)?;
    let disable_export = j_bool(f.req("disableExport")?)?;
    let disable_send = j_bool(f.req("disableSend")?)?;
    let duplicate_matching = j_bool(f.req("duplicateMatching")?)?;
    let mut mp = Fields::new(f.req("masterPassword")?)?;
    let enforce_on_login = j_bool(mp.req("enforceOnLogin")?)?;
    let min_complexity = u8::try_from(j_int(mp.req("minComplexity")?)?)
        .ok()
        .filter(|n| *n <= 4)
        .ok_or(Reason::Malformed)?;
    let min_length = u8::try_from(j_int(mp.req("minLength")?)?)
        .ok()
        .filter(|n| *n <= 128)
        .ok_or(Reason::Malformed)?;
    let require_lower = j_bool(mp.req("requireLower")?)?;
    let require_numbers = j_bool(mp.req("requireNumbers")?)?;
    let require_special = j_bool(mp.req("requireSpecial")?)?;
    let require_upper = j_bool(mp.req("requireUpper")?)?;
    mp.finish()?;
    let no_card_items = j_bool(f.req("noCardItems")?)?;
    let no_pin_unlock = j_bool(f.req("noPinUnlock")?)?;
    let require_sso = j_bool(f.req("requireSso")?)?;
    let mut st = Fields::new(f.req("sessionTimeout")?)?;
    let action = TimeoutAction::parse(&j_str(st.req("action")?)?).ok_or(Reason::Malformed)?;
    let minutes = u32::try_from(j_int(st.req("minutes")?)?)
        .ok()
        .filter(|n| *n <= 525_600)
        .ok_or(Reason::Malformed)?;
    st.finish()?;
    let single_space = j_bool(f.req("singleSpace")?)?;
    let two_step = j_bool(f.req("twoStep")?)?;
    f.finish()?;
    Ok(Policies {
        account_recovery,
        always_show_email,
        central_ownership,
        disable_export,
        disable_send,
        duplicate_matching,
        master_password: super::model::MasterPasswordPolicy {
            enforce_on_login,
            min_complexity,
            min_length,
            require_lower,
            require_numbers,
            require_special,
            require_upper,
        },
        no_card_items,
        no_pin_unlock,
        require_sso,
        session_timeout: super::model::SessionTimeoutPolicy { action, minutes },
        single_space,
        two_step,
    })
}

fn optional_id(f: &mut Fields) -> R<Option<Id>> {
    f.take("parent").map(j_id).transpose()
}

fn body_from(kind: Kind, value: Json, cx: &mut Cx) -> R<Body> {
    let mut f = Fields::new(value)?;
    let body = match kind {
        Kind::Create => {
            let bundle = j_bin(f.req("bundle")?, Some(BUNDLE_LEN))?;
            let bundle_signature = j_bin(f.req("bundleSignature")?, Some(SIGNATURE_LEN))?;
            let mut c = Fields::new(f.req("collection")?)?;
            let collection = j_id(c.req("id")?)?;
            let collection_name = j_hash(c.req("nameHash")?)?;
            c.finish()?;
            let member = j_id(f.req("member")?)?;
            let name_hash = j_hash(f.req("nameHash")?)?;
            let seals = commitments(f.req("seals")?, true, 0, usize::MAX, cx)?;
            Body::Create {
                bundle,
                bundle_signature,
                collection,
                collection_name,
                member,
                name_hash,
                seals,
            }
        }
        Kind::Invite => {
            let custom = custom_list(f.req("custom")?, cx)?;
            let grants = list(f.req("grants")?, 0, Limits::GRANTS, cx, |j| {
                let mut g = Fields::new(j)?;
                let collection = j_id(g.req("collection")?)?;
                let perm = permission(g.req("permission")?)?;
                g.finish()?;
                Ok((collection, perm))
            })?;
            ascending(&grants, |g| g.0)?;
            let member = j_id(f.req("member")?)?;
            let role = Role::parse(&j_str(f.req("role")?)?).ok_or(Reason::Malformed)?;
            Body::Invite {
                custom,
                grants,
                member,
                role,
            }
        }
        Kind::Confirm => Body::Confirm {
            bundle: j_bin(f.req("bundle")?, Some(BUNDLE_LEN))?,
            bundle_signature: j_bin(f.req("bundleSignature")?, Some(SIGNATURE_LEN))?,
            member: j_id(f.req("member")?)?,
            statement: j_bin(f.req("statement")?, Some(STATEMENT_LEN))?,
            statement_signature: j_bin(f.req("statementSignature")?, Some(SIGNATURE_LEN))?,
        },
        Kind::Rekey => Body::Rekey {
            bundle: j_bin(f.req("bundle")?, Some(BUNDLE_LEN))?,
            bundle_signature: j_bin(f.req("bundleSignature")?, Some(SIGNATURE_LEN))?,
        },
        Kind::Role => {
            let custom = custom_list(f.req("custom")?, cx)?;
            let member = j_id(f.req("member")?)?;
            let role = Role::parse(&j_str(f.req("role")?)?).ok_or(Reason::Malformed)?;
            Body::Role {
                custom,
                member,
                role,
            }
        }
        Kind::Remove => {
            let member = j_id(f.req("member")?)?;
            let replace = key_list(f.req("replace")?, cx)?;
            Body::Remove { member, replace }
        }
        Kind::Grant => Body::Grant {
            collection: j_id(f.req("collection")?)?,
            grantee: grantee(f.req("grantee")?)?,
            permission: permission(f.req("permission")?)?,
        },
        Kind::Ungrant => {
            let collection = j_id(f.req("collection")?)?;
            let grantee = grantee(f.req("grantee")?)?;
            let replace = key_list(f.req("replace")?, cx)?;
            Body::Ungrant {
                collection,
                grantee,
                replace,
            }
        }
        Kind::Collection => {
            let collection = j_id(f.req("collection")?)?;
            let grants = list(f.req("grants")?, 1, Limits::GRANTS, cx, |j| {
                let mut g = Fields::new(j)?;
                let who = grantee(g.req("grantee")?)?;
                let perm = permission(g.req("permission")?)?;
                g.finish()?;
                Ok((who, perm))
            })?;
            ascending(&grants, |g| g.0)?;
            let name_hash = j_hash(f.req("nameHash")?)?;
            let parent = optional_id(&mut f)?;
            let seals = commitments(f.req("seals")?, true, 0, usize::MAX, cx)?;
            Body::Collection {
                collection,
                grants,
                name_hash,
                parent,
                seals,
            }
        }
        Kind::Move => {
            let collection = j_id(f.req("collection")?)?;
            let parent = optional_id(&mut f)?;
            Body::Move { collection, parent }
        }
        Kind::CollectionDelete => Body::CollectionDelete {
            collection: j_id(f.req("collection")?)?,
        },
        Kind::Group => Body::Group {
            group: j_id(f.req("group")?)?,
            name_hash: j_hash(f.req("nameHash")?)?,
        },
        Kind::GroupMembers => {
            let add = id_list(f.req("add")?, cx)?;
            let group = j_id(f.req("group")?)?;
            let remove = id_list(f.req("remove")?, cx)?;
            let replace = key_list(f.req("replace")?, cx)?;
            if add.is_empty() && remove.is_empty() {
                return Err(Reason::Malformed);
            }
            if add.iter().any(|a| remove.contains(a)) {
                return Err(Reason::Malformed);
            }
            if add.len() + remove.len() > Limits::GROUP_MEMBERS {
                cx.too_large = true;
            }
            Body::GroupMembers {
                add,
                group,
                remove,
                replace,
            }
        }
        Kind::GroupDelete => {
            let group = j_id(f.req("group")?)?;
            let replace = key_list(f.req("replace")?, cx)?;
            Body::GroupDelete { group, replace }
        }
        Kind::Rename => Body::Rename {
            name_hash: j_hash(f.req("nameHash")?)?,
            target: NameTarget::parse(&j_str(f.req("target")?)?).ok_or(Reason::Malformed)?,
        },
        Kind::Seal => Body::Seal {
            seals: commitments(f.req("seals")?, false, 1, Limits::SEAL_SEALS, cx)?,
        },
        Kind::Keys => {
            let names = f.take("names").map(|j| j_bin(j, None)).transpose()?;
            let rotate = commitments(f.req("rotate")?, true, 1, Limits::KEYS_ROTATE, cx)?;
            if rotate.iter().filter(|c| c.key == KeyRef::Space).count() > 1 {
                return Err(Reason::Malformed);
            }
            Body::Keys { names, rotate }
        }
        Kind::Policies => Body::Policies {
            policies: policies(f.req("policies")?)?,
        },
        Kind::RecoveryKey => Body::RecoveryKey {
            key: j_bin(f.req("key")?, Some(KX1_LEN))?,
        },
        Kind::RecoveryKeyClear => Body::RecoveryKeyClear,
        Kind::Fence => Body::Fence {
            home: j_id(f.req("home")?)?,
            promotion: j_hash(f.req("promotion")?)?,
        },
    };
    f.finish()?;
    Ok(body)
}

fn record_from(value: Json, cx: &mut Cx) -> R<Record> {
    let mut f = Fields::new(value)?;
    let at = j_int(f.req("at")?)?;
    let body = f.req("body")?;
    let by = j_id(f.req("by")?)?;
    let epoch = j_u32(f.req("epoch")?, 1)?;
    let kind = Kind::parse(&j_str(f.req("kind")?)?).ok_or(Reason::Malformed)?;
    let prev = j_hash(f.req("prev")?)?;
    let seq = j_int(f.req("seq")?)?;
    let space = j_id(f.req("space")?)?;
    if j_int(f.req("v")?)? != 1 {
        return Err(Reason::Malformed);
    }
    f.finish()?;
    let body = body_from(kind, body, cx)?;
    if seq >= Limits::CHAIN_RECORDS {
        cx.too_large = true;
    }
    Ok(Record {
        space,
        seq,
        prev,
        epoch,
        at,
        by,
        body,
    })
}

// ---- wire form --------------------------------------------------------------------------------

impl SignedRecord {
    /// Reads the wire form's three possible members, each unpadded base64url. The signature is
    /// 3373 bytes; a cosignature is allowed only on a `rekey`, which [`verify`](super::verify)
    /// checks once it has the kind.
    pub fn from_wire(
        entry: &str,
        signature: &str,
        cosignature: Option<&str>,
    ) -> Result<SignedRecord, Reason> {
        let entry = b64::decode(entry).ok_or(Reason::Malformed)?;
        let signature = b64::decode(signature).ok_or(Reason::Malformed)?;
        if signature.len() != SIGNATURE_LEN {
            return Err(Reason::Malformed);
        }
        let cosignature = match cosignature {
            None => None,
            Some(text) => {
                let bytes = b64::decode(text).ok_or(Reason::Malformed)?;
                if bytes.len() != SIGNATURE_LEN {
                    return Err(Reason::Malformed);
                }
                Some(bytes)
            }
        };
        Ok(SignedRecord {
            entry,
            signature,
            cosignature,
        })
    }

    /// The wire form's text for the three members: `(entry, signature, cosignature)`.
    pub fn to_wire(&self) -> (String, String, Option<String>) {
        (
            b64::encode(&self.entry),
            b64::encode(&self.signature),
            self.cosignature.as_deref().map(b64::encode),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space_chain::model::{MasterPasswordPolicy, SessionTimeoutPolicy};

    fn sample(body: Body) -> Record {
        Record {
            space: [1; 16],
            seq: 5,
            prev: [2; 32],
            epoch: 1,
            at: 1_700_000_000,
            by: [3; 16],
            body,
        }
    }

    fn commit(key: KeyRef, makes: bool) -> Commitment {
        Commitment {
            key,
            version: 2,
            count: 3,
            digest: [4; 32],
            check: makes.then_some([5; 32]),
        }
    }

    fn all_bodies() -> Vec<Body> {
        let a = [10u8; 16];
        let b = [11u8; 16];
        vec![
            Body::Create {
                bundle: vec![7; BUNDLE_LEN],
                bundle_signature: vec![8; SIGNATURE_LEN],
                collection: a,
                collection_name: [9; 32],
                member: b,
                name_hash: [6; 32],
                seals: vec![
                    commit(KeyRef::Collection(a), true),
                    commit(KeyRef::Space, true),
                ],
            },
            Body::Invite {
                custom: vec![CustomPerm::CreateCollections, CustomPerm::ManageUsers],
                grants: vec![(a, CollectionPerm::View), (b, CollectionPerm::Manage)],
                member: b,
                role: Role::Custom,
            },
            Body::Confirm {
                bundle: vec![7; BUNDLE_LEN],
                bundle_signature: vec![8; SIGNATURE_LEN],
                member: b,
                statement: vec![1; STATEMENT_LEN],
                statement_signature: vec![2; SIGNATURE_LEN],
            },
            Body::Rekey {
                bundle: vec![7; BUNDLE_LEN],
                bundle_signature: vec![8; SIGNATURE_LEN],
            },
            Body::Role {
                custom: vec![],
                member: b,
                role: Role::Admin,
            },
            Body::Remove {
                member: b,
                replace: vec![KeyRef::Collection(a), KeyRef::Space],
            },
            Body::Grant {
                collection: a,
                grantee: Grantee::Group(b),
                permission: CollectionPerm::EditHidePasswords,
            },
            Body::Ungrant {
                collection: a,
                grantee: Grantee::User(b),
                replace: vec![],
            },
            Body::Collection {
                collection: a,
                grants: vec![
                    (Grantee::Group(a), CollectionPerm::View),
                    (Grantee::User(b), CollectionPerm::Manage),
                ],
                name_hash: [6; 32],
                parent: Some(b),
                seals: vec![commit(KeyRef::Collection(a), true)],
            },
            Body::Collection {
                collection: a,
                grants: vec![(Grantee::User(b), CollectionPerm::Manage)],
                name_hash: [6; 32],
                parent: None,
                seals: vec![commit(KeyRef::Collection(a), true)],
            },
            Body::Move {
                collection: a,
                parent: Some(b),
            },
            Body::Move {
                collection: a,
                parent: None,
            },
            Body::CollectionDelete { collection: a },
            Body::Group {
                group: a,
                name_hash: [6; 32],
            },
            Body::GroupMembers {
                add: vec![a],
                group: b,
                remove: vec![[12; 16]],
                replace: vec![KeyRef::Space],
            },
            Body::GroupDelete {
                group: a,
                replace: vec![],
            },
            Body::Rename {
                name_hash: [6; 32],
                target: NameTarget::Group(a),
            },
            Body::Seal {
                seals: vec![
                    commit(KeyRef::Collection(a), false),
                    commit(KeyRef::Space, false),
                ],
            },
            Body::Keys {
                names: Some(vec![1; 49]),
                rotate: vec![commit(KeyRef::Space, true)],
            },
            Body::Keys {
                names: None,
                rotate: vec![commit(KeyRef::Collection(a), true)],
            },
            Body::Policies {
                policies: Policies {
                    account_recovery: true,
                    master_password: MasterPasswordPolicy {
                        min_complexity: 4,
                        min_length: 128,
                        require_lower: true,
                        ..MasterPasswordPolicy::default()
                    },
                    session_timeout: SessionTimeoutPolicy {
                        action: TimeoutAction::LogOut,
                        minutes: 525_600,
                    },
                    two_step: true,
                    ..Policies::default()
                },
            },
            Body::RecoveryKey {
                key: vec![5; KX1_LEN],
            },
            Body::RecoveryKeyClear,
            Body::Fence {
                home: a,
                promotion: [8; 32],
            },
        ]
    }

    #[test]
    fn every_kind_round_trips_to_the_same_bytes() {
        let bodies = all_bodies();
        let kinds: std::collections::BTreeSet<&str> =
            bodies.iter().map(|b| b.kind().as_str()).collect();
        assert_eq!(kinds.len(), 21);
        for body in bodies {
            let record = sample(body);
            let bytes = record.to_bytes();
            assert_eq!(
                Record::parse(&bytes),
                Ok(record.clone()),
                "{:?}",
                record.kind()
            );
        }
    }

    #[test]
    fn members_come_in_byte_order() {
        let bytes = sample(Body::RecoveryKeyClear).to_bytes();
        let text = String::from_utf8(bytes).expect("ascii");
        assert!(
            text.starts_with(r#"{"at":1700000000,"body":{},"by":""#),
            "{text}"
        );
        assert!(text.ends_with(r#""seq":5,"space":"01010101-0101-0101-0101-010101010101","v":1}"#));
    }

    #[test]
    fn the_spec_examples_are_the_layout() {
        let fence = Record {
            space: parse_uuid("00000000-0000-4000-8000-000000000001").expect("uuid"),
            seq: 7,
            prev: [0x11; 32],
            epoch: 2,
            at: 1_700_000_700,
            by: parse_uuid("00000000-0000-4000-8000-000000000002").expect("uuid"),
            body: Body::Fence {
                home: parse_uuid("00000000-0000-4000-8000-0000000000f2").expect("uuid"),
                promotion: crate::hash::sha256(b"example promotion record"),
            },
        };
        let bytes = fence.to_bytes();
        assert_eq!(bytes.len(), 313);
        assert_eq!(
            String::from_utf8(bytes.clone()).expect("ascii"),
            "{\"at\":1700000700,\"body\":{\"home\":\"00000000-0000-4000-8000-0000000000f2\",\
             \"promotion\":\"QTHxrde9FN788OzrLL4TpaPmaC2O0E5WgPn8_Ws-K0Q\"},\
             \"by\":\"00000000-0000-4000-8000-000000000002\",\"epoch\":2,\"kind\":\"fence\",\
             \"prev\":\"ERERERERERERERERERERERERERERERERERERERERERE\",\"seq\":7,\
             \"space\":\"00000000-0000-4000-8000-000000000001\",\"v\":1}"
        );
        assert_eq!(Record::parse(&bytes), Ok(fence));
    }

    fn swap(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
        let text = String::from_utf8(bytes.to_vec()).expect("ascii");
        assert!(text.contains(from), "{from} in {text}");
        text.replacen(from, to, 1).into_bytes()
    }

    #[test]
    fn refuses_what_has_another_spelling() {
        let invite = sample(Body::Invite {
            custom: vec![CustomPerm::CreateCollections, CustomPerm::ManageUsers],
            grants: vec![],
            member: [11; 16],
            role: Role::Custom,
        })
        .to_bytes();
        let mv = sample(Body::Move {
            collection: [10; 16],
            parent: Some([11; 16]),
        })
        .to_bytes();
        let members = sample(Body::GroupMembers {
            add: vec![[10; 16], [12; 16]],
            group: [13; 16],
            remove: vec![],
            replace: vec![],
        })
        .to_bytes();
        let grant = sample(Body::Grant {
            collection: [10; 16],
            grantee: Grantee::User([11; 16]),
            permission: CollectionPerm::View,
        })
        .to_bytes();
        let id10 = uuid_text(&[10; 16]);
        let id11 = uuid_text(&[11; 16]);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "null parent",
                swap(&mv, &format!("\"parent\":\"{id11}\""), "\"parent\":null"),
            ),
            (
                "null custom",
                swap(
                    &invite,
                    "\"custom\":[\"create-collections\",\"manage-users\"]",
                    "\"custom\":null",
                ),
            ),
            ("1.0", swap(&invite, "\"seq\":5", "\"seq\":1.0")),
            ("-1", swap(&invite, "\"seq\":5", "\"seq\":-1")),
            (
                "2^53",
                swap(&invite, "\"seq\":5", "\"seq\":9007199254740992"),
            ),
            (
                "a short string",
                swap(&invite, "\"role\":\"custom\"", "\"role\":\"A\""),
            ),
            (
                "a surrogate",
                swap(&invite, "\"role\":\"custom\"", "\"role\":\"\\ud800\""),
            ),
            (
                "custom out of order",
                swap(
                    &invite,
                    "[\"create-collections\",\"manage-users\"]",
                    "[\"manage-users\",\"create-collections\"]",
                ),
            ),
            (
                "custom twice",
                swap(
                    &invite,
                    "[\"create-collections\",\"manage-users\"]",
                    "[\"manage-users\",\"manage-users\"]",
                ),
            ),
            (
                "an id twice in add",
                swap(
                    &members,
                    &format!("\"add\":[\"{id10}\",\"{}\"]", uuid_text(&[12; 16])),
                    &format!("\"add\":[\"{id10}\",\"{id10}\"]"),
                ),
            ),
            (
                "a member twice",
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
                swap(&grant, &format!("\"grantee\":\"user:{id11}\","), ""),
            ),
            ("trailing bytes", [grant.clone(), b"\n".to_vec()].concat()),
            ("v 2", swap(&grant, "\"v\":1", "\"v\":2")),
            ("epoch 0", swap(&grant, "\"epoch\":1", "\"epoch\":0")),
            (
                "a wrong kind",
                swap(&grant, "\"kind\":\"grant\"", "\"kind\":\"granted\""),
            ),
        ];
        for (what, bytes) in cases {
            assert_eq!(Record::parse(&bytes), Err(Reason::Malformed), "{what}");
        }
        assert!(Record::parse(&grant).is_ok());
    }

    #[test]
    fn limits_come_after_the_shape() {
        let grant = sample(Body::Grant {
            collection: [10; 16],
            grantee: Grantee::User([11; 16]),
            permission: CollectionPerm::View,
        })
        .to_bytes();
        let big = vec![b' '; Limits::RECORD_BYTES + 1];
        assert_eq!(Record::parse(&big), Err(Reason::TooLarge));
        assert_eq!(
            Record::parse(&grant[..grant.len() - 1]),
            Err(Reason::Malformed)
        );

        // A seq past 65,535 is the 65,537th record.
        let mut late = sample(Body::RecoveryKeyClear);
        late.seq = 65_536;
        assert_eq!(Record::parse(&late.to_bytes()), Err(Reason::TooLarge));
        late.seq = 65_535;
        assert!(Record::parse(&late.to_bytes()).is_ok());

        // 1,001 grants on a collection is too large, an empty list malformed.
        let many = |n: usize| {
            sample(Body::Collection {
                collection: [10; 16],
                grants: (0..n)
                    .map(|i| {
                        let mut id = [0u8; 16];
                        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                        (Grantee::User(id), CollectionPerm::View)
                    })
                    .collect(),
                name_hash: [6; 32],
                parent: None,
                seals: vec![],
            })
            .to_bytes()
        };
        assert!(Record::parse(&many(1000)).is_ok());
        assert_eq!(Record::parse(&many(1001)), Err(Reason::TooLarge));
        assert_eq!(Record::parse(&many(0)), Err(Reason::Malformed));
    }

    #[test]
    fn the_wire_form_checks_its_lengths() {
        let sig = b64::encode(&[1u8; SIGNATURE_LEN]);
        let signed = SignedRecord::from_wire("AAAA", &sig, None).expect("wire");
        assert_eq!(signed.entry, vec![0, 0, 0]);
        assert_eq!(signed.to_wire(), ("AAAA".to_owned(), sig.clone(), None));
        assert!(SignedRecord::from_wire("AAAA", &sig, Some(&sig)).is_ok());
        for bad in [
            SignedRecord::from_wire("AAAA", "AAAA", None),
            SignedRecord::from_wire("AAAA", &sig, Some("AAAA")),
            SignedRecord::from_wire("AA==", &sig, None),
            SignedRecord::from_wire("AAAA", &format!("{sig}A"), None),
        ] {
            assert_eq!(bad, Err(Reason::Malformed));
        }
    }
}
