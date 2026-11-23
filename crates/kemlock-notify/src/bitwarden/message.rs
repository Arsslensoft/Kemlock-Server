//! SignalR messages of Bitwarden's notification hub.
//!
//! Bitwarden's apps connect to `/notifications/hub` and speak SignalR over a WebSocket. After a
//! handshake (`{"protocol":"messagepack","version":1}` plus the record separator `0x1e`; the
//! server answers `{}` plus `0x1e`), the server sends *invocations* of `ReceiveMessage` carrying
//! one argument: `{ContextId, Type, Payload}`. With MessagePack an invocation is the array
//! `[1, {}, nil, "ReceiveMessage", [{...}]]`, prefixed by its length as a 7-bit varint; with JSON
//! it is `{"type":1,"target":"ReceiveMessage","arguments":[{...}]}` plus `0x1e`.
//!
//! Dates are MessagePack timestamps (extension type -1, 64-bit form) and RFC 3339 text in JSON.
//! Names, numbers and the spelling `AuthRequestResponseRecieved` are Vaultwarden's.

use rmpv::Value;
use serde_json::{Map, Value as Json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// The record separator that ends every JSON message and the handshake.
pub const RECORD_SEPARATOR: u8 = 0x1e;

/// The server's answer to a good handshake: `{}` and the record separator.
pub const HANDSHAKE_RESPONSE: [u8; 3] = [0x7b, 0x7d, RECORD_SEPARATOR];

/// A MessagePack SignalR ping: length 2, then the array `[6]`.
pub const MSGPACK_PING: [u8; 3] = [0x02, 0x91, 0x06];

/// A JSON SignalR ping.
pub const JSON_PING: &str = "{\"type\":6}\u{1e}";

/// The invocation target of every update.
pub const TARGET: &str = "ReceiveMessage";

/// The invocation target of the anonymous hub's answer (misspelled on purpose: so is Bitwarden's).
pub const ANONYMOUS_TARGET: &str = "AuthRequestResponseRecieved";

/// What changed, as Bitwarden numbers it (`PushType`). Only the types Vaultwarden sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpdateType {
    SyncCipherUpdate,
    SyncCipherCreate,
    SyncLoginDelete,
    SyncFolderDelete,
    SyncCiphers,
    SyncVault,
    SyncOrgKeys,
    SyncFolderCreate,
    SyncFolderUpdate,
    SyncSettings,
    LogOut,
    SyncSendCreate,
    SyncSendUpdate,
    SyncSendDelete,
    AuthRequest,
    AuthRequestResponse,
    None,
}

impl UpdateType {
    pub const fn code(self) -> i32 {
        match self {
            UpdateType::SyncCipherUpdate => 0,
            UpdateType::SyncCipherCreate => 1,
            UpdateType::SyncLoginDelete => 2,
            UpdateType::SyncFolderDelete => 3,
            UpdateType::SyncCiphers => 4,
            UpdateType::SyncVault => 5,
            UpdateType::SyncOrgKeys => 6,
            UpdateType::SyncFolderCreate => 7,
            UpdateType::SyncFolderUpdate => 8,
            UpdateType::SyncSettings => 10,
            UpdateType::LogOut => 11,
            UpdateType::SyncSendCreate => 12,
            UpdateType::SyncSendUpdate => 13,
            UpdateType::SyncSendDelete => 14,
            UpdateType::AuthRequest => 15,
            UpdateType::AuthRequestResponse => 16,
            UpdateType::None => 100,
        }
    }
}

/// Which SignalR protocol a socket chose in its handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    MessagePack,
    Json,
}

impl Protocol {
    /// What `{"protocol": ..., "version": 1}` asks for. `None` for anything else.
    pub fn from_handshake(text: &str) -> Option<Protocol> {
        let text = text
            .strip_suffix(char::from(RECORD_SEPARATOR))
            .unwrap_or(text);
        let value: Json = serde_json::from_str(text).ok()?;
        if value.get("version")?.as_i64()? != 1 {
            return None;
        }
        match value.get("protocol")?.as_str()? {
            "messagepack" => Some(Protocol::MessagePack),
            "json" => Some(Protocol::Json),
            _ => None,
        }
    }
}

/// One value of a payload.
#[derive(Clone, Debug, PartialEq)]
pub enum Field {
    Nil,
    Text(String),
    Date(OffsetDateTime),
    Texts(Vec<String>),
}

impl Field {
    pub fn id(id: Uuid) -> Field {
        Field::Text(id.to_string())
    }

    fn msgpack(&self) -> Value {
        match self {
            Field::Nil => Value::Nil,
            Field::Text(text) => Value::from(text.as_str()),
            Field::Date(at) => date(*at),
            Field::Texts(items) => {
                Value::Array(items.iter().map(|i| Value::from(i.as_str())).collect())
            }
        }
    }

    fn json(&self) -> Json {
        match self {
            Field::Nil => Json::Null,
            Field::Text(text) => Json::String(text.clone()),
            Field::Date(at) => Json::String(at.format(&Rfc3339).unwrap_or_default()),
            Field::Texts(items) => Json::Array(items.iter().cloned().map(Json::String).collect()),
        }
    }
}

/// A MessagePack timestamp: extension -1, the 64-bit form `nanoseconds << 34 | seconds`.
fn date(at: OffsetDateTime) -> Value {
    let seconds = u64::try_from(at.unix_timestamp()).unwrap_or(0);
    let nanos = u64::from(at.nanosecond());
    Value::Ext(-1, ((nanos << 34) | seconds).to_be_bytes().to_vec())
}

/// One update for a socket.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub kind: UpdateType,
    /// The device that made the change, so it ignores its own echo. `None` for server-made ones.
    pub context: Option<Uuid>,
    pub payload: Vec<(&'static str, Field)>,
    /// Set on the anonymous hub's answer: the account the answer is for.
    pub anonymous_user: Option<Uuid>,
}

impl Message {
    /// `SyncVault`, `SyncSettings`, `SyncOrgKeys`, `SyncCiphers`: the account's data changed.
    pub fn user_update(kind: UpdateType, user: Uuid, at: OffsetDateTime) -> Message {
        Message {
            kind,
            context: None,
            payload: vec![("UserId", Field::id(user)), ("Date", Field::Date(at))],
            anonymous_user: None,
        }
    }

    /// `LogOut`: the account's sessions ended.
    pub fn logout(user: Uuid, device: Option<Uuid>, at: OffsetDateTime) -> Message {
        Message {
            context: device,
            ..Message::user_update(UpdateType::LogOut, user, at)
        }
    }

    /// A cipher was created, updated or deleted (`SyncCipherCreate`, `SyncCipherUpdate`,
    /// `SyncLoginDelete`).
    pub fn cipher(
        kind: UpdateType,
        id: Uuid,
        user: Uuid,
        revision: OffsetDateTime,
        device: Option<Uuid>,
    ) -> Message {
        Message {
            kind,
            context: device,
            payload: vec![
                ("Id", Field::id(id)),
                ("UserId", Field::id(user)),
                ("OrganizationId", Field::Nil),
                ("CollectionIds", Field::Nil),
                ("RevisionDate", Field::Date(revision)),
            ],
            anonymous_user: None,
        }
    }

    /// A cipher message with everything Vaultwarden's `send_cipher_update` can put in it: the
    /// owning account (a personal cipher's), the organization, and the collections a share put
    /// the cipher in (`None` when the change wasn't a share).
    pub fn cipher_in(
        kind: UpdateType,
        id: Uuid,
        user: Option<Uuid>,
        organization: Option<Uuid>,
        collections: Option<Vec<Uuid>>,
        revision: OffsetDateTime,
        device: Option<Uuid>,
    ) -> Message {
        let optional = |value: Option<Uuid>| value.map_or(Field::Nil, Field::id);
        Message {
            kind,
            context: device,
            payload: vec![
                ("Id", Field::id(id)),
                ("UserId", optional(user)),
                ("OrganizationId", optional(organization)),
                (
                    "CollectionIds",
                    collections.map_or(Field::Nil, |ids| {
                        Field::Texts(ids.iter().map(Uuid::to_string).collect())
                    }),
                ),
                ("RevisionDate", Field::Date(revision)),
            ],
            anonymous_user: None,
        }
    }

    /// A folder was created, updated or deleted.
    pub fn folder(
        kind: UpdateType,
        id: Uuid,
        user: Uuid,
        revision: OffsetDateTime,
        device: Option<Uuid>,
    ) -> Message {
        Message {
            kind,
            context: device,
            payload: vec![
                ("Id", Field::id(id)),
                ("UserId", Field::id(user)),
                ("RevisionDate", Field::Date(revision)),
            ],
            anonymous_user: None,
        }
    }

    /// A Send was created, updated or deleted.
    pub fn send(kind: UpdateType, id: Uuid, user: Uuid, revision: OffsetDateTime) -> Message {
        Message {
            kind,
            context: None,
            payload: vec![
                ("Id", Field::id(id)),
                ("UserId", Field::id(user)),
                ("RevisionDate", Field::Date(revision)),
            ],
            anonymous_user: None,
        }
    }

    /// A device asked to log in with another device (`AuthRequest`) or was answered
    /// (`AuthRequestResponse`).
    pub fn auth_request(kind: UpdateType, id: Uuid, user: Uuid, device: Option<Uuid>) -> Message {
        Message {
            kind,
            context: device,
            payload: vec![("Id", Field::id(id)), ("UserId", Field::id(user))],
            anonymous_user: None,
        }
    }

    /// The answer the anonymous hub gives the device waiting on a login request.
    pub fn anonymous_response(id: Uuid, user: Uuid) -> Message {
        Message {
            kind: UpdateType::AuthRequestResponse,
            context: None,
            payload: vec![("Id", Field::id(id)), ("UserId", Field::id(user))],
            anonymous_user: Some(user),
        }
    }

    fn target(&self) -> &'static str {
        if self.anonymous_user.is_some() {
            ANONYMOUS_TARGET
        } else {
            TARGET
        }
    }

    fn argument_msgpack(&self) -> Value {
        let payload = Value::Map(
            self.payload
                .iter()
                .map(|(key, field)| (Value::from(*key), field.msgpack()))
                .collect(),
        );
        let mut map = Vec::new();
        match self.anonymous_user {
            Some(user) => {
                map.push((Value::from("Type"), Value::from(self.kind.code())));
                map.push((Value::from("Payload"), payload));
                map.push((Value::from("UserId"), Value::from(user.to_string())));
            }
            None => {
                let context = self
                    .context
                    .map_or(Value::Nil, |c| Value::from(c.to_string()));
                map.push((Value::from("ContextId"), context));
                map.push((Value::from("Type"), Value::from(self.kind.code())));
                map.push((Value::from("Payload"), payload));
            }
        }
        Value::Map(map)
    }

    /// The MessagePack frame: a varint length, then `[1, {}, nil, target, [argument]]`.
    pub fn msgpack(&self) -> Vec<u8> {
        let value = Value::Array(vec![
            Value::from(1),
            Value::Map(Vec::new()),
            Value::Nil,
            Value::from(self.target()),
            Value::Array(vec![self.argument_msgpack()]),
        ]);
        let mut body = Vec::new();
        // Writing to a Vec can't fail.
        let _ = rmpv::encode::write_value(&mut body, &value);
        let mut frame = varint(body.len());
        frame.extend_from_slice(&body);
        frame
    }

    /// The JSON text frame: the invocation, then the record separator.
    pub fn json(&self) -> String {
        let payload: Map<String, Json> = self
            .payload
            .iter()
            .map(|(key, field)| ((*key).to_owned(), field.json()))
            .collect();
        let mut argument = Map::new();
        match self.anonymous_user {
            Some(user) => {
                argument.insert("Type".to_owned(), Json::from(self.kind.code()));
                argument.insert("Payload".to_owned(), Json::Object(payload));
                argument.insert("UserId".to_owned(), Json::String(user.to_string()));
            }
            None => {
                argument.insert(
                    "ContextId".to_owned(),
                    self.context
                        .map_or(Json::Null, |c| Json::String(c.to_string())),
                );
                argument.insert("Type".to_owned(), Json::from(self.kind.code()));
                argument.insert("Payload".to_owned(), Json::Object(payload));
            }
        }
        let invocation = serde_json::json!({
            "type": 1,
            "target": self.target(),
            "arguments": [Json::Object(argument)],
        });
        let mut text = invocation.to_string();
        text.push(char::from(RECORD_SEPARATOR));
        text
    }
}

/// A length as SignalR's 7-bit varint: low bits first, the high bit set on all but the last byte.
pub fn varint(mut length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        // Masked to seven bits, so it always fits.
        let mut byte = u8::try_from(length & 0x7f).unwrap_or(0);
        length >>= 7;
        if length > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if length == 0 {
            return out;
        }
    }
}

/// Reads a varint length from the start of `bytes`: the length and how many bytes it took.
pub fn read_varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut length = 0usize;
    for (index, byte) in bytes.iter().take(5).enumerate() {
        length |= usize::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((length, index + 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn id(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    /// Decodes a MessagePack frame back to its value, checking the length prefix on the way.
    fn decode(frame: &[u8]) -> Value {
        let (length, used) = read_varint(frame).expect("a length");
        assert_eq!(
            length,
            frame.len() - used,
            "the prefix is the body's length"
        );
        rmpv::decode::read_value(&mut &frame[used..]).expect("a value")
    }

    fn field<'a>(map: &'a Value, key: &str) -> &'a Value {
        map.as_map()
            .expect("a map")
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("no {key}"))
    }

    #[test]
    fn update_types_have_bitwardens_numbers() {
        let all = [
            (UpdateType::SyncCipherUpdate, 0),
            (UpdateType::SyncCipherCreate, 1),
            (UpdateType::SyncLoginDelete, 2),
            (UpdateType::SyncFolderDelete, 3),
            (UpdateType::SyncCiphers, 4),
            (UpdateType::SyncVault, 5),
            (UpdateType::SyncOrgKeys, 6),
            (UpdateType::SyncFolderCreate, 7),
            (UpdateType::SyncFolderUpdate, 8),
            (UpdateType::SyncSettings, 10),
            (UpdateType::LogOut, 11),
            (UpdateType::SyncSendCreate, 12),
            (UpdateType::SyncSendUpdate, 13),
            (UpdateType::SyncSendDelete, 14),
            (UpdateType::AuthRequest, 15),
            (UpdateType::AuthRequestResponse, 16),
            (UpdateType::None, 100),
        ];
        for (kind, code) in all {
            assert_eq!(kind.code(), code, "{kind:?}");
        }
    }

    #[test]
    fn the_constants_are_signalrs() {
        assert_eq!(HANDSHAKE_RESPONSE, *b"{}\x1e");
        // Length 2, then a one-element array holding 6 (the SignalR ping message type).
        assert_eq!(MSGPACK_PING, [2, 0x91, 6]);
        let (length, used) = read_varint(&MSGPACK_PING).expect("length");
        assert_eq!((length, used), (2, 1));
        assert_eq!(JSON_PING, "{\"type\":6}\u{1e}");
    }

    #[test]
    fn varints_round_trip_across_the_byte_boundaries() {
        assert_eq!(varint(0), vec![0]);
        assert_eq!(varint(127), vec![0x7f]);
        assert_eq!(varint(128), vec![0x80, 0x01]);
        assert_eq!(varint(300), vec![0xac, 0x02]);
        for length in [0, 1, 127, 128, 255, 16_383, 16_384, 2_097_151, 2_097_152] {
            let bytes = varint(length);
            assert_eq!(read_varint(&bytes), Some((length, bytes.len())), "{length}");
        }
        // Never ends: not a length.
        assert_eq!(read_varint(&[0x80, 0x80]), None);
        assert_eq!(read_varint(&[]), None);
    }

    #[test]
    fn a_sync_vault_frame_has_signalrs_shape() {
        let at = datetime!(2026-11-23 10:00:00.5 UTC);
        let message = Message::user_update(UpdateType::SyncVault, id(7), at);
        let value = decode(&message.msgpack());
        let parts = value.as_array().expect("an invocation");
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].as_i64(), Some(1), "message type: invocation");
        assert_eq!(parts[1].as_map().map(Vec::len), Some(0), "no headers");
        assert!(parts[2].is_nil(), "no invocation id");
        assert_eq!(parts[3].as_str(), Some("ReceiveMessage"));
        let arguments = parts[4].as_array().expect("arguments");
        assert_eq!(arguments.len(), 1);
        let argument = &arguments[0];
        assert!(field(argument, "ContextId").is_nil());
        assert_eq!(field(argument, "Type").as_i64(), Some(5));
        let payload = field(argument, "Payload");
        assert_eq!(
            field(payload, "UserId").as_str(),
            Some("07070707-0707-0707-0707-070707070707")
        );
        // The date is the 64-bit timestamp extension.
        match field(payload, "Date") {
            Value::Ext(kind, bytes) => {
                assert_eq!(*kind, -1);
                let packed = u64::from_be_bytes(bytes.as_slice().try_into().expect("8 bytes"));
                assert_eq!(packed & ((1 << 34) - 1), at.unix_timestamp().unsigned_abs());
                assert_eq!(packed >> 34, 500_000_000, "the nanoseconds");
            }
            other => panic!("not a timestamp: {other:?}"),
        }
    }

    #[test]
    fn a_cipher_update_carries_the_context_device_and_vaultwardens_keys() {
        let message = Message::cipher(
            UpdateType::SyncCipherUpdate,
            id(1),
            id(2),
            datetime!(2026-11-23 10:00 UTC),
            Some(id(3)),
        );
        let value = decode(&message.msgpack());
        let argument = &value.as_array().expect("array")[4]
            .as_array()
            .expect("args")[0];
        assert_eq!(
            field(argument, "ContextId").as_str(),
            Some("03030303-0303-0303-0303-030303030303")
        );
        let payload = field(argument, "Payload");
        let keys: Vec<&str> = payload
            .as_map()
            .expect("map")
            .iter()
            .filter_map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(
            keys,
            [
                "Id",
                "UserId",
                "OrganizationId",
                "CollectionIds",
                "RevisionDate"
            ]
        );
        assert!(field(payload, "OrganizationId").is_nil());
        assert!(field(payload, "CollectionIds").is_nil());
    }

    #[test]
    fn an_organization_cipher_names_its_organization_and_collections_but_no_account() {
        let at = datetime!(2026-11-23 10:00 UTC);
        let message = Message::cipher_in(
            UpdateType::SyncCipherUpdate,
            id(1),
            None,
            Some(id(5)),
            Some(vec![id(6), id(7)]),
            at,
            Some(id(3)),
        );
        let value = decode(&message.msgpack());
        let argument = &value.as_array().expect("array")[4]
            .as_array()
            .expect("args")[0];
        let payload = field(argument, "Payload");
        assert!(field(payload, "UserId").is_nil());
        assert_eq!(
            field(payload, "OrganizationId").as_str(),
            Some("05050505-0505-0505-0505-050505050505")
        );
        let collections: Vec<&str> = field(payload, "CollectionIds")
            .as_array()
            .expect("an array")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            collections,
            [
                "06060606-0606-0606-0606-060606060606",
                "07070707-0707-0707-0707-070707070707"
            ]
        );
        let text = message.json();
        let json: Json =
            serde_json::from_str(text.strip_suffix('\u{1e}').expect("separator")).expect("json");
        assert_eq!(
            json["arguments"][0]["Payload"]["CollectionIds"][1],
            "07070707-0707-0707-0707-070707070707"
        );
        assert!(json["arguments"][0]["Payload"]["UserId"].is_null());
    }

    #[test]
    fn the_anonymous_answer_uses_the_misspelt_target_and_no_context() {
        let message = Message::anonymous_response(id(9), id(8));
        let value = decode(&message.msgpack());
        let parts = value.as_array().expect("array");
        assert_eq!(parts[3].as_str(), Some("AuthRequestResponseRecieved"));
        let argument = &parts[4].as_array().expect("args")[0];
        assert_eq!(field(argument, "Type").as_i64(), Some(16));
        assert_eq!(
            field(argument, "UserId").as_str(),
            Some("08080808-0808-0808-0808-080808080808")
        );
        assert!(
            argument
                .as_map()
                .expect("map")
                .iter()
                .all(|(k, _)| k.as_str() != Some("ContextId"))
        );
    }

    #[test]
    fn the_json_form_ends_with_the_record_separator() {
        let message = Message::logout(id(1), Some(id(2)), datetime!(2026-11-23 10:00 UTC));
        let text = message.json();
        let body = text.strip_suffix('\u{1e}').expect("a record separator");
        let value: Json = serde_json::from_str(body).expect("json");
        assert_eq!(value["type"], 1);
        assert_eq!(value["target"], "ReceiveMessage");
        let argument = &value["arguments"][0];
        assert_eq!(argument["Type"], 11);
        assert_eq!(
            argument["ContextId"],
            "02020202-0202-0202-0202-020202020202"
        );
        assert_eq!(argument["Payload"]["Date"], "2026-11-23T10:00:00Z");
    }

    #[test]
    fn a_handshake_names_the_protocol() {
        assert_eq!(
            Protocol::from_handshake("{\"protocol\":\"messagepack\",\"version\":1}\u{1e}"),
            Some(Protocol::MessagePack)
        );
        // The separator is optional, as in Vaultwarden.
        assert_eq!(
            Protocol::from_handshake("{\"protocol\":\"messagepack\",\"version\":1}"),
            Some(Protocol::MessagePack)
        );
        assert_eq!(
            Protocol::from_handshake("{\"protocol\":\"json\",\"version\":1}\u{1e}"),
            Some(Protocol::Json)
        );
        for bad in [
            "{\"protocol\":\"messagepack\",\"version\":2}",
            "{\"protocol\":\"xml\",\"version\":1}",
            "{\"protocol\":\"json\"}",
            "not json",
            "",
        ] {
            assert_eq!(Protocol::from_handshake(bad), None, "{bad:?}");
        }
    }
}
