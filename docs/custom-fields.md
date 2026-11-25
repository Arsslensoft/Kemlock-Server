# Custom fields and trusted devices: what the server offers the apps

Two small contracts the Kemlock apps read. Nothing here changes a byte of an item or of a key
copy: custom field *values* live inside the encrypted item body (see the item-format additions in
`docs/crypto.md`), and a trusted-device copy stays opaque to the server.

## Custom fields an admin offers

An admin can offer fields people add to their items ("Employee ID", "Cost center"). A definition is
a **name**, a **type** and the **item types** it applies to. These are not secret, so the server
keeps them in the clear (the `custom_fields` table) and every signed-in client reads them. The
values never reach the server. **Nothing is ever required**: a person may leave any field empty,
and no definition has a "required" flag.

| Member | Meaning |
|---|---|
| `id` | A UUID, stable across renames. An item that carries a value for the field names it by this id. |
| `name` | 1 to 64 characters, no control characters, white space collapsed. Unique across the server, whatever the case. |
| `type` | `text`, `hidden` (masked until shown) or `checkbox`. |
| `kinds` | The word `"all"` (every type that takes custom fields, now and later), or a list of item kind ids from `login`, `note`, `otp` (MFA code), `backup-codes`, `card`, `identity`, `contact`, `certificate`, `ssh-key`, `pgp-key`, in that order. A file and a passkey take no custom fields. |

A server holds at most 100 definitions.

### What a client reads

`GET /kem/v1/custom-fields` (any signed-in device):

```json
{
  "fields": [
    { "id": "7d0f…", "name": "Employee ID", "type": "text", "kinds": "all" },
    { "id": "1b9e…", "name": "Cost center", "type": "hidden", "kinds": ["login", "card"] }
  ],
  "allowOwn": true
}
```

`fields` are oldest first. `allowOwn` is whether people may add fields of their own to an item
("Your own field" in the forms); it is `true` until an admin turns it off, and fields already on
items stay either way. Deleting a definition deletes no value: the server can't open an item, so an
item keeps what it holds, and how an app shows a value whose definition is gone is the app's.

### What the console writes

All under `/admin/v1`, admins only, every write with a step-up token and recorded in the event log
(`admin.custom_field.create`, `.update`, `.delete` and `.allow_own`; the target is the field's id,
or `true` or `false` for the switch):

| Route | |
|---|---|
| `GET /custom-fields` | The same answer as the clients'. |
| `POST /custom-fields` | `{ "name", "type", "kinds" }`; answers 201 with the field. 409 when another field has the name or the server holds 100. |
| `PUT /custom-fields/{id}` | The same body; the id and creation time stay. |
| `DELETE /custom-fields/{id}` | 204. Items keep the values they hold. |
| `PUT /custom-fields/allow-own` | `{ "allow": bool }`; answers `{ "allowOwn": bool }`. |

## Trusted devices

A trusted device keeps a copy of the root key wrapped by a key only it holds (`docs/crypto.md`,
"The trusted-device copy of the root key"). So only that device can make its copy; the server and
the other devices can only take one away.

- `GET /kem/v1/devices` lists each device with `trusted` and `trustedSince` (when its copy was
  made; `null` when it holds none).
- `DELETE /kem/v1/devices/{id}/key-copy` stops trusting one of the account's devices: its copy is
  deleted and its session goes on (204; 404 for a device of another account; recorded as
  `device.untrust`). Any device of the account may ask, as any may sign another out.
- `DELETE /kem/v1/devices/key-copy` is the same for the signed-in device itself, as before.
- Trust is for Kemlock apps only. Amethystora Vault and Bitwarden apps hold no copy, and the web
  vault offers them Sign out alone.
