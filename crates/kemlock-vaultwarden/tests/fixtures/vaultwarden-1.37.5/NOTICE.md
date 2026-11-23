# Vaultwarden fixtures

`migrations/sqlite/*/up.sql` are copied unchanged from Vaultwarden 1.37.5
(<https://github.com/dani-garcia/vaultwarden/tree/1.37.5/migrations/sqlite>).

Vaultwarden is licensed under the GNU Affero General Public License, version 3
(<https://github.com/dani-garcia/vaultwarden/blob/1.37.5/LICENSE.txt>), the same licence as this
repository, so the files may be copied here. Copyright remains with the Vaultwarden authors,
Daniel Garcia and contributors.

The tests run these files in order against an empty SQLite database, as Vaultwarden's own
`diesel` migrations do, so the fixture databases have exactly the schema of that release. The
importer pins each schema release it accepts with a fixture like this one.
