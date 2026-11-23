# Kemlock Server on TrueNAS

This folder is the app as the TrueNAS apps catalog (github.com/truenas/apps) lays one out, under
`ix-dev/community/kemlock-server/`:

```
app.yaml                       name, versions, run-as user, capabilities
item.yaml                      catalog listing: categories, icon, screenshots
ix_values.yaml                 the image and constants the template reads
questions.yaml                 the install form
templates/docker-compose.yaml  the template the catalog's Python library renders to Compose
templates/test_values/         values the catalog's CI renders the template with
```

It installs the official image and one dataset (or host path) for `/data`. Nothing else is
required; the first admin comes from the one-time setup code in the app's log.

To publish it, copy this folder into a fork of the apps catalog, run the catalog's own checks (it
fills `lib_version_hash` in `app.yaml` and validates `questions.yaml` against the library), and
open a pull request. The template calls the catalog library's helpers, so it can only be
rendered there, and the helper names should be checked against the library version in use.
