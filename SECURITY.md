# Security policy

Kemlock Server holds people's vaults, as ciphertext. If you find a way to read one, to sign in as
someone else, to widen what a member can see, or to crash or take over a server, please tell us
privately first.

## Report a vulnerability

Open a private report with **GitHub security advisories** at
<https://github.com/Arsslensoft/Kemlock-Server/security/advisories/new>. It isn't public until a
fix is out, it keeps the report, the discussion and the fix in one private place, and it lets us
ask for a CVE. It is also the `Contact` line of every server's `/.well-known/security.txt`.

Include what you need to reproduce it: the version (the release or the image tag),
the configuration that matters, and the steps. A proof of concept helps; a working exploit against
someone else's server does not (see Safe harbour).

Flaws in a particular operator's server (a weak setting, an exposed port) belong to that operator:
use the `Contact` in the `security.txt` of their server. Flaws in the software belong here.

## What to expect

| When | What we do |
| --- | --- |
| Within 3 business days | We answer: we have the report, whether we can reproduce it, and who is looking. |
| Within 90 days | We release a fix and publish an advisory that names you, unless you ask us not to. |

If a fix needs longer than 90 days, we tell you why before the 90 days are up and agree a date
with you. If the flaw is being used against people, we release as soon as there is a fix, even if
the 90 days are not over. If you don't hear from us in 3 business days, write again: a report
that went astray is our fault, not yours.

## Safe harbour

We will not take legal action against, or ask anyone to take it against, research that:

- is done in good faith to find and report a vulnerability in Kemlock Server;
- is done against a server you run or against accounts you made on one, and never against
  other people's data;
- stops once you have shown the flaw: no copying, changing or deleting data you aren't entitled
  to, no pivoting further, no denial of service, no social engineering of our contributors or of
  a server's operator;
- is reported to us privately and kept private until the advisory is out or the 90 days are up.

If you aren't sure whether something is within this, ask first, in a private advisory.

## Supported versions

The latest release gets security fixes. Until 1.0, that is the only one.

## What counts

In scope: the server and the web vault it serves, the Kemlock API (`/kem/v1`), the Bitwarden API
as the server answers it, the admin console API, federation between servers, the release
artefacts (images, binaries, their signatures and SBOMs), and our CI.

Out of scope: findings that need a modified client or a device the attacker already controls and
has unlocked; a missing hardening header that has no effect; reports from automated scanners with
no demonstration; the Bitwarden API's use of RSA-2048 OAEP-SHA1 for sharing, which compatibility
with Bitwarden clients requires and the design records; and problems in a dependency that don't
affect Kemlock Server (report those upstream).

How we look for flaws ourselves: `cargo-deny`, `cargo-audit` and `cargo-vet` on every change,
`cargo-fuzz` on every parser of untrusted bytes, and an independent audit before 1.0.
