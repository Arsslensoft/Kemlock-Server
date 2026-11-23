# Governance

Kemlock Server is a maintainer-led project. This page says who decides what, and how that can
grow. It is short because the project is small; it will change as the project does.

## Roles

- **Lead maintainer**: sets the direction, owns the design and has the final say. Today that is
  `@Arsslensoft` (see [MAINTAINERS.md](MAINTAINERS.md)).
- **Maintainers**: review and merge pull requests, triage issues, and cut releases. They follow the
  design and the [code of conduct](CODE_OF_CONDUCT.md).
- **Contributors**: anyone who sends an issue, a pull request, a review or an answer. Contributors
  sign off their commits ([CONTRIBUTING.md](CONTRIBUTING.md)).

## How decisions are made

- Most changes are decided in pull request review: a maintainer approves, CI is green, and it is
  merged. Small disagreements end there.
- Anything that changes the design (a new feature, an API, a byte format, a dependency of weight,
  the licence) is raised in an issue or a discussion first. The lead maintainer decides after
  discussion, and records the decision in the design's Decisions table or in `docs/`.
- We aim for consensus. When there is none, the lead maintainer decides and says why.
- Two things are not decided by a vote or by a pull request: the Bitwarden API answers as
  Vaultwarden does, and the byte formats in [docs/crypto.md](docs/crypto.md) stay stable, because
  other people's vaults depend on them. Changes to either need the lead maintainer's explicit
  approval, and for the formats, a migration path.
- Security reports are handled privately by the maintainers, under [SECURITY.md](SECURITY.md), not
  in public discussion.
- The licence is AGPL-3.0, and contributions come under it with a DCO sign-off. Relicensing would
  need the consent of every contributor whose code is affected.

## Becoming a maintainer

There is no quota and no clock. A contributor is invited when they have:

- sent several changes that were merged with little rework, across more than one part of the code;
- reviewed other people's changes well and kindly;
- shown they understand the design, the compatibility rules and the security stakes; and
- kept to the code of conduct.

The lead maintainer (or any maintainer) can nominate someone, and the lead maintainer decides after
asking the other maintainers. A new maintainer is added to [MAINTAINERS.md](MAINTAINERS.md) and
`.github/CODEOWNERS` by a pull request, and gets write access.

Maintainers who are away for a long time may be moved to emeritus with thanks, and returned when
they come back. A maintainer who breaks the code of conduct, or who acts against the project's
interests, can be removed by the lead maintainer.

## Changing this page

Open a pull request. The lead maintainer approves changes to governance.
