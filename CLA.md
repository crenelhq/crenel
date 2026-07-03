# Contributor License Agreement (CLA)

> **Status: prepared, not yet activated.** This CLA is part of the public-launch
> scaffolding. It takes effect only when the project is published and the
> **first external contribution** is proposed. Until then it is a template the
> maintainer reviews and finalizes (legal-entity name, contact address, and the
> final project name are filled in at activation — see the placeholders below).

This project accepts contributions under a **dual sign-off** model:

1. a **DCO** sign-off on every commit (lightweight, per-commit — see
   [`DCO.txt`](DCO.txt) and [`CONTRIBUTING.md`](CONTRIBUTING.md)), **and**
2. a **one-time CLA** acceptance per contributor (this document), recorded before
   that contributor's **first** change is merged.

The DCO certifies *provenance* (you have the right to submit the code). The CLA
additionally grants the project the *licensing latitude* an open-core project
needs — most importantly the right to relicense/sublicense contributions as part
of the project (including in the separately-licensed enterprise directory; see
[`docs/OPEN-CORE.md`](docs/OPEN-CORE.md)) without re-contacting every contributor.
Both are required; see **Policy** at the bottom.

The terms below are adapted from the Apache Software Foundation's Individual and
Corporate CLAs (Apache-2.0-compatible). `[Project]` / `[Maintainer / Legal
Entity]` / `[contact]` are placeholders finalized at activation.

---

## Part A — Individual Contributor License Agreement ("ICLA")

You accept and agree to the following terms for Your present and future
Contributions submitted to `[Project]`. Except for the license granted herein to
`[Maintainer / Legal Entity]` ("the Project") and recipients of software
distributed by the Project, You reserve all right, title, and interest in and to
Your Contributions.

1. **Definitions.** "You" means the individual who Submits a Contribution.
   "Contribution" means any original work of authorship, including any
   modifications or additions to an existing work, that is intentionally
   Submitted by You to the Project for inclusion in, or documentation of, any of
   the products owned or managed by the Project. "Submit" means any form of
   electronic, verbal, or written communication sent to the Project, including
   but not limited to source-control systems and issue trackers managed by the
   Project, excluding communication conspicuously marked "Not a Contribution."

2. **Grant of Copyright License.** You grant to the Project and to recipients of
   software distributed by the Project a perpetual, worldwide, non-exclusive,
   no-charge, royalty-free, irrevocable copyright license to reproduce, prepare
   derivative works of, publicly display, publicly perform, sublicense, and
   distribute Your Contributions and such derivative works.

3. **Grant of Patent License.** You grant to the Project and to recipients of
   software distributed by the Project a perpetual, worldwide, non-exclusive,
   no-charge, royalty-free, irrevocable (except as stated in this section) patent
   license to make, have made, use, offer to sell, sell, import, and otherwise
   transfer Your Contribution, where such license applies only to those patent
   claims licensable by You that are necessarily infringed by Your Contribution
   alone or by combination of Your Contribution with the work to which it was
   Submitted. If any entity institutes patent litigation against You or any other
   entity alleging that Your Contribution, or the work to which You contributed,
   constitutes direct or contributory patent infringement, then any patent
   licenses granted to that entity under this Agreement for that Contribution or
   work shall terminate as of the date such litigation is filed.

4. **Representations.** You represent that You are legally entitled to grant the
   above licenses. If Your employer(s) has rights to intellectual property that
   You create that includes Your Contributions, You represent that You have
   received permission to make Contributions on behalf of that employer, that
   Your employer has waived such rights for Your Contributions to the Project, or
   that Your employer has executed a separate Corporate CLA with the Project.

5. **Original work.** You represent that each of Your Contributions is Your
   original creation (see the Corporate CLA for submissions on behalf of others).
   You represent that Your Contribution submissions include complete details of
   any third-party license or other restriction (including related patents and
   trademarks) of which You are personally aware and which are associated with
   any part of Your Contributions.

6. **No warranty / no support obligation.** You are not expected to provide
   support for Your Contributions, except to the extent You desire to. Unless
   required by applicable law or agreed to in writing, You provide Your
   Contributions on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.

7. **Notice.** You agree to notify the Project of any facts or circumstances of
   which You become aware that would make these representations inaccurate.

---

## Part B — Corporate / Entity Contributor License Agreement ("CCLA")

Use this part when Contributions are made on behalf of a **Legal Entity**
(employer or organization). The Entity accepts and agrees to the terms above
(Part A, sections 2–7, applied to the Entity as "You"), with the following
additions:

1. **Authorized signer.** The individual accepting this CCLA represents that they
   are authorized to bind the Entity to its terms.

2. **Schedule of authorized contributors.** The Entity will maintain, and provide
   on request, a list of the individuals who are authorized to Submit
   Contributions on its behalf. The Entity is responsible for keeping that list
   current (additions/removals via the same acceptance mechanism below). Each
   listed individual must also be made aware of these terms.

3. **Scope.** This CCLA covers Contributions Submitted by the Entity's authorized
   contributors. It does not change the licensing of the project's existing code,
   nor does it obligate either party to use or incorporate any Contribution.

---

## How to accept (the sign-off flow)

The acceptance mechanism is deliberately lightweight for a solo-maintained
project. **At activation the maintainer enables exactly one** of the following
(preference order):

1. **CLA-assistant bot (preferred once hosted publicly).** A CLA-assistant–style
   check on the forge (e.g. a status check on the first PR) records acceptance
   against your account. One click, one time; the bot stores the signed record.
   No bot is wired up yet — this is the target state.

2. **Ledger file (works today, no bot needed).** Add one line to a
   `contributors/CLA-signed.md` ledger in your first PR:

   ```
   - <Full Name> <email> — ICLA — <date> — signed-off via PR #<n>
   # or, for an entity:
   - <Entity Legal Name> (signer: <Full Name> <email>) — CCLA — <date> — PR #<n>
   ```

   By adding that line in a commit you also DCO-sign (`-s`), you affirm that you
   have read this CLA and agree to it for all your past and future Contributions
   to the project.

3. **Email / signed statement.** Email a statement of acceptance (the text "I
   have read and agree to the Crenel CLA, Parts A/B as applicable") to
   `[contact]`. The maintainer records it in the ledger on your behalf.

The maintainer records the acceptance date and the mechanism used. Acceptance is
**one-time per contributor** (or per entity) and covers all subsequent
Contributions unless you revoke it in writing (revocation is not retroactive).

---

## Policy — CLA + DCO before the first external PR is merged

- **Every commit** in a contribution must be **DCO-signed** (`git commit -s`).
  This is enforced per-commit and applies to all contributors including the
  maintainer.
- **Before a contributor's first PR is merged**, that contributor (or their
  entity) must have **accepted this CLA** via one of the mechanisms above. The
  maintainer will not merge a first-time external contribution until both are
  satisfied.
- These two requirements are independent: DCO is per-commit and ongoing; the CLA
  is one-time per contributor. Subsequent PRs from an already-accepted
  contributor need only the per-commit DCO sign-off.
- The maintainer's own commits are DCO-signed; the maintainer is the copyright
  owner of the original work and is bound by the project license directly.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the practical mechanics (how to
sign off, the PR checklist) and [`docs/OPEN-CORE.md`](docs/OPEN-CORE.md) for why
the open-core boundary makes the CLA's relicensing grant necessary.
