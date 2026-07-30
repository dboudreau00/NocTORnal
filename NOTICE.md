# Licence, and why it is this one

NocTORnal is licensed under the **GNU Affero General Public License,
version 3 or later** (AGPL-3.0-or-later). The full text is in
[`LICENSE`](LICENSE).

    NocTORnal — HUMINT / social network analysis for cybercrime investigation
    Copyright (C) 2026 sYYn

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at
    your option) any later version.

    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
    General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.

---

## This was not a free choice

**The SNA maths is copyleft, and it is not optional.**

| Dependency | Licence | Why it is here |
|---|---|---|
| [`python-igraph`](https://python.igraph.org/) | **GPL-2.0-or-later** | Betweenness, brokerage, k-core, components. `docs/02`: "igraph, not NetworkX" — NetworkX is pure Python and falls over around 50k edges when you ask for betweenness. |
| [`leidenalg`](https://github.com/vtraag/leidenalg) | **GPL-3.0-or-later** | Leiden community detection. `docs/03`: not Louvain, which can produce internally disconnected communities. |

Both are imported directly by `apps/api/src/noctornal_api/analytics.py`.
A work that links GPL code and is distributed must itself be distributed
under GPL-compatible terms, so **MIT, BSD and Apache-2.0 were never
available for the whole**, whatever the rest of the tree permits.

Given that the choice was between GPL-3.0 and AGPL-3.0, AGPL is the
coherent one: NocTORnal is a *networked service*. Under plain GPL-3.0 a
vendor could run a modified NocTORnal as a hosted product and never
publish a line of it, because they would never "distribute" a copy.
AGPL §13 closes that. For a tool whose entire value proposition is that
its handling of evidence can be inspected and trusted, a closed fork
serving investigators would be the worst possible outcome.

`leidenalg` being GPL-3.0-**or-later** is what makes AGPL-3.0 reachable
at all; a GPL-2.0-**only** dependency anywhere would have forced GPL-2.0
and ruled AGPL out.

### What this means in practice

- **Running it inside your organisation is unaffected.** AGPL's network
  clause bites when you offer the software to users *over a network*, not
  when your own analysts use your own deployment. Internal use imposes no
  publication duty.
- **Modifying it and offering it as a service** obliges you to offer those
  users the corresponding source of your version.
- **Case data is yours.** The licence covers the software. Nothing in it
  reaches your evidence, your graph or your reports.
- **Relicensing later is possible but bounded.** The copyright holder can
  relicense their own code; they cannot relicense igraph or leidenalg. Any
  future permissive release would require replacing both, which means
  replacing the analytics engine.

---

## Third-party material that is *not* bundled

### The YARA rule corpus

Fetched at runtime, **never committed and never redistributed**. Several
upstream rule sources carry non-permissive licences and are flagged in
`yara/sources.json`. Clearing them is a prerequisite for redistribution or
commercial use, and that clearance has not been done. Rules land in a
gitignored tree.

### `monero-wallet-rpc` and similar operator-supplied binaries

Not applicable to this project, but the same principle governs anything
added later: a tool that handles evidence does not bundle binaries whose
provenance the operator cannot verify.

---

## Other dependencies

Everything else in the tree is permissive (MIT, BSD-3-Clause, Apache-2.0,
PSF, ISC) and imposes only attribution. The two copyleft entries above are
the only ones that constrain the project's own licence. To re-audit:

```bash
python -m pip install pip-licenses && pip-licenses --format=markdown --with-urls
```

Re-run it before any release. A dependency that quietly changes licence
between versions is the kind of thing that is discovered by a lawyer
rather than by a developer, and always at the worst moment.
