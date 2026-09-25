# Licence, and why it is this one

NocTORnal is licensed under the **GNU Affero General Public License,
version 3 or later** (AGPL-3.0-or-later). The full text is in
[`LICENSE`](LICENSE).

    NocTORnal, HUMINT / social network analysis for cybercrime investigation
    Copyright (C) 2026 elemosecurity

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
| [`python-igraph`](https://python.igraph.org/) | **GPL-2.0-or-later** | Betweenness, brokerage, k-core, components. `docs/02`: "igraph, not NetworkX". NetworkX is pure Python and falls over around 50k edges when you ask for betweenness. |
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

Everything else in the tree is permissive (MIT, BSD-2-Clause,
BSD-3-Clause, Apache-2.0, PSF, ISC) and imposes only attribution, apart
from the two copyleft SNA libraries above and four weak-copyleft pieces,
none of which constrains the project's own licence:

- `certifi` is **MPL-2.0**, a file-level copyleft that names the GNU
  licences as Secondary Licenses, so it combines with AGPL-3.0; its CA
  bundle is used unmodified.
- `libquadmath` (**LGPL-2.1-or-later**) and `libgfortran`
  (**GPL-3.0-or-later with the GCC Runtime Library Exception 3.1**) ship
  inside numpy's Linux wheels, beside OpenBLAS (BSD-3-Clause). The
  exception covers exactly this use: a runtime library linked into a
  program compiled with GCC.
- `Modest` (**LGPL-2.1**) is compiled into selectolax's binary and
  imported by the package's own `__init__`, but never called: the forum
  parsers use `selectolax.lexbor` only (an AST test holds `forum_parse.py`
  and `forum_adapters.py` to that).

The two copyleft entries above are the only ones that constrain the
project's own licence. To re-audit:

```bash
python -m pip install pip-licenses && pip-licenses --format=markdown --with-urls
```

Re-run it before any release. A dependency that quietly changes licence
between versions is the kind of thing that is discovered by a lawyer
rather than by a developer, and always at the worst moment.

---

## Dependencies added for the 2026-09 roadmap build

Each was checked on 2026-09-24 against the bar every pin here meets:
wheels for CPython 3.12, 3.13 and 3.14 on Linux (x86_64 and aarch64),
Windows and macOS, or pure Python, or else an optional extra whose absence
the product shows as a gap. Licences are read from each wheel's own
metadata. The exact versions are in `constraints.txt`.

| Distribution | Licence | Bundles | Why it is here |
|---|---|---|---|
| `numpy` | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | Linux wheels: OpenBLAS (BSD-3-Clause), libgfortran (GPL-3.0-or-later WITH GCC-exception-3.1), libquadmath (LGPL-2.1-or-later) | CONCOR positional analysis. Installed with the API. |
| `selectolax` | MIT | lexbor (Apache-2.0, NOTICE below), Modest (LGPL-2.1, imported by the package, never called) | Parsing collected forum pages, with the lexbor backend only. Installed with the API. |
| `pefile` | MIT | | Static triage of Windows executables among samples. Installed with the API. |
| `urllib3` | MIT | | Imported directly by the sample stores; now declared rather than inherited through minio. |
| `certifi` | MPL-2.0 | | Imported directly by the readiness probe; now declared. |
| `idna` | BSD-3-Clause | | UTS-46 host normalisation in the egress policy; now declared by the API as well. |
| `telethon` | MIT | | Telegram collection. Optional: the `telegram` extra. |
| `python-socks` | Apache-2.0 | | Telethon's SOCKS5 client to the egress proxy (the `telegram` extra), and the egress wire-contract tests (the `dev` extra). |
| `pyaes` | MIT | | Needed by Telethon (the `telegram` extra). Published only as a pure-Python sdist, built without a compiler. |
| `rsa` | Apache-2.0 | | Needed by Telethon (the `telegram` extra). |
| `pyasn1` | BSD-2-Clause | | Needed by rsa (the `telegram` extra). |
| `yara-x` | BSD-3-Clause | | YARA scanning of samples. Optional: the `yara` extra, whose macOS wheels need macOS 14 or newer. |

`cryptography` was already here; the API now requires 47.0 or newer, for
the hpke module the egress proxy seals its exits with.

### lexbor's NOTICE

selectolax compiles in lexbor, whose Apache-2.0 licence asks that its
NOTICE travel with it. The wheel does not ship the file, so it is
reproduced here, verbatim from `selectolax-0.4.12.tar.gz`,
`lexbor/NOTICE`:

```
   Lexbor.

   Copyright 2018-2020 Alexander Borisov

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

## Ported into this tree: TLSH and ssdeep

`apps/api/src/noctornal_api/fuzzyhash.py` carries two fuzzy hashes as pure
Python ports, so that no compiled extension is needed to hash a sample:

- **TLSH**, the Trend Micro Locality Sensitive Hash, ported from the py-tlsh
  4.12.1 C++ sources (128 buckets, 1-byte checksum). Copyright 2010-2014
  Trend Micro. This product includes software developed at Trend Micro
  (http://www.trendmicro.com/). TLSH is offered under Apache-2.0 or BSD;
  this port is used under the BSD 3-Clause licence, whose full text is kept
  in the file's header.
- **ssdeep**, the context triggered piecewise hash, ported from libfuzzy
  2.14.1 (fuzzy.c, edit_dist.c). Copyright (C) 2002 Andrew Tridgell;
  (C) 2006 ManTech International Corporation; (C) 2013 Helmut Grohne;
  (C) 2014 kikairoya; (C) 2014 Jesse Kornblum; (C) 2017 Tsukasa OI.
  GPL-2.0-or-later, used here under GPL-3.0, which section 13 of the
  AGPL-3.0 lets this project combine with.

YARA rule sets an operator uploads or imports are stored in the
deployment's database, not redistributed by this project; a backup or
export handed to another party carries them and their licences.

## MinIO server and client images (mirrored)

The development stack, the production compose file and CI run MinIO's last
community builds, unmodified: server `RELEASE.2025-04-22T22-12-26Z` and
client `RELEASE.2025-08-13T08-35-41Z`, as published at `quay.io/minio/minio`
and `quay.io/minio/mc`. MinIO withdrew those images and binaries from public
download on 2026-09-25, so this project mirrors the same images, byte for
byte, at `ghcr.io/dboudreau00/minio` and `ghcr.io/dboudreau00/mc`, for
linux/amd64 only (the platform this project's machines held). Both are
licensed under the GNU Affero General Public License v3.0; their
corresponding source is the upstream repositories at those release tags,
`https://github.com/minio/minio` and `https://github.com/minio/mc`.
