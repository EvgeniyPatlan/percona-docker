# Percona Distribution for PostgreSQL 18 on Docker Hardened Images

Proof of concept. All numbers below were measured on 2026-11-12 with the commands in
[Reproduce](#9-reproduce). They change as the vulnerability databases change; re-run before quoting them.

## 1. What it is

`percona-distribution-postgresql:18-dhi` ships the same component set as the UBI-based
`percona/percona-distribution-postgresql:18.x` image (Percona Server for PostgreSQL 18, contrib, JIT,
pg_tde, pg_oidc_validator, pg_stat_monitor, pgaudit, set_user, pg_repack, pgvector, wal2json, pg_cron,
pgBackRest, Patroni) on top of `dhi.io/debian-base:trixie` (Docker Hardened Images, Debian 13) instead of
`ubi9-minimal`.

Build model:

- A `dhi.io/debian-base:trixie-dev` builder stage adds the Percona repository (`dhi-common/setup-apt.sh`,
  key verified by fingerprint), resolves the package list in `packages.txt` against the runtime base's dpkg
  database and unpacks the resulting `.deb` files into a copy of the runtime rootfs
  (`dhi-common/build-rootfs.sh`). Maintainer scripts are not run; the Dockerfile creates the user, directories
  and locale explicitly.
- The final stage is the unmodified runtime base with that rootfs copied over it. It has no package manager,
  no setuid/setgid files and no gosu. A shell (`sh`, `bash`) is still present because the entrypoint needs bash.
- Both base images are pinned by digest in the Dockerfile (`DHI_RUNTIME`, `DHI_BUILDER`).
- Package source policy: every package comes from `dhi.io`, `repo.percona.com`, or from an explicit,
  version-pinned allowlist of `deb.debian.org` packages (`allowlist.txt`). Anything else fails the build.
  The origin of every package is written to `/usr/share/percona/package-origins.tsv` in the image.
  See `dhi-common/README.md`.
- Only the PG18 image is covered here.

Not in this PoC: the operator postgres image (`postgresql-containers/build/postgres`) on DHI is out of scope.
Nothing in this directory is meant to be a drop-in replacement for it.

## 2. Build and run

From the repository root (requires `docker login dhi.io` with a Docker Hub account):

```bash
docker buildx build --load --build-context dhi-common=dhi-common \
    -t percona-distribution-postgresql:18-dhi percona-distribution-postgresql-18-dhi

docker run -d --name pg -e POSTGRES_PASSWORD=secret -p 5432:5432 \
    -v pgdata:/var/lib/postgresql percona-distribution-postgresql:18-dhi
psql -h 127.0.0.1 -U postgres        # password: secret
```

`PPG_REPO` (`release` default, `testing`, `experimental`) is a build arg. `PG_MAJOR` is also a build arg but must stay
`18` for now: `packages.txt`, `entrypoint.sh`, the tests and the workflow hardcode 18.

The entrypoint is derived from the upstream docker-library postgres entrypoint and supports the usual
environment: `POSTGRES_PASSWORD[_FILE]`, `POSTGRES_USER`, `POSTGRES_DB`, `POSTGRES_INITDB_ARGS`,
`POSTGRES_INITDB_WALDIR`, `POSTGRES_HOST_AUTH_METHOD` and `/docker-entrypoint-initdb.d`.

Hardened run (verified to start and become ready, see the Read-only row in the results):

```bash
docker run -d --read-only --cap-drop=ALL --security-opt no-new-privileges \
    --tmpfs /var/run/postgresql:uid=70,gid=70 --tmpfs /tmp -v pgdata:/var/lib/postgresql \
    -e POSTGRES_PASSWORD=secret percona-distribution-postgresql:18-dhi
```

## 3. Differences vs the UBI image

| | UBI image (`18.6.1-4`) | DHI image |
|---|---|---|
| User | uid 26 | uid 70 (same as `dhi.io/postgres`) |
| PGDATA | `/data/db` | `/var/lib/postgresql/18/data` (volume `/var/lib/postgresql`) |
| Binaries | `/usr/pgsql-18/bin` | `/usr/lib/postgresql/18/bin` (on `PATH`) |
| Privilege drop | gosu | none; no gosu in the image |
| Root | the image `USER` is 26; if started as root, the entrypoint drops to `postgres` with gosu | the entrypoint refuses to run as uid 0 with an explicit error |
| Package manager | dnf, microdnf, rpm | none |

Behaviour to know about:

- **Arbitrary UID.** `--user <uid>` works if PGDATA and the socket directory are writable by that uid
  (for example a volume owned by it, and a writable `/run/postgresql` or `/var/run/postgresql`). The entrypoint
  uses `libnss_wrapper` so `initdb` works for a uid with no `/etc/passwd` entry. Without writable directories it
  fails with a raw error and no hint, for example
  `chmod: changing permissions of '/var/lib/postgresql/18/data': Operation not permitted`
  (measured with `--user 1234:1234` and no volume). This is not yet a friendly error, see
  [limitations](#10-known-limitations-and-next-steps).
- **Root.** `docker run --user 0 ...` exits with
  `error: this image must not run as root; start the container as an unprivileged user (default uid 70)`.
- **pg_hba.conf.** The generated file trusts local socket connections and `127.0.0.1`/`::1` (for both normal
  and replication connections) and uses `md5` for all other hosts, as in the upstream docker-library image
  (observed in a running container). Anyone who can run a process inside the container, or share its network
  namespace, can connect as any user without a password.
- Locale `en_US.UTF-8` is compiled into the image because maintainer scripts do not run.

## 4. Results

Measured 2026-11-12, trivy 0.69.3, grype 0.116.1 (databases as of that day), syft `anchore/syft:v1.57.1`,
dockle `goodwithtech/dockle:v0.4.15`, Docker 29.1.3, buildx 0.36.1.

Images compared:

- Baseline: `percona/percona-distribution-postgresql:18.6.1-4`, image ID
  `sha256:9682f32eabe22d2eb15fef4b11f20d9b523e912551ffe60b0afa9f492f3c8103`, RepoDigest
  `percona/percona-distribution-postgresql@sha256:27a1dba816fcc4cec88f216d54e3ec86db4c1d4b16799f49800055c41606e11e`.
- DHI: `percona-distribution-postgresql:18-dhi` built locally from this branch, image ID
  `sha256:7361ff2b130244f826520a4b408eba7a870339162b2d0d45f81bde3a641cca44`.
- DHI bases: `DHI_RUNTIME` `sha256:c12f6059a81c93b872dfbc6042d8c045256db32b7e23ed5765a90b89726eac93`,
  `DHI_BUILDER` `sha256:94571f3dc07fbc7166f6f1cbf1fe068a7647198ee2554e6b90d59a68cc8b053c`.
- Percona packages in the DHI image: percona-postgresql-18 3:18.6-1.trixie, percona-patroni 1:4.1.5-1.trixie,
  percona-pgbackrest 1:2.59.1-1.trixie, percona-pg-tde18 1:2.2.2-1.trixie.

| Metric | UBI baseline | DHI PoC |
|---|---|---|
| Size | 419 MiB gzip'd save / 1134 MiB uncompressed | 127 MiB gzip'd save / 352 MiB uncompressed |
| Packages (syft, dpkg/rpm entries) | 523 | 198 |
| CVEs, trivy (all) | 8062 (C 1, H 188, M 5398, L 2474) | 435 (C 2, H 101, M 152, L 156) |
| CVEs, trivy (fixable) | 177 (C 1, H 42, M 121, L 12) | 13 (C 1, H 7, M 5, L 0) |
| CVEs, grype (all) | 1391 (C 1, H 63, M 959, L 364) | 508 (C 29, H 180, M 136, L 28) |
| CVEs, grype (fixable) | 163 (C 1, H 36, M 114, L 12) | 78 (C 12, H 40, M 24, L 2) |
| Package manager | yes (dnf, microdnf, rpm) | no |
| Shells | yes (sh, bash) | yes (sh, bash) |
| setuid files | 10 | 0 |
| Root by default | no (uid 26) | no (uid 70) |
| SBOM / provenance attached | no / no | not queryable for a local image; produced by the CI build, see section 7 |
| `--read-only --cap-drop=ALL --security-opt no-new-privileges` | works | works |
| Dockle (CIS-DI) | fatal 0, warn 0, info 3, pass 13 | fatal 0, warn 0, info 2, pass 14 |
| Scanner visibility | trivy and grype list percona-postgresql18-server, percona-patroni | trivy and grype list percona-postgresql-18, percona-patroni |

Totals include Unknown/Negligible severities not shown in the C/H/M/L breakdown.

CVEs are unique (id, package, version) matches; fixable means a fixed version is known. The two scanners
disagree strongly on the DHI image, see section 5. Compare each tool only against itself (baseline vs DHI);
trivy and grype counts differ widely on both images (for example 8062 vs 1391 on the UBI image).

CVEs by package origin, grype, DHI image (joined with `package-origins.tsv`; `unattributed` means the match
is not a dpkg package from the report, for example a Python dist-info or a statically detected binary):

| Origin | Critical | High | Medium | Low | Other | Total |
|---|---|---|---|---|---|---|
| dhi | 28 | 147 | 101 | 19 | 100 | 395 |
| percona | 0 | 0 | 0 | 0 | 0 | 0 |
| debian-allowlist | 0 | 4 | 1 | 0 | 0 | 5 |
| unattributed | 1 | 29 | 34 | 9 | 35 | 108 |

Reading it: the 22 Percona packages contribute no grype matches, almost all findings sit in DHI-built packages,
and the allowlisted Debian packages contribute 5. Of the 29 Criticals, 28 are in DHI-built packages
(curl, libcurl4t64, libxml2 and the curl binary matches) and 1 is `certifi` (an allowlisted Debian package, listed
as unattributed because grype matched it through its Python metadata).

Baseline has no origin report, so it is a single bucket: C 1, H 63, M 959, L 364, other 4, total 1391.

## 5. Scanner notes

### 5.1 Why grype reports 29 Critical and trivy 2 on the DHI image

Measured on the same image on 2026-11-12:

- Trivy's two Criticals are `libxml2` (CVE-2026-6653) and `certifi` (GHSA-6q48-6c7w-9gw2, fixed in 2026.10.18).
- Grype's 29 Criticals are: 8 on the `curl` deb, 8 on the `libcurl4t64` deb, 1 on `libxml2`, 1 on `certifi`, and 11
  more for `curl` 8.14.1 matched as a **binary** (grype's binary cataloger finds `/usr/bin/curl` and matches it
  independently of the dpkg entry, so each curl CVE is counted twice, once as `deb` and once as `binary`).
- The 16 curl/libcurl4t64 deb matches are the same CVEs that trivy reports for `curl`, but trivy rates them
  Medium or Low (curl: 2 High, 9 Medium, 28 Low in total) and grype rates them Critical. For example
  CVE-2026-9079 is MEDIUM in trivy and Critical in grype. The Debian security tracker data does not carry a
  severity for these, so the tools fall back to other sources. Grype marks the deb matches `wont-fix` (the Debian
  tracker has no fix for the installed `+dhi1` build); trivy reports the same packages as `affected`.
- The packages are DHI builds (`8.14.1-2+deb13u7+dhi1`, `2.12.7+dfsg+really2.9.14-2.1+deb13u3+dhi3`) and both
  tools match them against Debian's data, not DHI's.

So the gap is mostly severity scoring plus the duplicate binary match, not different sets of vulnerable packages.
Treat the Critical count as scanner-dependent and use the fixable counts and the origin table instead.

### 5.2 Docker's VEX for DHI

DHI publishes an OpenVEX attestation (`https://openvex.dev/ns/v0.2.0`) for each base image; `verify-base.sh`
verifies its signature (section 7). The one for the pinned runtime base was extracted and applied to this image
on 2026-11-12:

- The statement set is small: 125 statements, 124 `not_affected` and 1 `under_investigation`, covering base
  packages only (glibc 60, gcc-14 20, systemd 18, tar 7, ncurses 6, coreutils 6, acl 4, openssl 2, ...). It does not
  mention curl or libxml2, which are not in the runtime base; they are installed into this image by the build.
- Applied as published (`trivy image --vex <file>` / `grype --vex <file>`), it had **no effect**: the VEX product
  purls carry qualifiers (`os_distro=trixie&os_name=debian&os_version=13`) and, for glibc, the source name
  (`glibc`) where the scanners use `distro=debian-13.7` and the binary name (`libc6`).
- With the qualifiers stripped from the purls, trivy dropped 8 findings (435 to 427; Low and Medium only) and grype
  suppressed 14 matches (Medium, Low and Negligible only). Critical and High did not change.

Conclusion: the VEX is useful for the base packages, but it needs a purl normalisation step to be consumed by
trivy/grype and does not address the findings that matter here (curl, libxml2, certifi). Making VEX part of the CI
comparison is a next step; DHI's VEX statements also do not extend to packages added on top of the base.

### 5.3 Which Percona package pulls in curl and libcurl

Taken from the `Depends` fields in the image's dpkg database (2026-11-12):

- `percona-postgresql-18` depends on `curl` (the command-line tool, which in turn depends on `libcurl4t64`).
- `percona-pg-tde18` and `percona-pg-oidc-validator18` depend on `libcurl4t64` (they link libcurl).
- `libxml2` is pulled in by `percona-postgresql-18` and `percona-pgbackrest`, and through `libxslt1.1`.

Consequence: libcurl is required by two extensions, but the curl **binary** is only there because
`percona-postgresql-18` declares `Depends: curl`. If that dependency were relaxed or moved to `Recommends`
(a packaging change owned by Percona; whether anything in the server package invokes the curl binary
was not checked), `/usr/bin/curl` and its 11 binary
and 8 deb Critical matches would disappear from this image. The libcurl4t64 and libxml2 findings would stay.

The UBI baseline ships curl as well: `curl-minimal` and `libcurl-minimal` 7.76.1 are in the ubi9-minimal base and are
required by `percona-postgresql18-server`, `percona-pg_tde18`, `percona-pg_oidc_validator18`, rpm and the release
packages (checked with `rpm -q` and `--whatrequires` in `percona/percona-distribution-postgresql:18.6.1-4`). So curl is
not a DHI regression; on DHI it is present only because of Percona's dependency.

### 5.4 Gate ignore for the certifi advisory

`percona-distribution-postgresql-18-dhi/.trivyignore` (added 2026-11-12) holds one entry, `GHSA-6q48-6c7w-9gw2`, and is
passed to the CI gate step only (`--ignorefile`). `compare.sh` and `tests/test-image.sh` do not use it, so the
counts in section 4 still include this finding. Justification, checked on the image:

- `python3-certifi` 2025.1.31+ds (Debian, from the allowlist) is patched so that `certifi.where()` returns the system
  bundle `/etc/ssl/certs/ca-certificates.crt`. The package ships no bundled `cacert.pem`.
- The advisory is about the emSign roots. They are in the system bundle that comes from the DHI base
  (`ca-certificates`), so upgrading certifi would not change exposure; see section 10.
- Revisit when DHI ships `ca-certificates` without emSign Root CA - G1, emSign Root CA - C1 and emSign ECC Root CA - C3,
  or when certifi leaves the allowlist.

## 6. Non-DHI content

22 packages come from `deb.debian.org` through the allowlist (`allowlist.txt`, versions pinned). The image has 92
packages from DHI and 22 from Percona (136 in the origin report in total).

| Packages | Why they are needed |
|---|---|
| `python3-yaml python3-psycopg2 python3-requests python3-urllib3 python3-certifi python3-charset-normalizer python3-idna python3-chardet python3-psutil python3-dnspython python3-consul python3-etcd python3-dateutil python3-prettytable python3-six python3-cdiff python3-systemd` | Python dependencies of `percona-patroni`. |
| `libjson-perl libipc-run-perl libio-pty-perl` | Perl modules used by the `percona-postgresql-common` tooling. |
| `ssl-cert` | Dependency of `percona-postgresql-common` and also a direct dependency of `percona-postgresql-18` (snakeoil certificate tooling). |
| `libnss-wrapper` | Lets `initdb` run under an arbitrary UID (used by `entrypoint.sh`). |

Findings from these: 5 grype matches (4 High, 1 Medium), plus the `certifi` Critical that is counted as
unattributed (it is `python3-certifi` 2025.1.31; the advisory lists 2026.10.18 as the fix).

Ways to close the gap:

1. **Ask DHI to package them.** DHI already ships Python 3.13 and builds debs; the Patroni dependency set and
   `libnss-wrapper` are the best candidates. This gives rebuilt packages with provenance and VEX coverage.
2. **Vendor them through the Percona repository.** Percona already builds `percona-patroni`; it could also
   build or bundle its Python dependencies (as a virtualenv or `percona-patroni-deps` package) so they become
   `percona` origin, under Percona's control and update cadence. This also solves the stale certifi problem.
3. **Drop the dependency.**
   - The Perl modules come with the `percona-postgresql-common` tooling. A container does not need
     cluster-management tooling, so splitting that package or relaxing the dependency would remove three
     allowlist packages (the Perl modules; not tested). `ssl-cert` would stay, because `percona-postgresql-18`
     also depends on it.
   - `libnss-wrapper` could be dropped by supporting only uid 70, at the cost of arbitrary-UID support.
   - A variant without Patroni would remove the 17 Python packages, at the cost of dropping Patroni.

## 7. Compliance

### Dockle (CIS-DI)

Dockle `v0.4.15`, 2026-11-12. Both images: no fatal and no warnings.

| Code | Title | Baseline | DHI |
|---|---|---|---|
| CIS-DI-0005 | Enable Content trust for Docker | INFO | INFO |
| CIS-DI-0006 | Add HEALTHCHECK instruction to the container image | INFO | INFO |
| CIS-DI-0008 | Confirm safety of setuid/setgid files | INFO | not raised |

### CIS docker-bench-security

Not run. docker-bench-security's image checks (section 4) iterate over every image and container on the
host, so they cannot be scoped to the two images under comparison. Dockle covers the image-level CIS-DI items
for each image on its own, so it replaces docker-bench-security here. If a host-wide run is wanted, it can be added
to CI separately.

### DHI base verification (`dhi-common/verify-base.sh`)

Run on 2026-11-12 for both pinned base digests. Method: the attestations are OCI referrers of the linux/amd64
per-platform manifest. Each in-toto attestation is verified with `cosign verify --key <DHI public key>
--insecure-ignore-tlog=true` (the public key is downloaded from `registry.scout.docker.com/keyring/dhi/latest.pub`).

| Image | Cryptographically verified (cosign, DHI key) | Presence only |
|---|---|---|
| `debian-base:trixie@sha256:c12f6059...` | 15 attestations: CycloneDX, SPDX and Scout SBOMs, SLSA provenance v0.2 and v1, Scout provenance, SLSA verification summary, OpenVEX, vulnerability reports (Scout and in-toto vulns v0.2), source, changelog, secrets, virus, tests | cosign signature artifact on the index |
| `debian-base:trixie-dev@sha256:94571f3d...` | 15 attestations (same set of types) | cosign signature artifact on the index |

Both runs ended with `RESULT: all attestations verified with cosign against the DHI public key` (exit 0).

Which checks are what:

- **Cryptographic:** every in-toto attestation row, verified against Docker's public key. The transparency log
  (Rekor) check is skipped, so these results prove the attestations were signed by the DHI key, not that they
  appear in a public log.
- **Presence only:** the "cosign signature artifact on index" row. The signature attached to the multi-arch index
  is listed, but not verified, because cosign cannot verify it through a tag lookup. The image signature itself
  is therefore not covered by this script.

`verify-base.sh` exit codes: 0 ok, 1 a verification failed, 2 usage or environment error, 3 no attestations found.

### SBOM and provenance of this image

The CI build uses `--sbom=true --provenance=mode=max` (`.github/workflows/dhi-postgres-poc.yml`, multi-arch
OCI output in the test job, pushed to ghcr.io by the publish job). This attaches a BuildKit SPDX SBOM and SLSA provenance, which is expected to record the pinned base
digests (`DHI_RUNTIME`, `DHI_BUILDER`) as build inputs. The OCI tar is uploaded as a workflow artifact. The
local `docker --load` build used for the numbers above has neither, which is why the table says "not queryable".
Because `build-rootfs.sh` writes the unpacked packages into `/var/lib/dpkg/status`, syft/trivy/grype also see
the Percona and allowlist packages from inside the image. The provenance and SBOM content is to be confirmed on the
first CI run; no CI-produced SBOM has been inspected yet.

## 8. CI

`.github/workflows/dhi-postgres-poc.yml` runs on `workflow_dispatch` (input `baseline`, default
`percona/percona-distribution-postgresql:18.6.1-4`) and on pushes to `dhi-postgres-poc` that touch
`dhi-common/**`, `percona-distribution-postgresql-18-dhi/**` or the workflow itself. The only registry it pushes to
is `ghcr.io` (job 3); nothing is pushed to Docker Hub. Jobs:

1. **Verify DHI base images**: logs in to `dhi.io`, runs `dhi-common/verify-base.sh` for the pinned digests.
2. **Build, test and scan**: builds the multi-arch OCI image once (SBOM, provenance, OCI source and revision
   labels) and uploads it as an artifact; loads the linux/amd64 image from that tar into the local daemon (`skopeo`
   and `docker load`) and records its amd64 manifest and config digests, then checks the config digest against the loaded image ID; runs `tests/test-image.sh`, `tests/test-entrypoint.sh` and the `postgres-basics` and
   `postgres-initdb` tests from the repository's `test/` suite; runs `dhi-common/compare.sh` against the baseline and
   writes `summary.md` to the job summary; uploads all scan outputs (trivy, grype, SBOMs, dockle, origin TSV) as an
   artifact; and finally fails if trivy finds a fixable Critical vulnerability
   (`trivy image --severity CRITICAL --ignore-unfixed --exit-code 1 --ignorefile percona-distribution-postgresql-18-dhi/.trivyignore`,
   see section 5.4). The compare, upload and gate steps run even when an earlier test step failed (`!cancelled()`),
   so CVE results are not hidden by a test failure; the job still ends as failed in that case.
3. **Publish to GHCR**: runs only after jobs 1 and 2 both succeeded, and only for `push` and `workflow_dispatch`.
   It does not rebuild: it downloads the OCI tar artifact of the same run and copies it with
   `skopeo copy --all` to `ghcr.io/<lowercased repository owner>/percona-distribution-postgresql` under the tags
   `18-dhi` and `18-dhi-<short commit sha>`. `--all` keeps the index, both architectures, the SBOM and provenance
   attestation manifests and the index digest, so the pushed image is the same OCI image whose linux/amd64 variant
   was tested and scanned in job 2: job 2 compares the config digest of the tar's amd64 manifest with the ID of the
   image it loaded into the daemon and fails on a mismatch (the manifest digest itself differs after loading, because
   the DHI base layers are decompressed for the load, but the config digest does not). The `org.opencontainers.image.source` label (set at build time) links the
   package to the repository. The job fails if the pushed index digest differs from the tar's. The summary lists
   the pushed index digest, the tested amd64 manifest digest and config digest from job 2 (match them against the index with
   `docker buildx imagetools inspect`) and the `docker pull` commands. The job has `packages: write` (all other jobs and the workflow
   default are `contents: read`) and logs in with the workflow `GITHUB_TOKEN`.

Pull the published image with `docker pull ghcr.io/evgeniypatlan/percona-distribution-postgresql:18-dhi`
(replace `evgeniypatlan` with your lowercased GitHub owner).
GHCR packages created under a personal account are private by default: make the package public in its package
settings, or `docker login ghcr.io` with a token that has `read:packages`. The multi-arch OCI tar from job 2 is
also kept as a workflow artifact for 7 days (comparison results for 14 days).

Secrets (repository secrets in the fork): `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`, used only to log in to
`dhi.io`; the baseline and tool images are pulled from Docker Hub anonymously. They are never used to log in to docker.io or to push. Jobs fail early with a clear message if they are not set. trivy and grype
versions are pinned in the workflow (`TRIVY_VERSION`, `GRYPE_VERSION`).

The `GHSA-6q48-6c7w-9gw2` certifi finding is ignored in the gate step only (section 5.4), so the gate passes on
this image; it exits 1 without the ignore file.

## 9. Reproduce

```bash
docker login dhi.io

# build
docker buildx build --load --build-context dhi-common=dhi-common \
    -t percona-distribution-postgresql:18-dhi percona-distribution-postgresql-18-dhi

# tests
bash percona-distribution-postgresql-18-dhi/tests/test-image.sh percona-distribution-postgresql:18-dhi
bash percona-distribution-postgresql-18-dhi/tests/test-entrypoint.sh percona-distribution-postgresql:18-dhi

# comparison (trivy, grype, syft, dockle, origin report)
docker pull percona/percona-distribution-postgresql:18.6.1-4
REQUIRED_PKGS_DHI="percona-postgresql-18 percona-patroni" bash dhi-common/compare.sh \
    percona/percona-distribution-postgresql:18.6.1-4 percona-distribution-postgresql:18-dhi /tmp/compare-out
cat /tmp/compare-out/summary.md

# base image attestations (reads DHI_RUNTIME and DHI_BUILDER from the Dockerfile)
bash dhi-common/verify-base.sh

# or one reference
bash dhi-common/verify-base.sh dhi.io/debian-base:trixie@sha256:c12f6059a81c93b872dfbc6042d8c045256db32b7e23ed5765a90b89726eac93

# CI-equivalent vulnerability gate (exit 0; without --ignorefile it exits 1 on certifi)
trivy image --severity CRITICAL --ignore-unfixed --exit-code 1 \
  --ignorefile percona-distribution-postgresql-18-dhi/.trivyignore percona-distribution-postgresql:18-dhi
```

`REQUIRED_PKGS_DHI` equals the script default and is shown only for explicitness.

## 10. Known limitations and next steps

- **emSign roots in the DHI base trust store.** The system bundle from the DHI base `ca-certificates` (148 roots)
  contains emSign Root CA - G1, emSign Root CA - C1 and emSign ECC Root CA - C3, which is what
  GHSA-6q48-6c7w-9gw2 is about. The CI gate ignores that advisory (section 5.4); the exposure is in the base image
  and is not removed by any certifi version. The `python3-certifi` 2025.1.31 package is still on the allowlist.
- **Arbitrary UID gives a raw error.** Starting under another uid without a writable PGDATA fails with a bare
  `chmod` error. The entrypoint should check writability up front and print what to mount or which uid to use.
- **Operator image deferred.** The operator postgres image on DHI (phase 2) is out of scope; nothing here
  covers `postgresql-containers/build/postgres`, its entrypoint, or the changes the operator would need
  (user, paths and PGDATA differ from today's).
- **curl dependency.** Removing `Depends: curl` from `percona-postgresql-18` would remove the curl binary and about
  19 of the 29 grype Criticals.
- **Non-DHI packages.** 22 allowlisted Debian packages; see section 6 for how to close the gap.
- **VEX not integrated.** The DHI OpenVEX statements need purl normalisation to be usable and cover base packages
  only.
- **Image signature not verified.** `verify-base.sh` verifies attestations; the cosign signature on the index is
  listed only. The Rekor transparency log is not checked.
- **Shell still present.** `sh` and `bash` remain; the entrypoint needs bash.
- **No HEALTHCHECK** (Dockle CIS-DI-0006), same as the baseline.
- **arm64 is not run or scanned.** The arm64 image is built in the same build and published in the same index, but
  only linux/amd64 is loaded, tested and scanned in CI.
- **Not measured:** a published-image SBOM/provenance, arm64 scan results, FIPS/STIG variants.
