# DHI common build tooling

Shared helpers for PostgreSQL images built on [Docker Hardened Images](https://docs.docker.com/dhi/)
(`dhi.io/debian-base:trixie`). They are used from a `dhi.io/debian-base:trixie-dev` builder stage via a
buildx named context:

```bash
docker buildx build --build-context dhi-common=dhi-common ...
```

| File | Purpose |
|---|---|
| `setup-apt.sh` | Adds the Percona repository (key verified by fingerprint) and the source-priority policy. Env: `PPG_REPO_NAME` (default `ppg-18`), `PPG_REPO` (`release`/`testing`/`experimental`), `SUITE` (default `trixie`). |
| `apt-preferences` | Prefers `dhi.io` and `repo.percona.com` (priority 900) over `deb.debian.org` (100). |
| `build-rootfs.sh` | Resolves packages against the runtime rootfs' dpkg database, enforces the source policy, extracts the `.deb` files into the rootfs and records them in `/var/lib/dpkg/status` and `/var/lib/dpkg/info/*.list` so vulnerability scanners can see them. Removes docs/man pages, package-manager binaries and setuid/setgid bits. |
| `compare.sh` | `compare.sh <baseline-image> <dhi-image> <outdir>` writes `trivy-*.json`, `grype-*.json`, `sbom-*.spdx.json`, `sbom-*.cdx.json`, `dockle-*.json`, `origins-dhi.tsv` and `summary.md` (size, package count, CVEs by severity from trivy and grype, hardening properties, read-only run, Dockle/CIS-DI findings, and grype CVEs split by package origin using the image's origin report). trivy and grype run from the host; syft and dockle run from pinned container images (`SYFT_IMAGE`, `DOCKLE_IMAGE`) with the docker socket. |
| `verify-base.sh` | `verify-base.sh [image@sha256:...]...` lists the attestations (SBOM, provenance, VEX, ...) attached to the pinned DHI base digests (default: `DHI_RUNTIME`/`DHI_BUILDER` from the PG18 Dockerfile) and verifies each with cosign against Docker's DHI public key (`COSIGN_IMAGE`, `DHI_PUBKEY_URL`). Exit codes: 0 all attestations verified, 1 a verification failed, 2 usage or environment error (missing tool, no docker login, unreadable image, bad key), 3 no attestations found so nothing was verified. Requires `docker login dhi.io`. The cosign signature artifact attached to the index is listed as present only. |

## Package source policy

Every package added to the runtime image must come from:

- `dhi.io` (Docker Hardened Images Debian packages), or
- `repo.percona.com`, or
- `deb.debian.org`, **only** if the package is listed in the image's allowlist. Allowlist lines are
  `<package> [<version>]`; when a version is given, the resolved version must match it, ignoring the
  architecture-specific binNMU suffix (`+bN`).

Anything else fails the build with `POLICY VIOLATION: <package> from <source>`. The origin of each installed
package is written to a TSV report (`package`, `version`, `origin`), by default
`/usr/share/percona/package-origins.tsv` in the image.

Maintainer scripts are not run. Images must create users, directories and symlinks they need explicitly.

## Tests

```bash
docker login dhi.io
bash dhi-common/tests/test-build-rootfs.sh
bash dhi-common/tests/test-compare.sh [baseline-image] [dhi-image] [outdir]   # runs scanners, takes minutes
```
