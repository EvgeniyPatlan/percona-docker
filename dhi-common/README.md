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

## Package source policy

Every package added to the runtime image must come from:

- `dhi.io` (Docker Hardened Images Debian packages), or
- `repo.percona.com`, or
- `deb.debian.org`, **only** if the package name is listed in the image's allowlist.

Anything else fails the build with `POLICY VIOLATION: <package> from <source>`. The origin of each installed
package is written to a TSV report (`package`, `version`, `origin`), by default
`/usr/share/percona/package-origins.tsv` in the image.

Maintainer scripts are not run. Images must create users, directories and symlinks they need explicitly.

## Tests

```bash
docker login dhi.io
bash dhi-common/tests/test-build-rootfs.sh
```
