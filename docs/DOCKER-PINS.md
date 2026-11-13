# App image pins (maintenance rule)

The app `Dockerfile` pins every external image by tag AND multi-arch index digest, like
`docker/unbound/Dockerfile` (see docs/UNBOUND.md). The image is built for linux/amd64 and
linux/arm64; the index digest resolves to the right platform manifest on each.

| Reference | Index digest | Read on |
|---|---|---|
| `docker/dockerfile:1` (syntax frontend) | `sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e` | 2026-11-13 |
| `python:3.12-slim-trixie` | `sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b` | 2026-11-13 |
| `ghcr.io/astral-sh/uv:0.13.7` | `sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490` | 2026-11-13 |

## Maintenance rule
1. Update deliberately, not automatically. Get the digest with
   `docker buildx imagetools inspect <image:tag>` and take the top-level `Digest:` line whose
   `MediaType` is `application/vnd.oci.image.index.v1+json` (not a `Platform:` manifest digest).
2. Change the Dockerfile, rebuild (`docker build .`), run the tests, and commit the new digest
   together with the date in this table and in the Dockerfile comments.
3. The frontend is pinned too: a moving `:1` would let a replaced tag change how the file is parsed.
4. `.github/workflows/rebuild.yml` rebuilds the app image with `--no-cache` every Monday
   04:17 UTC (build check only, nothing pushed). A red run means: investigate before release.
5. `tests/test_dockerfile_pins.py` fails if any `FROM` or `COPY --from` image loses its digest.
6. Python patch version: the image's Python comes from the pinned base; the CI test interpreter
   comes from `.python-version` via `setup-uv`, so they can differ in patch level.

## postgres (compose.yaml)
`postgres:17` is left as is: it follows the 17 minor/security releases on purpose for the dev
and self-host database, and pinning a digest would freeze them without a refresh process.
Pin it (same rule) only if reproducible database images become a requirement.
