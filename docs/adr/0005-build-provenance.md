# 0005. Build provenance

Status: accepted

## Context

A verdict is only as trustworthy as the code that produced it. The attestation of the confidential container (decision 0004) names the image set that ran. A reader still needs to know which repository, which workflow and which commit built those images, and to check that without trusting us.

GitHub artifact attestations sign a SLSA build provenance statement with a short-lived Sigstore certificate that carries the repository, the git ref, the commit and the signing workflow. They are free for public repositories, the signature is verifiable with the `gh` CLI, and the bundle can be stored next to the image in the registry.

## Decision

Keep GitHub artifact attestations as the build provenance mechanism.

- A manually triggered workflow builds the image with Buildx, pushes it to the GitHub Container Registry and attests it with `actions/attest`, using only the permissions the documentation lists. Every action is pinned to a commit.
- `tools/provenance/verify.py` wraps `gh attestation verify --format json` and returns the certificate fields that matter: `sourceRepositoryURI`, `sourceRepositoryRef`, `buildSignerURI`, the subject digest and `sourceRepositoryIdentifier`. Callers pin the signer workflow with `--signer-workflow`.
- Container images are verified online. `gh attestation verify oci://...` resolves the image digest from the registry, so it cannot run without network access even when given a bundle and a trusted root. Files are verified fully offline: download the bundle and the trusted root while online, then pass `--bundle` and `--custom-trusted-root`.
- The repository ID in the certificate is compared with the ID of the expected repository. A repository keeps its ID when renamed, and a new repository that takes the old name gets a different one.

Fallback if attestations stop being free or verifiable: keyless signing with cosign and the same Sigstore trust root.

## Measurements

| Measurement | Value | Unit | Command | Date |
| --- | --- | --- | --- | --- |
| Job wall-clock with attestation (median of 3) | 35 | s | `gh run view <id> --json jobs` | 2026-10-22 |
| Job wall-clock without attestation (median of 3) | 20 | s | `gh run view <id> --json jobs` | 2026-10-22 |
| Attestation steps, image and file (median of 3 runs) | 12 | s | `gh run view <id> --json jobs` | 2026-10-22 |
| Attestations returned for one image | 1 | attestations | `gh attestation verify oci://<image> --format json` | 2026-10-22 |
| Bundle file for the demo file, 3 attested runs | 33623 | bytes | `gh attestation download <file> -R <repo>` | 2026-10-22 |
| Trusted root file | 34634 | bytes | `gh attestation trusted-root` | 2026-10-22 |
| Offline verification with the network blocked (5 runs) | 0.02 | s | `gh attestation verify <file> --bundle <b> --custom-trusted-root <r>` | 2026-10-22 |
| Online verification of an image (median of 3) | 5.7 | s | `gh attestation verify oci://<image>` | 2026-10-22 |
| sourceRepositoryURI | https://github.com/DavidZapataOh/the-fourth-official | URI | `gh attestation verify oci://<image> --format json` | 2026-10-22 |
| sourceRepositoryRef | refs/heads/main | git ref | `gh attestation verify oci://<image> --format json` | 2026-10-22 |
| buildSignerURI | https://github.com/DavidZapataOh/the-fourth-official/.github/workflows/provenance.yml@refs/heads/main | URI | `gh attestation verify oci://<image> --format json` | 2026-10-22 |
| Negative cases rejected | 4 of 4 | cases | `FOURTH_LIVE=1 uv run pytest tools/provenance` | 2026-10-22 |

The negative cases are an image digest without an attestation, another repository, a bundle with one altered byte and a different signer workflow.

Decision: keep GitHub artifact attestations for build provenance.

## Consequences

- The repository must stay public for attestations to be free and for the registry package to be readable without login.
- Images are referenced by digest everywhere, so a digest identifies exactly one build.
- The attestation step adds about 12 seconds to a build.
- The trusted root is the only online dependency of offline verification and should be refreshed whenever new signed material is imported. Anything signed before the file was generated keeps verifying.
- A verifier that must work in a browser needs its own Sigstore bundle verification; the CLI covers command-line and CI use.
