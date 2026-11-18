# Releasing FastRoll

Pushing to the `release` branch publishes a release through [release.yml](.github/workflows/release.yml).
[CHANGELOG.md](CHANGELOG.md) records the changes of each version and the versioning rules.

## Publish a release

1. Commit the release changes to `main`:

   | File | Change |
   |---|---|
   | `Cargo.toml` | Set `version` of `[workspace.package]`. |
   | `Cargo.lock` | Run `cargo update --workspace`. The image build fails on a stale lockfile. |
   | `common/src/versions.rs` | Set `SPEC_VERSION` to the supported Graypaper version. |
   | `CHANGELOG.md` | Move the `[Unreleased]` changes under `## [<version>] - <YYYY-MM-DD>`, add a `Graypaper: <spec-version>` line, and update the compare links. |

2. Check the release notes:

   ```bash
   ./scripts/extract-release-notes.sh <version> <spec-version>
   ```

3. After CI passes on `main`, fast-forward `release`:

   ```bash
   git push origin main:release
   ```

## Release workflow

The workflow runs these steps:

1. Stops if the `v<version>` tag exists, or if `CHANGELOG.md` has no entry for the version and `SPEC_VERSION`.
2. Publishes the `ghcr.io/fastroll-jam/fastroll:<version>` and `latest` images.
3. Creates the `v<version>` tag and a GitHub release with the `CHANGELOG.md` entry as its notes.

`release` cannot be force-pushed, so fix a failed release on `main` and fast-forward again. Manual workflow runs only
take effect on the `release` branch.
