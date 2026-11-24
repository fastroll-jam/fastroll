# Changelog

Notable changes to FastRoll, per release. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Starting from 0.2.0, versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) as below.

| Version part | Raised for | Example |
|---|---|---|
| `MAJOR` | Support for version 1.0 of the JAM protocol | 1.0.0 |
| `MINOR` | A newly supported Graypaper version or a major capability | 0.2.0 |
| `PATCH` | Fixes and performance work on the same Graypaper version | 0.2.1 |

- Each release names its supported Graypaper version, the `SPEC_VERSION` of `common/src/versions.rs`.
- Versions have no pre-release suffix, because the fuzzer protocol carries a client version as three octets.
- Releases up to 0.1.37 were published as binaries in [fastroll-releases](https://github.com/fastroll-jam/fastroll-releases), and their entries come from those release notes.

## [Unreleased]

### Changed

- [GP v0.8.0] Make validator sets variable-length, and scale reports, assurances, statistics and ticket entries with the set size ([`2e83e362`](https://github.com/fastroll-jam/fastroll/commit/2e83e362), [`0670821b`](https://github.com/fastroll-jam/fastroll/commit/0670821b), [`c4d57fd9`](https://github.com/fastroll-jam/fastroll/commit/c4d57fd9))
- [GP v0.8.0] Derive the erasure coding rate from the validator count, and add erasure shards to the availability spec ([`9c0efea5`](https://github.com/fastroll-jam/fastroll/commit/9c0efea5), [`af16de0a`](https://github.com/fastroll-jam/fastroll/commit/af16de0a))
- [GP v0.8.0] Encode ticket attempts in one octet ([`fee0d558`](https://github.com/fastroll-jam/fastroll/commit/fee0d558))
- [GP v0.8.0] Commit to preimage hashes in the extrinsic hash ([`f786d235`](https://github.com/fastroll-jam/fastroll/commit/f786d235))
- [GP v0.8.0] Apply the disputes extrinsic limits ([`fc837f62`](https://github.com/fastroll-jam/fastroll/commit/fc837f62))
- [GP v0.8.0] Add the lookup-anchor post state root and anchor slot to the refinement context ([`ec14db04`](https://github.com/fastroll-jam/fastroll/commit/ec14db04))
- [GP v0.8.0] Keep full guarantees in availability assignments ([`8e30ace2`](https://github.com/fastroll-jam/fastroll/commit/8e30ace2))
- [GP v0.8.0] Count processed transfers in service statistics ([`09a41740`](https://github.com/fastroll-jam/fastroll/commit/09a41740))
- [GP v0.8.0] Reserve transfer and always-accumulate gas in outer accumulation ([`713503ad`](https://github.com/fastroll-jam/fastroll/commit/713503ad))
- [GP v0.8.0] Restrict `bless` to the manager, and merge assigners per core with `R` ([`83fa089b`](https://github.com/fastroll-jam/fastroll/commit/83fa089b), [`f6947533`](https://github.com/fastroll-jam/fastroll/commit/f6947533))
- [GP v0.8.0] Return `HUH` for preimage sizes of `2^32` or more ([`34869a40`](https://github.com/fastroll-jam/fastroll/commit/34869a40))
- [GP v0.8.0] Limit `machine` to 63 inner VMs ([`86cb168b`](https://github.com/fastroll-jam/fastroll/commit/86cb168b))
- [GP v0.8.0] Read `z` validator keys in `designate`, and drop the removed `fetch` constants ([`e5e90b9b`](https://github.com/fastroll-jam/fastroll/commit/e5e90b9b))
- [GP v0.8.0] Remove the `sbrk` instruction
- [GP v0.8.0] Renumber the PVM opcodes and add `unlikely`
- [GP v0.8.0] Validate program blobs in `deblob` by `v_blob` and zero padding bits of `k`, and return `HUH` from `machine` for an initial pc that is not an instruction
- [GP v0.8.0] Panic on a branch unless both its target and its next instruction start basic blocks, and make `fallthrough` a static jump
- [GP v0.8.0] Add the gas cost model, which simulates each basic block once when a program loads
- [GP v0.8.0] Charge gas per basic block with a gas-charged flag instead of per instruction
- [GP v0.8.1] Bound work reports by the work-package limits ([gavofyork/graypaper#563](https://github.com/gavofyork/graypaper/pull/563))
- [GP v0.8.1] Let privilege holders hand over their role via `bless` ([gavofyork/graypaper#558](https://github.com/gavofyork/graypaper/pull/558), [#375](https://github.com/fastroll-jam/fastroll/pull/375))
- [GP v0.8.1] Limit the instruction data size and jump table entries in `deblob` ([gavofyork/graypaper#559](https://github.com/gavofyork/graypaper/pull/559))
- [GP v0.8.1] Count the destination of `cmov` as a source register in the gas cost model ([gavofyork/graypaper#559](https://github.com/gavofyork/graypaper/pull/559))
- [GP v0.8.1] Clear the gas-charged flag when `Ψ` halts or panics ([gavofyork/graypaper#588](https://github.com/gavofyork/graypaper/pull/588))
- [GP v0.8.1] Mask the third register of three-register instructions to 4 bits ([gavofyork/graypaper#554](https://github.com/gavofyork/graypaper/pull/554))
- Saturate balances at `2^64-1` on incoming deferred transfers, a rule of the Graypaper 0.8.0 fuzz campaign that no Graypaper version defines ([jam-conformance/jam-fuzzing#212](https://github.com/jam-conformance/jam-fuzzing/pull/212))

### Fixed

- Return 0 as the instruction counter when `Ψ` halts or panics, and keep it on a page fault
- Report the page address of a page fault on a memory read, not the faulting address
- Mark the block after a terminating instruction at index 0 as a basic block start, and never the end of the code
- Decode instruction arguments from `ζ`, which reads past the next opcode, instead of crashing on an instruction shorter than its arguments
- Check jump and branch targets in full 64 bits against the basic block starts, not only their low 32 bits
- Take the host-call id from the full `ecalli` immediate, not its low 8 bits, so an unknown id is not run as another host call and `invoke` reports it unchanged
- Encode the always-accumulate services of `χ` as fixed-length `E_4(s) ⌢ E_8(g)` pairs, as every number in the state is fixed-length
- Give no output instead of rejecting the block when `Ψ_M` halts with an output address of `2^32` or more
- Replace an account ejected in an earlier accumulation round when the registrar creates its id again, instead of rejecting the block
- Panic in `Ψ_M` instead of rejecting the block when the program fails to load ([#374](https://github.com/fastroll-jam/fastroll/pull/374))
- Check culprits and faults against the posterior good and bad sets ([`f3ed7039`](https://github.com/fastroll-jam/fastroll/commit/f3ed7039))
- Remove duplicate offender keys from `ψ'_O` ([`e255e745`](https://github.com/fastroll-jam/fastroll/commit/e255e745))
- Reject work reports without digests ([`0ea4f292`](https://github.com/fastroll-jam/fastroll/commit/0ea4f292))
- Reuse the smallest free inner VM id in `machine` ([`dd0211bd`](https://github.com/fastroll-jam/fastroll/commit/dd0211bd))
- Reject an out-of-range author index in validator statistics instead of panicking ([`2916e53f`](https://github.com/fastroll-jam/fastroll/commit/2916e53f))
- Fix swapped errors in `add_account_balance` ([`5c430173`](https://github.com/fastroll-jam/fastroll/commit/5c430173))
- Keep a dirty state cache entry when a parallel read loads the same key from the DB, which lost `κ'` and rejected epoch-change blocks right after `Initialize`

## [0.1.38] - 2026-05-21

Graypaper: 0.7.2

### Added

- Publish the `tiny` and `full` fuzz targets as a Docker image at `ghcr.io/fastroll-jam/fastroll` ([#373](https://github.com/fastroll-jam/fastroll/pull/373))

### Removed

- Binary release assets, replaced by the Docker image ([#373](https://github.com/fastroll-jam/fastroll/pull/373))

### Fixed

- Close the fuzzing session when a second `Initialize` message arrives ([#373](https://github.com/fastroll-jam/fastroll/pull/373))

## [0.1.37] - 2026-02-18

Graypaper: 0.7.2

### Changed

- Revert the `TicketsXtEntry` codec fix of 0.1.36

## [0.1.36] - 2026-02-18

Graypaper: 0.7.2

### Fixed

- `TicketsXtEntry` codec

## [0.1.35] - 2026-02-07

Graypaper: 0.7.2

### Changed

- Improve runtime panic recovery for fuzzing sessions

## [0.1.34] - 2026-02-05

Graypaper: 0.7.2

### Fixed

- Accumulation partial state merge

## [0.1.33] - 2026-02-04

Graypaper: 0.7.2

### Fixed

- PVM host functions and the accumulation pipeline

## [0.1.32] - 2026-01-28

Graypaper: 0.7.2

### Changed

- Optimize PVM performance

### Fixed

- `GetState` fuzz message

## [0.1.31] - 2026-01-22

Graypaper: 0.7.2

### Changed

- Optimize PVM performance

## [0.1.30] - 2026-01-20

Graypaper: 0.7.2

### Changed

- Optimize PVM performance

## [0.1.29] - 2026-01-14

Graypaper: 0.7.2

### Fixed

- Ring cache context handling for simple forks (follow-up of 0.1.28)

## [0.1.28] - 2026-01-12

Graypaper: 0.7.2

### Fixed

- Ring cache context handling for simple forks

## [0.1.27] - 2026-01-12

Graypaper: 0.7.2

### Fixed

- `BLESS` and `TRANSFER` host calls
- Fuzz target ancestors handling

## [0.1.26] - 2025-12-24

Graypaper: 0.7.2

### Changed

- Enhance fuzz target reinitialization

### Fixed

- Some STF logic

## [0.1.25] - 2025-12-18

Graypaper: 0.7.2

### Changed

- Sync with Graypaper 0.7.2

## [0.1.24] - 2025-11-24

Graypaper: 0.7.1

### Fixed

- Parallel accumulation result merging

## [0.1.23] - 2025-11-13

Graypaper: 0.7.1

### Changed

- Use a ZIP-215 compatible Ed25519 crate

## [0.1.22] - 2025-11-10

Graypaper: 0.7.1

### Changed

- Optimize performance
- Reduce build size

## [0.1.21] - 2025-11-09

Graypaper: 0.7.1

### Changed

- Optimize PVM performance

### Fixed

- Codec
- Accumulation pipeline

## [0.1.20] - 2025-11-01

Graypaper: 0.7.1

### Fixed

- Some host functions

## [0.1.19] - 2025-10-28

Graypaper: 0.7.1

### Fixed

- DB lifetime issue

## [0.1.18] - 2025-10-27

Graypaper: 0.7.1

### Fixed

- Remove potential runtime panics

## [0.1.17] - 2025-10-13

Graypaper: 0.7.1

### Fixed

- Accumulation pipeline

## [0.1.16] - 2025-10-13

Graypaper: 0.7.1

### Changed

- Optimize Safrole performance

## [0.1.15] - 2025-10-10

Graypaper: 0.7.1

### Added

- Simple forking feature of fuzz protocol v1

## [0.1.14] - 2025-10-08

Graypaper: 0.7.1

### Changed

- Sync to Graypaper 0.7.1

## [0.1.13] - 2025-10-02

Graypaper: 0.7.0

### Changed

- Re-implement state merklization (StateMerkle V2)

## [0.1.12] - 2025-09-20

Graypaper: 0.7.0

### Fixed

- PVM instruction gas charge

## [0.1.11] - 2025-09-17

Graypaper: 0.7.0

### Changed

- Improve PVM memory access checks

## [0.1.10] - 2025-09-17

Graypaper: 0.7.0

### Changed

- Improve STF error handling

## [0.1.9] - 2025-09-17

Graypaper: 0.7.0

### Added

- Fuzzer V1 with the ancestors feature

## [0.1.8] - 2025-09-12

Graypaper: 0.7.0

### Changed

- Improve PVM host function error handling

## [0.1.7] - 2025-09-10

Graypaper: 0.7.0

### Changed

- Catch up on missed Graypaper updates

## [0.1.6] - 2025-09-08

Graypaper: 0.7.0

### Changed

- Improve PVM performance

## [0.1.5] - 2025-09-08

Graypaper: 0.7.0

### Added

- `fuzz` feature that skips timeslot validation while fuzzing

## [0.1.4] - 2025-09-04

Graypaper: 0.7.0

### Changed

- Improve Safrole performance

## [0.1.3] - 2025-09-04

Graypaper: 0.7.0

### Changed

- Enhance error handling for crypto modules
- Reorder block importer STFs and header validations

## [0.1.2] - 2025-09-01

Graypaper: 0.7.0

### Fixed

- `EJECT` host call to properly handle preimage deletion

## 0.1.1 - 2025-08-31

Graypaper: 0.7.0

No release notes were published for this version, and no tag in this repository matches its binaries.

## [0.1.0] - 2025-08-31

Graypaper: 0.7.0

### Added

- First public binary release of the fuzz target

[Unreleased]: https://github.com/fastroll-jam/fastroll/compare/38e0ef25...HEAD
[0.1.38]: https://github.com/fastroll-jam/fastroll/compare/v2026.02.18-4a487fb...38e0ef25
[0.1.37]: https://github.com/fastroll-jam/fastroll/compare/v2026.02.17-d25878a...v2026.02.18-4a487fb
[0.1.36]: https://github.com/fastroll-jam/fastroll/compare/v2026.02.07-80a8120...v2026.02.17-d25878a
[0.1.35]: https://github.com/fastroll-jam/fastroll/compare/v2026.02.05-2f11bac...v2026.02.07-80a8120
[0.1.34]: https://github.com/fastroll-jam/fastroll/compare/v2026.02.04-a08e377...v2026.02.05-2f11bac
[0.1.33]: https://github.com/fastroll-jam/fastroll/compare/v2026.01.28-090b180...v2026.02.04-a08e377
[0.1.32]: https://github.com/fastroll-jam/fastroll/compare/v2026.01.22-f445b52...v2026.01.28-090b180
[0.1.31]: https://github.com/fastroll-jam/fastroll/compare/v2026.01.20-e00a0eb...v2026.01.22-f445b52
[0.1.30]: https://github.com/fastroll-jam/fastroll/compare/v2026.01.14-ad2466a...v2026.01.20-e00a0eb
[0.1.29]: https://github.com/fastroll-jam/fastroll/compare/v2026.01.12-80ce457...v2026.01.14-ad2466a
[0.1.28]: https://github.com/fastroll-jam/fastroll/compare/v2026.01.12-4c61d73...v2026.01.12-80ce457
[0.1.27]: https://github.com/fastroll-jam/fastroll/compare/v2025.12.24-9e3907a...v2026.01.12-4c61d73
[0.1.26]: https://github.com/fastroll-jam/fastroll/compare/v2025.12.18-73b92b7...v2025.12.24-9e3907a
[0.1.25]: https://github.com/fastroll-jam/fastroll/compare/v2025.11.24-b0bd68c...v2025.12.18-73b92b7
[0.1.24]: https://github.com/fastroll-jam/fastroll/compare/v2025.11.13-77c228e...v2025.11.24-b0bd68c
[0.1.23]: https://github.com/fastroll-jam/fastroll/compare/v2025.11.10-9492bd2...v2025.11.13-77c228e
[0.1.22]: https://github.com/fastroll-jam/fastroll/compare/v2025.11.09-8907ff5...v2025.11.10-9492bd2
[0.1.21]: https://github.com/fastroll-jam/fastroll/compare/v2025.11.01-5c71405...v2025.11.09-8907ff5
[0.1.20]: https://github.com/fastroll-jam/fastroll/compare/v2025.10.28-bad1d9e...v2025.11.01-5c71405
[0.1.19]: https://github.com/fastroll-jam/fastroll/compare/v2025.10.27-7ba1f76...v2025.10.28-bad1d9e
[0.1.18]: https://github.com/fastroll-jam/fastroll/compare/v2025.10.13-6ab3889...v2025.10.27-7ba1f76
[0.1.17]: https://github.com/fastroll-jam/fastroll/compare/v2025.10.11-40b49a7...v2025.10.13-6ab3889
[0.1.16]: https://github.com/fastroll-jam/fastroll/compare/v2025.10.10-fe162d8...v2025.10.11-40b49a7
[0.1.15]: https://github.com/fastroll-jam/fastroll/compare/v2025.10.08-21ce8ac...v2025.10.10-fe162d8
[0.1.14]: https://github.com/fastroll-jam/fastroll/compare/v2025.10.02-344948a...v2025.10.08-21ce8ac
[0.1.13]: https://github.com/fastroll-jam/fastroll/compare/v2025.09.19-9fb00c8...v2025.10.02-344948a
[0.1.12]: https://github.com/fastroll-jam/fastroll/compare/v2025.09.17-2e42ae7...v2025.09.19-9fb00c8
[0.1.11]: https://github.com/fastroll-jam/fastroll/compare/v2025.09.17-423e6d2...v2025.09.17-2e42ae7
[0.1.10]: https://github.com/fastroll-jam/fastroll/compare/v2025.09.17-058e962...v2025.09.17-423e6d2
[0.1.9]: https://github.com/fastroll-jam/fastroll/compare/v2025.09.12-d4be782...v2025.09.17-058e962
[0.1.8]: https://github.com/fastroll-jam/fastroll/compare/v2025.09.10-d264d2f...v2025.09.12-d4be782
[0.1.7]: https://github.com/fastroll-jam/fastroll/compare/v2025.09.08-e1bc1b0...v2025.09.10-d264d2f
[0.1.6]: https://github.com/fastroll-jam/fastroll/compare/v2025.09.08-a3d73b6...v2025.09.08-e1bc1b0
[0.1.5]: https://github.com/fastroll-jam/fastroll/compare/v2025.09.04-3393cef...v2025.09.08-a3d73b6
[0.1.4]: https://github.com/fastroll-jam/fastroll/compare/v2025.09.04-dc0da93...v2025.09.04-3393cef
[0.1.3]: https://github.com/fastroll-jam/fastroll/compare/v2025.09.01-83b9ec0...v2025.09.04-dc0da93
[0.1.2]: https://github.com/fastroll-jam/fastroll/compare/v2025.08.31-96d4ea5...v2025.09.01-83b9ec0
[0.1.0]: https://github.com/fastroll-jam/fastroll/releases/tag/v2025.08.31-96d4ea5
