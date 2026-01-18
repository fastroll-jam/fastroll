# FastRoll: JAM validator client

[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![CI](https://github.com/fastroll-jam/fastroll/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![codecov](https://codecov.io/github/fastroll-jam/fastroll/graph/badge.svg?token=52L9F3PBY2)](https://codecov.io/github/fastroll-jam/fastroll)

## About FastRoll

FastRoll is a Rust implementation of the JAM (Join-Accumulate Machine) validator client.

The primary goal is strict conformance with the [Graypaper](https://github.com/gavofyork/graypaper) formal
specification ([supported version](./common/src/versions.rs)).

## Status

- Successfully imports blocks and yields valid post-states as specified in Graypaper.
- Passes all public test vectors and available block fuzz traces. See below for details.
- Ready for [JAM prize](https://jam.web3.foundation/) Milestone #1 evaluation:
    - [Milestone #1 delivery](https://github.com/w3f/jam-milestone-delivery/pull/30)
    - [Conformance testing](https://github.com/davxy/jam-conformance/issues/45)
- Block authoring, auditing, and networking are in progress.

## Supported Chain Specs

- [Tiny](https://docs.jamcha.in/basics/chain-spec/tiny) / [Full](https://docs.jamcha.in/basics/chain-spec/full)

## Build and Run

Currently, the FastRoll binary focuses exclusively on fuzz-target functionality as specified in
the [fuzz protocol](https://github.com/davxy/jam-conformance/tree/f2da851a65707576e8ec9ef865564cee215fcba3/fuzz-proto).

The JAM node runner is under active development and currently requires dev accounts to run.

### Prerequisites

- Rust toolchain (stable, edition 2021)
- Git submodules for test vectors (see below)

### Rust features

- `tiny` feature selects `tiny` chain-spec parameters for conformance testing.
- `fuzz` feature skips timeslot index validation against wall clock time for fuzzing.

### Build the CLI

```bash
cargo build --features "tiny,fuzz"
```

### Run the CLI (fuzz target)

```bash
cargo run --features "tiny,fuzz" -- fuzz --socket "/tmp/jam_target.sock"
```

### Defaults

- RocksDB path: `./.rocksdb`
- Fuzzer socket: `/tmp/jam_target.sock`

## Conformance Testing

### Test vector submodules

FastRoll relies on external test-vector repos as Git submodules:

- [integration/jamtestvectors](integration/jamtestvectors) (official W3F test vectors)
- [integration/jamtestvectors-polkajam](integration/jamtestvectors-polkajam) (test vectors release candidate)
- [integration/jamtestvectors-pvm](integration/jamtestvectors-pvm) (PVM/RISC-V test vectors)
- [integration/jam-conformance](integration/jam-conformance) (fuzzing traces)

Initialize them with:

```bash
git submodule update --init --recursive
```

### State Transition Function (STF) tests

- Vectors: [integration/jamtestvectors-polkajam/stf](integration/jamtestvectors-polkajam/stf)
- Harness: [test-utils/src/stf_harness.rs](test-utils/src/stf_harness.rs)
- Test Cases: [integration/tests/stf](integration/tests/stf)

### PVM/RISC-V tests

- Vectors: [integration/jamtestvectors-pvm/pvm/programs](integration/jamtestvectors-pvm/pvm/programs)
- Harness: [test-utils/src/pvm_harness.rs](test-utils/src/pvm_harness.rs)
- Build Script: [integration/build.rs](integration/build.rs)
- Test Cases: [integration/tests/pvm.rs](integration/tests/pvm.rs)

### Block import tests

- Vectors: [integration/jamtestvectors-polkajam/traces](integration/jamtestvectors-polkajam/traces)
- Harness: [test-utils/src/importer_harness.rs](test-utils/src/importer_harness.rs)
- Build Script: [integration/build.rs](integration/build.rs)
- Test Cases: [integration/tests/block_importer.rs](integration/tests/block_importer.rs)

### Block import tests (simple forks)

- Vectors:
    - [integration/jamtestvectors-polkajam/traces](integration/jamtestvectors-polkajam/traces) (fuzzy blocks)
    - [integration/jam-conformance/fuzz-reports/0.7.2/traces](integration/jam-conformance/fuzz-reports/0.7.2/traces)
      (fuzzing traces)
- Harness: [fuzz/src/fuzzer.rs](fuzz/src/fuzzer.rs)
- Build Script: [integration/build.rs](integration/build.rs)
- Test Cases: [integration/tests/block_importer.rs](integration/tests/block_importer.rs)

### Running tests

- `fuzz` feature is required for fuzzing trace block imports.

Run all tests:

```bash
cargo nextest run --workspace --no-fail-fast --features "tiny,fuzz" --release
```

Run all block import tests:

```bash
cargo nextest run block_import_ --no-fail-fast --features "tiny,fuzz" --release
```

Run block import tests for a specific group:

```bash
cargo nextest run block_import_storage_ --no-fail-fast --features "tiny,fuzz" --release
```

- Available groups:
    - [fallback](integration/jamtestvectors-polkajam/traces/fallback)
    - [safrole](integration/jamtestvectors-polkajam/traces/safrole)
    - [storage](integration/jamtestvectors-polkajam/traces/storage)
    - [storage_light](integration/jamtestvectors-polkajam/traces/storage_light)
    - [preimages](integration/jamtestvectors-polkajam/traces/preimages)
    - [preimages_light](integration/jamtestvectors-polkajam/traces/preimages_light)
    - [fuzzy](integration/jamtestvectors-polkajam/traces/fuzzy)
    - [fuzzy_light](integration/jamtestvectors-polkajam/traces/fuzzy_light)

Run block import tests for fuzzing traces:

```bash
cargo nextest run block_import_conformance_ --no-fail-fast --features "tiny,fuzz" --release
```

## Repository Map

Top-level directories and their roles:

- `block/`: Block common types and stores.
- `cli/`: `fastroll` CLI binary.
- `clock/`: Time provider and clock utilities.
- `codec/`: JAM codec (`fr-codec`) and derive macro (`fr-codec-derive`).
- `common/`: Shared types, constants, logging, utilities.
    - `erasure-coding/`: Reed-solomon erasure codec for data availability.
    - `limited-vec/`: Bounded vector types.
- `config/`: Configuration and defaults.
- `crypto/`: Hashing, signatures, VRF, and signing key utilities.
- `db/`: RocksDB-backed storage primitives.
- `extrinsics/`: Extrinsic types and validation.
- `fuzz/`: Fuzz harness and integration with the block importer.
- `integration/`: Integration test crate and test-vector submodules.
- `merkle/`: Common Merkle-related utilities.
- `network/`: QUIC-based networking stack.
- `node/`: Node runtime, block importer, and service wiring.
- `node-bench/`: Criterion benchmarks.
- `pvm/`: PVM sub-crates:
    - `pvm-core`: VM execution primitives; architectural state, interpreter, program loader, instructions.
    - `pvm-host`: Host functions, partial state.
    - `pvm-interface`: Host/guest interface types.
    - `pvm-invocation`: PVM invocation entry-points (is_authorized, refine, accumulate).
    - `pvm-types`: Common PVM data types.
- `scripts/`: Utility scripts (e.g., flamegraph generation).
- `state/`: Global state types, stores, state cache, manager, and merkle interfaces.
    - `state-merkle-v2/`: Current merkle trie and store implementation.
    - `state-merkle/`: Deprecated merkle trie (kept for reference).
- `storage/`: Node storage layer wiring different store types: state, merkle, header, extrinsics, etc.
- `test-utils/`: Test harnesses and helpers.
    - `asn-types/`: Type conversion between Rust and ASN types for test vectors (JSON support)
- `transition/`: State transition functions (STFs) and state prediction helpers.

## Team Account IDs

- `Polkadot`: 134xm7pSX5oWibyckm4a2FXFqPumE1kfwxZNVLTHN28RQVTP
- `Kusama`: HHwToJztPUFMp2qVerfbizz7wYSzu3q5HmSiCaq3AewmgUf

## License

Apache-2.0. See [LICENSE](LICENSE).
