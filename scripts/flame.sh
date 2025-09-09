#!/bin/bash

set -e

generate_flamegraph() {
  local kind=$1
  local block_num=$2

  local block_num_padded
  block_num_padded=$(printf "%08d" "$block_num")

  local test_name="${kind}_${block_num_padded}"
  local file_name="${kind}-${block_num_padded}"
  local folded_file="./integration/target/${file_name}.folded"
  local svg_file="flamegraphs/${file_name}.svg"

  echo "Running test: ${test_name}"
  RUST_LOG=debug cargo nextest run "${test_name}" --features tiny --release

  echo "Generating flamegraph: ${svg_file}"
  cat "${folded_file}" | inferno-flamegraph > "${svg_file}"

  echo "Done: ${svg_file}"
}

mkdir -p flamegraphs

# Batch run
if [[ "$1" == "--all" || "$1" == "-a" ]]; then
  echo "Batch generation for all test cases"
  test_kinds=("fallback" "safrole" "storage" "preimages")

  for kind in "${test_kinds[@]}"; do
    for i in $(seq 1 100); do
      generate_flamegraph "$kind" "$i"
    done
  done
  echo "All flamegraphs generated successfully"
  exit 0
fi

# Single test case
generate_flamegraph "$1" "$2"
