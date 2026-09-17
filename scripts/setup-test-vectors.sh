#!/usr/bin/env bash

set -euo pipefail

readonly VECTOR_SUBMODULES=(
  "integration/jamtestvectors-polkajam"
  "integration/jamtestvectors-pvm"
  "integration/jam-conformance"
)

force_reset=false
verify_only=false

usage() {
  cat <<'EOF'
Usage: ./scripts/setup-test-vectors.sh [--force] [--verify]

Fetch FastRoll's pinned test vectors, downloading only the files required by the test suite.

Options:
  --force   Discard and recreate all vector submodules and their local metadata.
  --verify  Check revisions, cleanliness, and required files without fetching.
  -h, --help
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      force_reset=true
      ;;
    --verify)
      verify_only=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
  shift
done

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

expected_revision() {
  local submodule_path=$1
  local revision
  revision=$(git ls-tree HEAD -- "$submodule_path" | awk '$1 == "160000" && $2 == "commit" { print $3 }')
  [[ -n "$revision" ]] || die "submodule is not recorded in HEAD: $submodule_path"
  printf '%s\n' "$revision"
}

module_git_dir() {
  local submodule_path=$1
  local module_dir
  module_dir=$(git rev-parse --git-path "modules/${submodule_path}")
  if [[ "$module_dir" == /* ]]; then
    printf '%s\n' "$module_dir"
  else
    printf '%s/%s\n' "$repo_root" "$module_dir"
  fi
}

remove_submodule_checkout() {
  local submodule_path=$1
  local module_dir
  module_dir=$(module_git_dir "$submodule_path")
  local git_dir
  git_dir=$(git rev-parse --absolute-git-dir)

  case "$module_dir" in
    "$git_dir"/modules/*)
      ;;
    *)
      die "refusing to remove unexpected module directory: $module_dir"
      ;;
  esac

  git submodule deinit -f -- "$submodule_path" >/dev/null 2>&1 || true
  rm -rf -- "$submodule_path" "$module_dir"
  git submodule init -- "$submodule_path" >/dev/null
}

has_checkout() {
  local submodule_path=$1
  local checkout_root
  checkout_root=$(git -C "$submodule_path" rev-parse --show-toplevel 2>/dev/null) || return 1
  [[ "$checkout_root" == "$repo_root/$submodule_path" ]]
}

checkout_is_dirty() {
  local submodule_path=$1
  [[ -n $(git -C "$submodule_path" status --porcelain --untracked-files=all) ]]
}

clone_submodule() {
  local submodule_path=$1
  local url=$2
  local module_dir
  module_dir=$(module_git_dir "$submodule_path")

  if [[ -e "$module_dir" ]]; then
    die "stale module data exists for $submodule_path; rerun with --force"
  fi
  if [[ -e "$submodule_path" ]]; then
    rmdir "$submodule_path" 2>/dev/null || \
      die "non-empty path is not a submodule checkout: $submodule_path"
  fi

  echo "Cloning metadata for $submodule_path"
  git clone --filter=blob:none --depth 1 --no-checkout "$url" "$submodule_path"
  git submodule absorbgitdirs -- "$submodule_path"
}

setup_submodule() {
  local submodule_path=$1
  shift
  local sparse_patterns=("$@")
  local revision
  revision=$(expected_revision "$submodule_path")
  local url
  url=$(git config -f .gitmodules --get "submodule.${submodule_path}.url")

  if [[ "$force_reset" == true ]]; then
    echo "Recreating checkout $submodule_path"
    remove_submodule_checkout "$submodule_path"
    clone_submodule "$submodule_path" "$url"
  elif has_checkout "$submodule_path"; then
    if checkout_is_dirty "$submodule_path"; then
      die "$submodule_path has local changes; inspect them or rerun with --force"
    fi
  else
    clone_submodule "$submodule_path" "$url"
  fi

  # Establish a sparse worktree before selecting the pinned commit, so a
  # blobless clone downloads only the files FastRoll actually consumes.
  git -C "$submodule_path" sparse-checkout init --no-cone
  if ! git -C "$submodule_path" cat-file -e "${revision}^{commit}" 2>/dev/null; then
    echo "Fetching pinned revision ${revision:0:12} for $submodule_path"
    git -C "$submodule_path" fetch --filter=blob:none --depth 1 origin "$revision"
  fi
  git -C "$submodule_path" checkout --detach --force "$revision"
  git -C "$submodule_path" sparse-checkout set --no-cone "${sparse_patterns[@]}"
}

require_any_file() {
  local directory=$1
  local filename_pattern=$2
  [[ -d "$directory" ]] || die "required directory is missing: $directory"
  local match
  match=$(find "$directory" -type f -name "$filename_pattern" -print -quit)
  [[ -n "$match" ]] || die "no $filename_pattern files found under $directory"
}

verify_submodule() {
  local submodule_path=$1
  has_checkout "$submodule_path" || die "submodule is not initialized: $submodule_path"
  local expected
  expected=$(expected_revision "$submodule_path")
  local actual
  actual=$(git -C "$submodule_path" rev-parse HEAD)
  [[ "$actual" == "$expected" ]] || \
    die "$submodule_path is at ${actual:0:12}, expected ${expected:0:12}"
  ! checkout_is_dirty "$submodule_path" || die "$submodule_path has local changes"
}

verify_vectors() {
  local submodule_path
  for submodule_path in "${VECTOR_SUBMODULES[@]}"; do
    verify_submodule "$submodule_path"
  done

  require_any_file "integration/jamtestvectors-polkajam/codec/tiny" "*.json"
  require_any_file "integration/jamtestvectors-polkajam/codec/tiny" "*.bin"
  require_any_file "integration/jamtestvectors-polkajam/codec/full" "*.json"
  require_any_file "integration/jamtestvectors-polkajam/erasure/tiny" "*.json"
  require_any_file "integration/jamtestvectors-polkajam/erasure/full" "*.json"
  require_any_file "integration/jamtestvectors-polkajam/shuffle" "*.json"
  require_any_file "integration/jamtestvectors-polkajam/stf" "*.json"
  require_any_file "integration/jamtestvectors-polkajam/traces" "*.bin"
  require_any_file "integration/jamtestvectors-pvm/pvm/programs" "*.json"
  [[ -f integration/jam-conformance/crypto/ed25519/vectors.json ]] || \
    die "Ed25519 consensus vectors are missing"
  require_any_file "integration/jam-conformance/fuzz-reports/0.7.2/traces" "*.bin"

  echo "Test-vector revisions and sparse files verified."
  du -sh "${VECTOR_SUBMODULES[@]}"
}

if [[ "$verify_only" == true ]]; then
  verify_vectors
  exit 0
fi

git submodule sync -- "${VECTOR_SUBMODULES[@]}" >/dev/null
git submodule init -- "${VECTOR_SUBMODULES[@]}" >/dev/null

setup_submodule \
  "integration/jamtestvectors-polkajam" \
  "/codec/tiny/*" \
  "/codec/full/*" \
  "/erasure/tiny/*.json" \
  "/erasure/full/*.json" \
  "/shuffle/shuffle_tests.json" \
  "/stf/*/tiny/*.json" \
  "/stf/*/full/*.json" \
  "/traces/**/*.bin"

setup_submodule \
  "integration/jamtestvectors-pvm" \
  "/pvm/programs/*.json"

setup_submodule \
  "integration/jam-conformance" \
  "/crypto/ed25519/vectors.json" \
  "/fuzz-reports/0.7.2/traces/**/*.bin"

verify_vectors
