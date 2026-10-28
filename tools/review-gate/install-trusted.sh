#!/bin/bash
# Install the trusted review-gate: a root-owned checker, signer, and pinned
# public key. Run as yourself in a terminal; sudo asks for your password.
#
#   ./install-trusted.sh               install or update the checker
#   ./install-trusted.sh --rotate-key  also replace the pinned public key
#   ./install-trusted.sh --path DIRS   pin the PATH that test commands use
#
# Test commands never inherit the caller's PATH. The first install pins
# the system directories; later installs keep the pinned PATH unless --path
# is given. A check is trusted only when every pinned directory is root-owned.
set -euo pipefail

src="$(cd "$(dirname "$0")" && pwd)"
prefix=/usr/local
sudo=sudo
install=/usr/bin/install
approver_build=
default_path=/usr/bin:/bin:/usr/sbin:/sbin
# Tests stage an install under a temporary REVIEW_GATE_PREFIX. The other
# overrides apply only then, so they can never change the real install.
if [[ -n ${REVIEW_GATE_PREFIX:-} && $REVIEW_GATE_PREFIX != /usr/local ]]; then
  prefix="$REVIEW_GATE_PREFIX"
  sudo="${REVIEW_GATE_SUDO:-sudo}"
  install="${REVIEW_GATE_INSTALL:-/usr/bin/install}"
  approver_build="${REVIEW_GATE_APPROVER_BUILD:-}"
  echo "Staged install under $prefix" >&2
fi
libexec="$prefix/libexec/review-gate"
etc="$prefix/etc/review-gate"
key_dir="$HOME/.config/review-gate"
legacy_key="$key_dir/approver.handle"
pub="$key_dir/approver.pub"

if [[ $EUID -eq 0 ]]; then
  echo "Run as your user, not root; the Touch ID key belongs to your account." >&2
  exit 2
fi
rotate=0
new_path=
while [[ $# -gt 0 ]]; do
  case $1 in
    --rotate-key) rotate=1 ;;
    --path) new_path="${2:?--path needs a value}"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
if [[ -n $new_path ]]; then
  IFS=: read -ra dirs <<<"$new_path"
  for dir in "${dirs[@]}"; do
    if [[ $dir != /* ]]; then
      echo "--path entries must be absolute directories: '$dir'" >&2
      exit 2
    fi
  done
fi

build="$(mktemp -d "${TMPDIR:-/tmp}/review-gate-install.XXXXXX")"
trap 'rm -rf "$build"' EXIT
if [[ -n $approver_build ]]; then
  cp "$approver_build" "$build/approver"
else
  /usr/bin/swiftc -O "$src/approver.swift" -o "$build/approver"
fi

mkdir -p "$key_dir"
chmod 700 "$key_dir"

# Each key has its own file, named by its public key's fingerprint, and the
# checker signs with the file that matches the pinned key. A new key never
# replaces the pinned key's file, so whichever key is pinned, its file is
# there.
# Fails unless the hash is 16 hex digits, so a failed shasum can never make
# a name the checker would not compute. Callers assign the result first:
# a failure inside a command used as an argument would not stop the script.
key_for() {
  local sum
  sum="$(shasum -a 256 "$1")" || return 1
  sum="${sum:0:16}"
  [[ $sum =~ ^[0-9a-f]{16}$ ]] || return 1
  echo "$key_dir/approver-$sum.handle"
}
# True when $1 is a key file whose public key is exactly $2. `approver
# public` needs no Touch ID, so this proves the pair instead of trusting a
# file name: anything running as the user can write this directory. A link
# is followed: only the key it leads to counts, and place_key copies that key
# into a new regular file.
key_matches() {
  [[ -f $1 ]] &&
    "$build/approver" public --key "$1" 2>/dev/null | cmp -s - "$2"
}
# Write key file $1 to $2 for public key $3, replacing whatever is at $2
# (a planted file or link) but never writing through it.
place_key() {
  local tmp
  if [[ -d $2 ]]; then
    echo "$2 is a directory; remove it first." >&2
    exit 2
  fi
  tmp="$(mktemp "$key_dir/.approver.XXXXXX")"
  cat "$1" >"$tmp"
  mv -f "$tmp" "$2"
  if ! key_matches "$2" "$3"; then
    echo "Could not write $2." >&2
    exit 1
  fi
}

# Enroll only when the pin is known to be absent. A pin we cannot see, or a
# sudo that fails, stops the install instead of making a new key.
pinned=0
if [[ -f "$etc/approver.pub" ]]; then
  pinned=1
elif ! $sudo test ! -e "$etc/approver.pub"; then
  echo "Cannot confirm whether $etc/approver.pub exists; fix sudo or its permissions." >&2
  exit 2
fi
if [[ $pinned -eq 1 ]]; then
  active="$(key_for "$etc/approver.pub")"
  if ! key_matches "$active" "$etc/approver.pub" &&
    key_matches "$legacy_key" "$etc/approver.pub"; then
    # Older installs kept the key at approver.handle. Give it its new name
    # before the new checker is installed, also when rotating, so the
    # checker finds it if the rotation stops.
    place_key "$legacy_key" "$active" "$etc/approver.pub"
    echo "Moved the signing key to $active."
  fi
  if ! key_matches "$active" "$etc/approver.pub"; then
    if [[ -e $legacy_key || -L $legacy_key ]]; then
      # An older checker may still sign with this file, and a check can fail
      # for reasons other than a wrong key. Change nothing, also when
      # rotating: the new checker would not use this file.
      # Say "does not match" only for a public key that was read and
      # differs from the pin. A failed or unstable read is "could not check".
      # The output goes to a file, so the bytes are compared exactly.
      legacy_read=0
      if [[ -f $legacy_key ]] &&
        "$build/approver" public --key "$legacy_key" >"$build/legacy.pub" 2>/dev/null &&
        [[ -s $build/legacy.pub ]]; then
        legacy_read=1
      fi
      if [[ $legacy_read -eq 1 ]] && ! cmp -s "$build/legacy.pub" "$etc/approver.pub"; then
        echo "$legacy_key does not match the pinned key; move it away, then run $0 --rotate-key." >&2
      else
        echo "Could not check $legacy_key against the pinned key; nothing was changed. Run $0 again; if it still fails and you no longer need that key, move it away, then run $0 --rotate-key." >&2
      fi
      exit 2
    fi
    if [[ $rotate -eq 0 ]]; then
      echo "No key file matches the pinned key ($active); run $0 --rotate-key." >&2
      exit 2
    fi
  fi
fi
$sudo "$install" -d -o root -g wheel -m 755 "$etc" "$libexec" "$prefix/bin"
if [[ -n $new_path ]] || ! $sudo test -f "$etc/path"; then
  printf '%s\n' "${new_path:-$default_path}" >"$build/path"
  $sudo "$install" -o root -g wheel -m 644 "$build/path" "$etc/path"
fi
$sudo "$install" -o root -g wheel -m 755 "$build/approver" "$libexec/approver"
$sudo "$install" -o root -g wheel -m 644 "$src/review_gate.py" "$libexec/review_gate.py"
# /usr/bin/python3 is an xcrun shim; these variables would let the caller
# choose which interpreter it runs.
printf '#!/bin/sh\nexec /usr/bin/env -u DEVELOPER_DIR -u TOOLCHAINS -u SDKROOT /usr/bin/python3 -I %s/review_gate.py "$@"\n' \
  "$libexec" >"$build/review-gate"
$sudo "$install" -o root -g wheel -m 755 "$build/review-gate" "$prefix/bin/review-gate"

# Rotate last. The checker and signer installed above already pick the key
# file by the pinned key's fingerprint, so if the pin changes, the checker
# that reads it is never one that uses another file.
if [[ $pinned -eq 0 || $rotate -eq 1 ]]; then
  # Enroll: never trust key files already in the user's directory. Anything
  # running as the user could have planted a software key there. Make a new
  # Secure Enclave key here and pin the public key this run produced.
  "$build/approver" init --key "$build/approver.handle" --pub "$build/approver.pub"
  # The new key's file exists before the pin changes.
  new_key="$(key_for "$build/approver.pub")"
  place_key "$build/approver.handle" "$new_key" "$build/approver.pub"
  # Switch the pin by renaming a checked copy, so the pin is always the old
  # key or the new one, never a partial file. A failure at any step leaves
  # the old pin, and the old key's file is untouched.
  $sudo "$install" -d -o root -g wheel -m 755 "$etc"
  $sudo "$install" -o root -g wheel -m 644 "$build/approver.pub" "$etc/approver.pub.new" ||
    echo "Copying the new pin reported an error; checking the copy." >&2
  if ! cmp -s "$build/approver.pub" "$etc/approver.pub.new"; then
    echo "The new key was not pinned; the old key still signs." >&2
    exit 1
  fi
  $sudo mv -f "$etc/approver.pub.new" "$etc/approver.pub"
  # The user's copy of the public key is for reference only.
  tmp="$(mktemp "$key_dir/.approver.XXXXXX")"
  cat "$build/approver.pub" >"$tmp"
  chmod 644 "$tmp"
  mv -f "$tmp" "$pub"
  echo "Created and pinned a new Secure Enclave key; signing needs Touch ID or your password."
fi

echo "Installed from $(git -C "$src" rev-parse --short HEAD 2>/dev/null || echo 'an untracked tree')."
echo "Checker sha256: $(shasum -a 256 "$libexec/review_gate.py" | cut -d' ' -f1)"
echo "Approver sha256: $(shasum -a 256 "$libexec/approver" | cut -d' ' -f1)"
echo "Pinned key: $(shasum -a 256 "$etc/approver.pub" | cut -d' ' -f1)"
echo "Test command PATH: $($sudo cat "$etc/path")"
