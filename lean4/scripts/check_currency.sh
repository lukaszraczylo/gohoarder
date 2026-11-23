#!/bin/sh
# Fails when a Go file cited by the Lean model changed in the range with no change under lean4/.
# Usage: lean4/scripts/check_currency.sh [base-ref]   (default origin/main)
set -eu

base="${1:-origin/main}"
root="$(git rev-parse --show-toplevel)"
cd "$root"

changed="$(git diff --name-only "$base"...HEAD)"
cited="$(grep -rhoE '(pkg|cmd)/[A-Za-z0-9_./-]+\.go|Dockerfile\.frontend' lean4/Gohoarder | sort -u)"

if printf '%s\n' "$changed" | grep -q '^lean4/'; then
	lean_changed=yes
else
	lean_changed=no
fi

status=0
for file in $cited; do
	if [ ! -f "$file" ]; then
		echo "MISSING: $file is cited by the Lean model but does not exist"
		status=1
		continue
	fi
	if printf '%s\n' "$changed" | grep -qx "$file" && [ "$lean_changed" = no ]; then
		echo "REVIEW: $file is cited by the Lean model and changed with no lean4/ change"
		status=1
	fi
done

[ "$status" -eq 0 ] && echo "currency: every cited file exists and none changed without a model change"
exit "$status"
